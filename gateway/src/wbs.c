/**
 * @file wbs_gw.c
 * @brief Thread-safe production-grade gateway wrapper matching original wsServer APIs
 * @note Integrated with automated background heartbeats (ping/pong tracking) and slot recycling.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>

#include "ws.h" 
#include "wbs.h"
#include "log.h"
#include "cJSON.h"
#include "cmdengine.h"
#include "sys.h"
#include "redgw.h"

#define TAG                 "[WBS]"
#define MAX_CLI             MAX_CLIENTS
#define PING_INTERVAL_SEC   10  /* Ping every 10 seconds */
#define PING_THRESHOLD      2   /* Kick client if missed 2 consecutive PONGs */

typedef struct {
    ws_cli_conn_t conn;
    int active;
} wbs_slot_t;

typedef struct {
    const char *host;
    uint16_t port;
    pthread_mutex_t lock;      /* Mutual exclusion lock for slots and concurrent API calls */
    pthread_cond_t cond;
    wbs_slot_t clis[MAX_CLI];  /* Tracks up to 16 concurrent screens */
    pthread_t ping_tid;        /* Internal thread handle for keep-alive routine */
    int is_run;
} wbs_ctx_t;

static wbs_ctx_t g_ctx = {0};

/**
 * @brief  Internal static helper to safely parse dashboard JSON control packet and dump metrics.
 * @param  json_str [in] Null-terminated or length-bounded JSON string sequence.
 * @param  len      [in] Total buffer length of the inbound string.
 * @return void
 * @note   Memory Safe: Completely diagnostic-only; frees allocated cJSON memory context upon exit.
 */
static void ws_parse_config(const char *json_str, uint64_t len) {
    if (!json_str || len == 0) return;

    /* 1. Fast intercept for high-frequency heartbeat ping frames to skip overhead */
    if (len >= 4 && strncmp(json_str, "ping", 4) == 0) {
        return;
    }

    /* 2. Parse JSON payload into local arena */
    cJSON *root = cJSON_ParseWithLength(json_str, len);
    if (!root) {
        log_warn("%s Corrupted or non-compliant JSON payload frame discarded.", TAG);
        return;
    }

    /* 3. Extract the multiplexing discriminator identifier "type" */
    cJSON *type_node = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (cJSON_IsString(type_node) && type_node->valuestring && strcmp(type_node->valuestring, "config") == 0) {
        
        cJSON *payload = cJSON_GetObjectItemCaseSensitive(root, "payload");
        if (payload && cJSON_IsObject(payload)) {
            
            /* 4. Extract telemetry boolean switches into local stack variables */
            cJSON *isdebug_node    = cJSON_GetObjectItemCaseSensitive(payload, "isdebug");
            cJSON *islogpkt_node  = cJSON_GetObjectItemCaseSensitive(payload, "islogpkt");
            cJSON *forward_node = cJSON_GetObjectItemCaseSensitive(payload, "forward_debug");
            cJSON *gen_log_node = cJSON_GetObjectItemCaseSensitive(payload, "general_log");

            int local_debug   = cJSON_IsBool(isdebug_node)    ? cJSON_IsTrue(isdebug_node) : 0;
            int local_logpkt  = cJSON_IsBool(islogpkt_node)  ? cJSON_IsTrue(islogpkt_node) : 0;
            int local_forward = cJSON_IsBool(forward_node) ? cJSON_IsTrue(forward_node) : 0;
            int local_gen_log = cJSON_IsBool(gen_log_node) ? cJSON_IsTrue(gen_log_node) : 0;

            /* 5. Direct Industrial high-visibility telemetry dump on console */
            log_info("[KERNEL CONFIG] Received Frontend Control Flow Optimizations");
            log_info("[Debug Tracking]  -> %s", local_debug   ? "ENABLED" : "DISABLED");
            log_info("[XDP Reassembly]  -> %s", local_logpkt  ? "ENABLED" : "DISABLED");
            log_info("[Producer-Buffer Flow] -> %s", local_forward ? "ENABLED" : "DISABLED");
            log_info("[General System Logs]  -> %s", local_gen_log ? "ENABLED" : "DISABLED");

            cmd_setdebug_enabled(local_debug ? true : false);
            cmd_setlogpkt_enabled(local_logpkt ? true : false);
        }
    }

    /* 6. Enforce strict heap reclamation to avoid critical memory leakage */
    cJSON_Delete(root);
}

/**
 * @brief WebSocket telemetry logging bridge matching the rxi/log callback signature.
 * @note Stripped timestamp constraints. Includes synchronized stack-allocated JSON escaping 
 * to prevent payload corruption or parsing failures on the Web UI.
 * @param ev Pointer to the active log event context containing metadata and variadic arguments.
 */
void ws_log_callback(log_Event *ev) {
    /* Guardrail against invalid or uninitialized log event telemetry */
    if (!ev || !ev->fmt) return;

    /* Stack allocate buffers to eliminate heap fragmentation risks in high-throughput paths */
    char raw_msg[1024]   = {0};
    char final_msg[1280] = {0};
    char escaped_msg[2048] = {0};
    char json_buf[2560]  = {0};

    /* Extract and format the raw variadic message payload under a safe variadic copy snapshot */
    va_list args_copy;
    va_copy(args_copy, ev->ap);
    int msg_len = vsnprintf(raw_msg, sizeof(raw_msg) - 1, ev->fmt, args_copy);
    va_end(args_copy);

    if (msg_len < 0) return;

    /* Map discrete log level integers to structured global string descriptors */
    const char *level_strings[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
    const char *lvl_str = (ev->level >= 0 && ev->level <= 5) ? level_strings[ev->level] : "UNKNOWN";

    /* Consolidate metadata components: [LEVEL] file:line: raw_message */
    int final_len = snprintf(final_msg, sizeof(final_msg) - 1, "[%-5s] %s:%d: %s", 
                             lvl_str, ev->file, ev->line, raw_msg);
    if (final_len < 0) return;

    /* Industrial-grade JSON Escape Shield: 
     * Iteratively sanitize control characters (\n, \r, \t), backslashes, and quotes 
     * to safeguard the frontend JSON parser against unexpected frame truncation.
     */
    char *dst = escaped_msg;
    const char *src = final_msg;
    const char *max_dst = escaped_msg + sizeof(escaped_msg) - 3; /* Guard room for safe trailing characters */

    while (*src && dst < max_dst) {
        switch (*src) {
            case '"':  *dst++ = '\\'; *dst++ = '"';  break;
            case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
            case '\n': *dst++ = '\\'; *dst++ = 'n';  break;
            case '\r': *dst++ = '\\'; *dst++ = 'r';  break;
            case '\t': *dst++ = '\\'; *dst++ = 't';  break;
            default:   *dst++ = *src;                break;
        }
        src++;
    }
    *dst = '\0';

    /* Encap the sanitized stream inside a flat single-field JSON tracking object */
    int json_len = snprintf(json_buf, sizeof(json_buf) - 1,
        "{"
          "\"type\":\"log\","
          "\"payload\":{"
            "\"msg\":\"%s\""
          "}"
        "}",
        escaped_msg
    );

    /* Dispatch telemetry packet via asynchronous raw network layer broadcast */
    if (json_len > 0 && json_len < (int)sizeof(json_buf)) {
        wbs_bcast(json_buf, (uint64_t)json_len);
    }
}

static void _on_open_bridge(ws_cli_conn_t client) {
    char *ip = ws_getaddress(client);
    char *port = ws_getport(client);
    int idx = -1;

    pthread_mutex_lock(&g_ctx.lock);
    for (int i = 0; i < MAX_CLI; i++) {
        if (!g_ctx.clis[i].active) {
            g_ctx.clis[i].conn = client;
            g_ctx.clis[i].active = 1;
            idx = i;
            break;
        }
    }
    pthread_mutex_unlock(&g_ctx.lock);

    if (idx != -1) {
        log_info("%s Link approved -> Slot: %d, Remote: %s:%s", 
                 TAG, idx, ip ? ip : "0.0.0.0", port ? port : "0");
    } else {
        log_warn("%s Connection rejected: MAX_CLI (%d) overflow.", TAG, MAX_CLI);
        ws_close_client(client);
    }
}

static void _on_close_bridge(ws_cli_conn_t client) {
    char *ip = ws_getaddress(client);
    int idx = -1;

    pthread_mutex_lock(&g_ctx.lock);
    for (int i = 0; i < MAX_CLI; i++) {
        if (g_ctx.clis[i].active && g_ctx.clis[i].conn == client) {
            g_ctx.clis[i].active = 0;
            g_ctx.clis[i].conn = 0;
            idx = i;
            break;
        }
    }
    pthread_mutex_unlock(&g_ctx.lock);

    if (idx != -1) {
        log_info("%s Link severed or timed out at Slot %d (IP: %s)", TAG, idx, ip ? ip : "0.0.0.0");
    }
}

static void _on_msg_bridge(ws_cli_conn_t client, const unsigned char *msg, uint64_t size, int type) {
    (void)client;
    if (type == 1) {
        log_info("%s UTF-8 Stream (Size: %lu): %s", TAG, size, (const char *)msg);
        ws_parse_config((const char *)msg, size);
    } else if (type == 2) {
        log_info("%s Inbound Raw Binary Stream (Size: %lu bytes)", TAG, size);
    }
}

static void* _wbs_ping_worker(void *arg) {
    (void)arg;
    log_info("%s Internal keep-alive heartbeat thread spawned.", TAG);

    pthread_mutex_lock(&g_ctx.lock);
    while (g_ctx.is_run) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += PING_INTERVAL_SEC; /* Set precision timeout to 10 seconds */

        /* 
         * Releases the lock while sleeping, and automatically re-acquires it upon waking up.
         * If pthread_cond_signal is fired in wbs_stop(), this will awaken INSTANTLY.
         */
        int ret = pthread_cond_timedwait(&g_ctx.cond, &g_ctx.lock, &ts);

        /* If g_ctx.is_run was toggled off during our sleep, break immediately with lock held */
        if (!g_ctx.is_run) {
            break;
        }

        /* If it was a natural timeout (ret != 0), fire the ping probe safely under lock protection */
        if (ret != 0) {
            ws_ping(0, PING_THRESHOLD);
        }
    }
    pthread_mutex_unlock(&g_ctx.lock);
    
    log_info("%s Heartbeat worker exited cleanly without latency.", TAG);
    return NULL;
}

int wbs_start(const char *host, uint16_t port) {
    if (port == 0) return -1;
    
    memset(&g_ctx, 0, sizeof(wbs_ctx_t));
    g_ctx.port = port;
    g_ctx.host = host;
    
    if (pthread_mutex_init(&g_ctx.lock, NULL) != 0) return -1;
    if (pthread_cond_init(&g_ctx.cond, NULL) != 0) {
        pthread_mutex_destroy(&g_ctx.lock);
        return -1;
    }

    struct ws_server srv = {0};
    srv.host = host ? host : CONFIG_DEFAULT_HOST;
    srv.port = port;
    srv.thread_loop = 1;  /* Run raw epoll network loop in background native thread */
    srv.timeout_ms = 1000;
    srv.evs.onopen = _on_open_bridge;
    srv.evs.onclose = _on_close_bridge;
    srv.evs.onmessage = _on_msg_bridge;

    if (ws_socket(&srv) != 0) {
        log_error("%s Fatal: Socket binding collapsed on %s:%u", TAG, srv.host, port);
        pthread_cond_destroy(&g_ctx.cond);
        pthread_mutex_destroy(&g_ctx.lock);
        return -1;
    }
    log_add_callback(ws_log_callback, NULL, LOG_TRACE);
    g_ctx.is_run = 1;

    if (pthread_create(&g_ctx.ping_tid, NULL, _wbs_ping_worker, NULL) != 0) {
        log_error("%s Fatal: Failed to spawn heartbeat thread", TAG);
        g_ctx.is_run = 0;
        pthread_cond_destroy(&g_ctx.cond);
        pthread_mutex_destroy(&g_ctx.lock);
        return -1;
    }

    log_info("%s Deployment successful. System fully autonomous on port %u", TAG, port);
    return 0;
}

/**
 * @brief Thread-safe API to broadcast payloads to all connected clients.
 * @param pkt Pointer to the raw buffer (can accept text string or binary data).
 * @param len Explicit length of the data to transmit, bypasses truncation risks.
 */
void wbs_bcast(const void *pkt, uint64_t len) {
    /* Guardrail against invalid parameters or inactive server state */
    if (!pkt || len == 0 || !g_ctx.is_run) return;

    pthread_mutex_lock(&g_ctx.lock);
    
    /*  
     * Explicit length tracking completely replaces the vulnerable 'strlen()', 
     * guaranteeing that the payload is sprayed out raw without any risk of 
     * mid-stream truncation caused by embedded null bytes (\0).
     *
     * Note: Hardcoded to WS_FR_OP_TXT (1) here assuming text-based streaming (e.g., JSON). 
     * If mixed binary/text transmission is required later, pass the type flag 
     * directly through the function arguments.
     */
    ws_sendframe_bcast(g_ctx.port, (const char *)pkt, len, WS_FR_OP_TXT);
    
    pthread_mutex_unlock(&g_ctx.lock);
}

void wbs_stop(void) {
    if (!g_ctx.is_run) return;

    pthread_mutex_lock(&g_ctx.lock);
    g_ctx.is_run = 0;
    pthread_cond_signal(&g_ctx.cond); 
    pthread_mutex_unlock(&g_ctx.lock);

    pthread_join(g_ctx.ping_tid, NULL);

    /* STEP 3: Clean drop all remaining slots */
    pthread_mutex_lock(&g_ctx.lock);
    for (int i = 0; i < MAX_CLI; i++) {
        if (g_ctx.clis[i].active) {
            ws_close_client(g_ctx.clis[i].conn);
            g_ctx.clis[i].active = 0;
            g_ctx.clis[i].conn = 0;
        }
    }
    pthread_mutex_unlock(&g_ctx.lock);
    pthread_cond_destroy(&g_ctx.cond);
    pthread_mutex_destroy(&g_ctx.lock);

    log_info("%s Gateway offline. All slots recycled, heartbeat terminated.", TAG);
}

/**
 * @brief  Collects real-time gateway hardware telemetry data, formats floats to pure text, and broadcasts.
 * @param  eth1_ctx [in/out] Persistent telemetry context for the primary interface.
 * @param  eth2_ctx [in/out] Persistent telemetry context for the secondary interface.
 * @return void
 * @note   Thread-Safe & Memory-Safe. Bypasses binary float serialization anomalies by converting via %0.2f strings.
 */
static void ws_report_system_status(sys_net_ctx *eth1_ctx, sys_net_ctx *eth2_ctx) {
    if (!eth1_ctx || !eth2_ctx) return;

    /* 1. Extract raw data plane statistics */
    float cpu = sys_cpu_usage();
    float mem = sys_proc_mem_mb();
    float eth1_rx = 0.0f, eth1_tx = 0.0f;
    float eth2_rx = 0.0f, eth2_tx = 0.0f;

    sys_net_rate(redserver.dev1, eth1_ctx, &eth1_rx, &eth1_tx);
    sys_net_rate(redserver.dev2, eth2_ctx, &eth2_rx, &eth2_tx);

    /* Sanitize against non-finite float anomalies */
    cpu     = (cpu < 0.0f || !isfinite(cpu)) ? 0.0f : cpu;
    mem     = (mem < 0.0f || !isfinite(mem)) ? 0.0f : mem;
    eth1_rx = (eth1_rx < 0.0f || !isfinite(eth1_rx)) ? 0.0f : eth1_rx;
    eth2_rx = (eth2_rx < 0.0f || !isfinite(eth2_rx)) ? 0.0f : eth2_rx;

    char fmt_cpu[32], fmt_mem[32], fmt_eth1[32], fmt_eth2[32];
    snprintf(fmt_cpu,  sizeof(fmt_cpu),  "%.2f", cpu);
    snprintf(fmt_mem,  sizeof(fmt_mem),  "%.2f", mem);
    snprintf(fmt_eth1, sizeof(fmt_eth1), "%.2f", eth1_rx);
    snprintf(fmt_eth2, sizeof(fmt_eth2), "%.2f", eth2_rx);

    /* 3. Construct Structured cJSON Object Architecture */
    cJSON *root = cJSON_CreateObject();
    if (!root) goto mem_error_abort;

    if (!cJSON_AddStringToObject(root, "type", "status")) goto cleanup_fail;

    cJSON *payload = cJSON_CreateObject();
    if (!payload) goto cleanup_fail;
    cJSON_AddItemToObject(root, "payload", payload);

    /* Bind static fields */
    if (!cJSON_AddStringToObject(payload, "version", "2.4.12-rc3")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "gateway_ip", "192.168.211.129")) goto cleanup_fail;
    if (!cJSON_AddNumberToObject(payload, "gateway_port", 9001)) goto cleanup_fail;
    
    if (!cJSON_AddStringToObject(payload, "cpu_usage",  fmt_cpu))  goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "mem_usage",  fmt_mem))  goto cleanup_fail;
    
    if (!cJSON_AddStringToObject(payload, "black_zone_status", "UP")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "black_ip", redserver.core_ip ? redserver.core_ip : "0.0.0.0")) goto cleanup_fail;
    if (!cJSON_AddNumberToObject(payload, "black_port", redserver.core_port)) goto cleanup_fail;
    
    if (!cJSON_AddStringToObject(payload, "eth1_name", redserver.dev1 ? redserver.dev1 : "eth1")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "eth1_speed", fmt_eth1)) goto cleanup_fail;
    
    if (!cJSON_AddStringToObject(payload, "eth2_name", redserver.dev2 ? redserver.dev2 : "eth2")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "eth2_speed", fmt_eth2)) goto cleanup_fail;

    /* 4. Serialize into unformatted compact stream buffer */
    char *json_raw_str = cJSON_PrintUnformatted(root);
    if (!json_raw_str) goto cleanup_fail;

    /* 5. Transmit data plane packet via WebSocket */
    uint64_t total_len = (uint64_t)strlen(json_raw_str);
    if (total_len > 0) {
        wbs_bcast(json_raw_str, total_len);
    }

    free(json_raw_str);

cleanup_fail:
    cJSON_Delete(root);
    return;

mem_error_abort:
    log_error("%s Critical OOM condition. Telemetry broadcast dropped.", TAG);
}

/**
 * @brief  Constructs the live configuration JSON telemetry packet and broadcasts it to the dashboard.
 * @return void
 * @note   Memory Safe: Allocates cJSON object locally, serializes to string, transmits, 
 * and immediately reclaims all allocated heap memory to enforce a zero-leak policy.
 */
static void ws_report_live_config(void) {
    /* 1. Create the root JSON frame container */
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        log_error("%s Failed to allocate memory for config root object.", TAG);
        return;
    }

    /* 2. Inject the type discriminator */
    cJSON_AddStringToObject(root, "type", "config");

    /* 3. Create and populate the child "payload" object */
    cJSON *payload = cJSON_CreateObject();
    if (!payload) {
        log_error("%s Failed to allocate memory for config payload object.", TAG);
        cJSON_Delete(root);
        return;
    }
    cJSON_AddItemToObject(root, "payload", payload);

    bool is_logpkt = cmd_islogpkt_enabled();
    bool is_debug  = cmd_isdebug_enabled();

    cJSON_AddBoolToObject(payload, "isdebug", is_debug);      /* Map debug tracking state */
    cJSON_AddBoolToObject(payload, "islogpkt", is_logpkt);    /* Map packet reassembly state */
    cJSON_AddBoolToObject(payload, "forward_debug", false);   /* Placeholder/Default placeholder */
    cJSON_AddBoolToObject(payload, "general_log", false);     /* Sync standard system log toggle */

    /* 5. Serialize cJSON structure into unformatted, compact raw string sequence */
    char *json_raw_str = cJSON_PrintUnformatted(root);
    if (json_raw_str) {
        uint64_t total_len = (uint64_t)strlen(json_raw_str);
        
        wbs_bcast(json_raw_str, total_len);

        /* Free the temporary text buffer allocated by cJSON_PrintUnformatted */
        free(json_raw_str);
    } else {
        log_error("%s Failed to serialize active kernel config payload into string.", TAG);
    }

    /* 6. Enforce rigorous heap cleanup of the cJSON object tree */
    cJSON_Delete(root);
}

/**
 * @brief  Core monitoring background daemon worker thread.
 */
static void *ws_mon_worker(void *arg) {
    int interval_ms = (int)(intptr_t)arg;
    
    /* Persistent telemetry context rings allocated on thread stack */
    sys_net_ctx eth1_ctx = {0};
    sys_net_ctx eth2_ctx = {0};

    while (1) {
        ws_report_system_status(&eth1_ctx, &eth2_ctx);
        ws_report_live_config();
        usleep(interval_ms * 1000);
    }
    return NULL;
}

int ws_notify_thread(int interval_ms) {
    pthread_t tid;
    pthread_attr_t attr;

    if (pthread_attr_init(&attr) != 0) return -1;
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        pthread_attr_destroy(&attr);
        return -1;
    }

    if (pthread_create(&tid, &attr, ws_mon_worker, (void *)(intptr_t)interval_ms) != 0) {
        pthread_attr_destroy(&attr);
        return -1;
    }

    pthread_attr_destroy(&attr);
    return 0;
}