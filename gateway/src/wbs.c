/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "ws.h" 
#include "wbs.h"
#include "util.h"
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

static const char *const SYSTEM_WHITELIST_TOKENS[] = {
    /* --- Network Diagnostics & Configuration --- */
    "ping",         /* ICMP connectivity check */
    "ip",           /* Modern link, address, and routing management */
    "ifconfig",     /* Legacy interface telemetry */
    "route",        /* IP routing table manager */
    "sysctl",       /* Kernel parameter tuner (e.g., net.ipv4.ip_forward) */
    "netstat",      /* Network statistics and socket auditing */
    "ss",           /* High-performance socket statistics (modern netstat) */
    "traceroute",   /* Route path packet tracing */
    "mtr",          /* Combined ping + traceroute real-time diagnostic */
    "tcpdump",      /* Low-level network packet capturing and filtering */
    "nslookup",     /* DNS lookup agent */
    "dig",          /* Advanced DNS lookup tool */
    "arp",          /* ARP table manipulator */

    /* --- Process Management & System Performance --- */
    "ls",           /* Directory listing utility */
    "systemctl",    /* Systemd service and unit controller */
    "df",           /* Disk filesystem space telemetry */
    "free",         /* Memory sub-system metrics */
    "uname",        /* Print kernel and OS metadata */
    "tail",         /* Real-time stream log tracking */
    "ps",           /* Static snapshot of current active processes */
    "kill",         /* Process termination agent */
    "lsof",         /* List open files and network ports mapped to processes */
    "pidof",        /* Find the PID of a running program by name */
    "uptime"        /* System load average and historical operational uptime */
};

/**
 * @brief Parse the interior payload object and commit configurations safely to the data-plane.
 * @param payload Pointer to the valid cJSON object node containing config parameters.
 */
static void ws_process_config_payload(const cJSON *payload) {
    if (!payload || !cJSON_IsObject(payload)) return;

    cJSON *isdebug_node   = cJSON_GetObjectItemCaseSensitive(payload, "isdebug");
    cJSON *islogpkt_node  = cJSON_GetObjectItemCaseSensitive(payload, "islogpkt");
    cJSON *iscapture_node = cJSON_GetObjectItemCaseSensitive(payload, "iscapture");
    cJSON *ifname_node    = cJSON_GetObjectItemCaseSensitive(payload, "capture_interface");
    cJSON *filter_node    = cJSON_GetObjectItemCaseSensitive(payload, "packet_filter");

    int local_debug   = cJSON_IsBool(isdebug_node)   ? cJSON_IsTrue(isdebug_node) : 0;
    int local_logpkt  = cJSON_IsBool(islogpkt_node)  ? cJSON_IsTrue(islogpkt_node) : 0;
    int local_capture = cJSON_IsBool(iscapture_node) ? cJSON_IsTrue(iscapture_node) : 0;

    char safe_ifname[32] = {0};
    char safe_filter[256] = {0};

    if (cJSON_IsString(ifname_node) && ifname_node->valuestring != NULL) {
        strncpy(safe_ifname, ifname_node->valuestring, sizeof(safe_ifname) - 1);
    } else {
        strncpy(safe_ifname, "eth1", sizeof(safe_ifname) - 1); /* Safe fallback telemetry boundary */
    }

    if (cJSON_IsString(filter_node) && filter_node->valuestring != NULL) {
        strncpy(safe_filter, filter_node->valuestring, sizeof(safe_filter) - 1);
    } else {
        safe_filter[0] = '\0';
    }

    log_info("[KERNEL CONFIG] Received Frontend Control Flow Optimizations");
    log_info("[Debug Tracking]  -> %s", local_debug   ? "ENABLED" : "DISABLED");
    log_info("[XDP Reassembly]  -> %s", local_logpkt  ? "ENABLED" : "DISABLED");
    log_info("[PCAP Capture  ]  -> %s", local_capture ? "ENABLED" : "DISABLED");
    log_info("[Interface     ]  -> %s", safe_ifname);
    log_info("[BPF Filter    ]  -> \"%s\"", safe_filter);

    cmd_setdebug_enabled(local_debug ? true : false);
    cmd_setlogpkt_enabled(local_logpkt ? true : false);
    cmd_setpcap_enabled(local_capture ? true : false, safe_ifname, safe_filter);
}

/**
 * @brief Helper function to wrap command execution results into a compliant JSON frame and send to client.
 * @param ctx The opaque connection context pointer (e.g., rbuf connection instance).
 * @param cmd_out The raw stdout/stderr output from the executed command.
 * @param cmd_len The byte length of the command output.
 */
static void ws_send_cmd_response(const char *cmd_out, size_t cmd_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        log_error("%s Failed to allocate memory for response JSON object.", TAG);
        return;
    }

    cJSON_AddStringToObject(root, "type", "cmd");
    if (cmd_out && cmd_len > 0) {
        cJSON_AddStringToObject(root, "payload", cmd_out);
    } else {
        cJSON_AddStringToObject(root, "payload", "[SYS] Command executed with blank output stream.");
    }

    char *json_frame = cJSON_PrintUnformatted(root);
    if (json_frame) {
        size_t frame_len = strlen(json_frame);
        wbs_bcast(json_frame, frame_len);
        free(json_frame);
    } else {
        log_error("%s Failed to serialize command response JSON frame.", TAG);
    }

    cJSON_Delete(root);
}

/**
 * @brief Enterprise Security Sentinel: Command Validation Engine with Sudo Stripping
 * Uses zero-copy pointer iteration to completely eliminate buffer overflow risks.
 * @param raw_cmd The raw command string received from the websocket payload.
 * @return 1 if the command passes the compliance matrix, 0 if intercepted.
 */
static int ws_is_command_allowed(const char *raw_cmd) {
    if (!raw_cmd) return 0;

    /* Phase 1: Pre-whitespace sanitization (Skip leading spaces/tabs) */
    const char *p_start = raw_cmd;
    while (*p_start && isspace((unsigned char)*p_start)) {
        p_start++;
    }

    if (*p_start == '\0') return 0;

    /* Phase 2: Shell Injection Mitigation
     * Scan the entire string for structural characters used to chain malicious commands,
     * execute background jobs, or exploit environmental variables. */
    if (strpbrk(p_start, "|;&`$\n\r")) {
        log_warn("%s Critical Interception: Malicious shell syntax chaining sequence blocked!", TAG);
        return 0;
    }

    /* Phase 3: Token Tracking (Locate the right boundary of the first word) */
    const char *p_end = p_start;
    while (*p_end && !isspace((unsigned char)*p_end)) {
        p_end++;
    }
    
    size_t first_token_len = (size_t)(p_end - p_start);
    if (first_token_len == 0) return 0;

    /* Phase 4: Adaptive Privilege State Machine
     * Check if the command prefixes with "sudo". Exact string match enforces strict boundary rules,
     * preventing bypass tricks like "sudoee". */
    if (first_token_len == 4 && strncmp(p_start, "sudo", 4) == 0) {
        
        /* Shift pointers past "sudo" and clear intermediate spaces to find the real executable */
        p_start = p_end;
        while (*p_start && isspace((unsigned char)*p_start)) {
            p_start++;
        }
        
        /* Edge case safety check: string containing only "sudo " is rejected */
        if (*p_start == '\0') {
            return 0;
        }
        
        /* Relocate the right boundary for the actual target binary executable token */
        p_end = p_start;
        while (*p_end && !isspace((unsigned char)*p_end)) {
            p_end++;
        }
    }

    /* Phase 5: Calculate targeted functional binary string length */
    size_t target_token_len = (size_t)(p_end - p_start);
    if (target_token_len == 0) return 0;

    /* Phase 6: Zero-Copy Compliant Matching Against Whitelist Matrix */
    size_t whitelist_size = ARRAY_SIZE(SYSTEM_WHITELIST_TOKENS);
    for (size_t i = 0; i < whitelist_size; i++) {
        const char *allowed_token = SYSTEM_WHITELIST_TOKENS[i];
        
        /* Both length and exact string payload must correspond completely */
        if (strlen(allowed_token) == target_token_len && 
            strncmp(p_start, allowed_token, target_token_len) == 0) {
            return 1; /* Verified: Secure system telemetry command authorized */
        }
    }

    log_warn("%s Access Denied: Executable target \"%.*s\" failed compliance whitelist matching.", 
             TAG, (int)target_token_len, p_start);
    return 0;
}

void wbs_on_cmd_stream_flash(void *ctx, const char *data, size_t len) {
    (void)ctx; /* Unused parameter in this context */
    if (!data || len == 0) return;

    if (len >= SYS_CHUNK_SIZE) {
        len = SYS_CHUNK_SIZE - 1;
    }

    char buf[SYS_CHUNK_SIZE];
    memcpy(buf, data, len);
    buf[len] = '\0';

    ws_send_cmd_response(buf, len);
}

/**
 * @brief Parse the flat command payload string, automatically discriminate execution profiles,
 * and dispatch to either synchronous aggregation or real-time pipeline streaming.
 * @param payload Pointer to the valid cJSON string node containing the command text.
 * @param ctx The opaque connection context tracking identifier (e.g., connection session / descriptor).
 */
static void ws_process_cmd_payload(const cJSON *payload, void *ctx) {
    if (!payload || !cJSON_IsString(payload)) return;

    const char *raw_cmd = payload->valuestring;
    if (strlen(raw_cmd) == 0) {
        const char *error_msg = "Error: Command payload string cannot be empty.";
        log_warn("%s %s", TAG, error_msg);
        ws_send_cmd_response(error_msg, strlen(error_msg));
        return;
    }

    if (!ws_is_command_allowed(raw_cmd)) {
        char deny_msg[512];
        int offset = snprintf(deny_msg, sizeof(deny_msg), 
            " Security Notice: Action rejected. Target executable not listed in hardware matrix.\n"
            " Available Commands: [ ");

        size_t whitelist_size = ARRAY_SIZE(SYSTEM_WHITELIST_TOKENS);
        for (size_t i = 0; i < whitelist_size; i++) {
            if (offset < (int)sizeof(deny_msg) - 32) {
                offset += snprintf(deny_msg + offset, sizeof(deny_msg) - offset, 
                                   "%s%s", SYSTEM_WHITELIST_TOKENS[i], (i == whitelist_size - 1) ? "" : ", ");
            }
        }
        
        snprintf(deny_msg + offset, sizeof(deny_msg) - offset, " ]");
        ws_send_cmd_response(deny_msg, strlen(deny_msg));
        return;
    }

    log_info("%s Inspecting routing policy for system directive: \"%s\"", TAG, raw_cmd);

    sys_run_cmd(raw_cmd, ctx, wbs_on_cmd_stream_flash);

    return;
}

/**
 * @brief Derives the legacy standard CIDR prefix length based on IPv4 classful routing rules.
 * @param ip Crucial raw IP string token to perform class deduction.
 * @return Integer representational value of the computed netmask bits (8, 16, or 24).
 */
static int get_classful_prefix_len(const char *ip) {
    if (!ip || *ip == '\0') {
        return 24; /* Fallback default standard for Class C / local networks */
    }
    
    int first_octet = atoi(ip);
    if (first_octet >= 1 && first_octet <= 126) {
        return 8;   /* Class A Network Allocation Block (e.g., 10.0.0.0/8) */
    } else if (first_octet >= 128 && first_octet <= 191) {
        return 16;  /* Class B Network Allocation Block (e.g., 172.16.0.0/16) */
    }
    return 24;      /* Class C Network Allocation Block (e.g., 192.168.0.0/24) */
}

/**
 * @brief Industrial-grade parsing entry point for executing stateless WebSocket network interfaces mutations.
 * @param payload Active pointer tracking the unmarshalled root cJSON node context payload.
 */
static void ws_process_wlan_payload(cJSON *payload) {
    if (unlikely(!payload)) {
        return;
    }

    cJSON *iface_node = cJSON_GetObjectItemCaseSensitive(payload, "target_interface");
    cJSON *ip_node    = cJSON_GetObjectItemCaseSensitive(payload, "target_ip");

    if (!cJSON_IsString(iface_node) || !iface_node->valuestring ||
        !cJSON_IsString(ip_node)    || !ip_node->valuestring) {
        log_error("[WS] SET_IP missing required target_interface or target_ip payload parameters.");
        return;
    }

    const char *interface_name = iface_node->valuestring;
    const char *target_ip      = ip_node->valuestring;

    /* 
     * [SECURITY MITIGATION]: High-severity shell command injection containment.
     * Intercepts metacharacters to completely isolate hazardous terminal executions. 
     */
    if (strpbrk(interface_name, ";&|`$\n\r") || strpbrk(target_ip, ";&|`$\n\r")) {
        log_error("[WS] Critical Security Violation: Shell injection token sequence intercepted. Operations dropped.");
        return;
    }

    /* Isolated tracking memory block matrices for clean parameter translation */
    char clean_ip[48] = {0};
    int final_prefix_len = 24; /* Initialize with default standard */
    
    /* Evaluate string topology to see if target input presents a standard CIDR slash format */
    const char *slash = strchr(target_ip, '/');
    
    if (slash) {
        /* Verify string memory bounds explicitly before execution to eliminate buffer overflow vectors */
        size_t ip_bytes = (size_t)(slash - target_ip);
        if (ip_bytes >= sizeof(clean_ip)) {
            log_error("[WS] Structural anomaly detected: IP length exceeds platform stack safety parameters.");
            return;
        }
        
        /* Isolate the raw structural IP prefix without the tailing slash network bit representation */
        memcpy(clean_ip, target_ip, ip_bytes);
        clean_ip[ip_bytes] = '\0';
        
        /* Capture and validate prefix notation bounds securely */
        int input_prefix = atoi(slash + 1);
        if (input_prefix >= 0 && input_prefix <= 32) {
            final_prefix_len = input_prefix;
        } else {
            /* Fallback to classful rules if the provided slash number is corrupted (e.g., /99) */
            final_prefix_len = get_classful_prefix_len(clean_ip);
        }
    } else {
        final_prefix_len = get_classful_prefix_len(target_ip);
    }

    int ret = set_interface_primary_ip(interface_name, target_ip, final_prefix_len);
    log_info("[WS] SET_IP executed for %s with IP %s/%d, %s", interface_name, target_ip, final_prefix_len, ret ? "SUCCESS" : "FAILURE");
}

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
            ws_process_config_payload(payload);
        }
    } else if (cJSON_IsString(type_node) && type_node->valuestring && strcmp(type_node->valuestring, "cmd") == 0) {
        cJSON *payload = cJSON_GetObjectItemCaseSensitive(root, "payload");
        if (payload && cJSON_IsString(payload)) {
            ws_process_cmd_payload(payload, NULL);
        }
    } else if (cJSON_IsString(type_node) && type_node->valuestring && strcmp(type_node->valuestring, "wlan") == 0) {
        cJSON *payload = cJSON_GetObjectItemCaseSensitive(root, "payload");
        if (payload && cJSON_IsObject(payload)) {
            ws_process_wlan_payload(payload);
        }
    }

    cJSON_Delete(root);
}

/**
 * @brief WebSocket telemetry logging bridge matching the rxi/log callback signature.
 * @note Stripped timestamp constraints. Includes synchronized stack-allocated JSON escaping 
 * to prevent payload corruption or parsing failures on the Web UI.
 * @param ev Pointer to the active log event context containing metadata and variadic arguments.
 */
static void ws_log_callback(log_Event *ev) {
    if (!ev || !ev->fmt) return;

    char json_buf[2560];
    
    const char json_prefix[] = "{\"type\":\"log\",\"payload\":{\"msg\":\"";
    const size_t prefix_len = sizeof(json_prefix) - 1;
    memcpy(json_buf, json_prefix, prefix_len);

    const char *level_strings[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
    const char *lvl_str = (ev->level >= 0 && ev->level <= 5) ? level_strings[ev->level] : "UNKNOWN";

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_time;
    localtime_r(&ts.tv_sec, &tm_time);

    char time_str[96];
    snprintf(time_str, sizeof(time_str), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
             tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec,
             (int)(ts.tv_nsec / 1000000));

    char *dst = json_buf + prefix_len;
    /* Leave enough safety margin at the end of the buffer:
     * 128 bytes reserved for the closing JSON "}}" and any
     * potential escape character inflation. */
    char *max_dst = json_buf + sizeof(json_buf) - 128;

    int meta_len = snprintf(dst, (size_t)(max_dst - dst), "[%s] [%-5s] %s:%d: ", 
                            time_str, lvl_str, ev->file, ev->line);
    if (meta_len < 0) return;
    dst += meta_len;

    char raw_msg[1024];
    int msg_len = vsnprintf(raw_msg, sizeof(raw_msg) - 1, ev->fmt, ev->ap);
    if (msg_len < 0) return;

    /* 
     * Highly optimized escape engine:
     * Directly escape raw_msg content and append it immediately 
     * after the metadata for maximum efficiency and minimal memory movement.
     */
    const char *src = raw_msg;
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

    /* Core optimization:
     * No longer need to call snprintf to append the tail.
     * Use direct pointer manipulation to hardcode the packet trailer.
     * Extremely fast. */
    *dst++ = '"';
    *dst++ = '}';
    *dst++ = '}';
    *dst = '\0';

    uint64_t json_len = (uint64_t)(dst - json_buf);

    if (json_len > 0) {
        wbs_bcast(json_buf, json_len);
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

    float cpu = sys_cpu_usage();
    float mem = sys_proc_mem_mb();
    float eth1_rx = 0.0f, eth1_tx = 0.0f;
    float eth2_rx = 0.0f, eth2_tx = 0.0f;

    if (sys_net_rate(redserver.dev1, eth1_ctx, &eth1_rx, &eth1_tx) != 0) {
        eth1_rx = 0.0f; eth1_tx = 0.0f;
    }
    if (sys_net_rate(redserver.dev2, eth2_ctx, &eth2_rx, &eth2_tx) != 0) {
        eth2_rx = 0.0f; eth2_tx = 0.0f;
    }

    /* Sanitize against non-finite float anomalies */
    cpu     = (cpu < 0.0f || !isfinite(cpu)) ? 0.0f : cpu;
    mem     = (mem < 0.0f || !isfinite(mem)) ? 0.0f : mem;
    eth1_rx = (eth1_rx < 0.0f || !isfinite(eth1_rx)) ? 0.0f : eth1_rx;
    eth2_rx = (eth2_rx < 0.0f || !isfinite(eth2_rx)) ? 0.0f : eth2_rx;

   /* Physical bandwidth safeguard:
    * For Gigabit NICs (theoretical max ~125000 KB/s),
    * if the computed rate exceeds 2x the physical limit (e.g. >250000 KB/s),
    * treat it as invalid (NIC reset or corrupted data) and reset to zero.
    */
    if (eth1_rx > 250000.0f) eth1_rx = 0.0f;
    if (eth2_rx > 250000.0f) eth2_rx = 0.0f;

    char fmt_cpu[32], fmt_mem[32];
    snprintf(fmt_cpu,  sizeof(fmt_cpu),  "%.2f", cpu);
    snprintf(fmt_mem,  sizeof(fmt_mem),  "%.2f", mem);

    cJSON *root = cJSON_CreateObject();
    if (!root) goto mem_error_abort;

    if (!cJSON_AddStringToObject(root, "type", "status")) goto cleanup_fail;

    cJSON *payload = cJSON_CreateObject();
    if (!payload) goto cleanup_fail;
    cJSON_AddItemToObject(root, "payload", payload);

    int isxdp1 = sys_is_xdp_loaded(redserver.dev1);
    int isxdp2 = sys_is_xdp_loaded(redserver.dev2);
    char eth1_buffer[INET_ADDRSTRLEN];
    char eth2_buffer[INET_ADDRSTRLEN];
    char ddev_buffer[INET_ADDRSTRLEN];

    get_interface_ip(redserver.dev1, eth1_buffer, sizeof(eth1_buffer));
    get_interface_ip(redserver.dev2, eth2_buffer, sizeof(eth2_buffer));
    get_interface_ip(redserver.ddev, ddev_buffer, sizeof(ddev_buffer));

    if (!cJSON_AddStringToObject(payload, "version", "2.0.1")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "gateway_ip", redserver.gw_host)) goto cleanup_fail;
    if (!cJSON_AddNumberToObject(payload, "gateway_port", redserver.ws_port)) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "cpu_usage",  fmt_cpu))  goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "mem_usage",  fmt_mem))  goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "black_zone_status", "UP")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "black_ip", redserver.core_ip ? redserver.core_ip : "0.0.0.0")) goto cleanup_fail;
    if (!cJSON_AddNumberToObject(payload, "black_port", redserver.core_port)) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "eth1_name", redserver.dev1 ? redserver.dev1 : "eth1")) goto cleanup_fail;
    if (!cJSON_AddNumberToObject(payload, "eth1_speed", eth1_rx)) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "eth1_ip", eth1_buffer)) goto cleanup_fail;
    if (!cJSON_AddBoolToObject(payload, "eth1_xdp", isxdp1)) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "eth2_name", redserver.dev2 ? redserver.dev2 : "eth2")) goto cleanup_fail;
    if (!cJSON_AddNumberToObject(payload, "eth2_speed", eth2_rx)) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "eth2_ip", eth2_buffer)) goto cleanup_fail;
    if (!cJSON_AddBoolToObject(payload, "eth2_xdp", isxdp2)) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "ddev_name", redserver.ddev ? redserver.ddev : "ddev")) goto cleanup_fail;
    if (!cJSON_AddStringToObject(payload, "ddev_ip", ddev_buffer)) goto cleanup_fail;

    char *json_raw_str = cJSON_PrintUnformatted(root);
    if (!json_raw_str) goto cleanup_fail;

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
    bool is_capture = cmd_ispcap_enabled();
    const char *ceth = cmd_get_current_eth();
    char filter[256] = {0};
    cmd_get_pcap_filter_safe(filter, sizeof(filter));

    cJSON_AddBoolToObject(payload, "isdebug", is_debug);            /* Map debug tracking state */
    cJSON_AddBoolToObject(payload, "islogpkt", is_logpkt);          /* Map packet reassembly state */
    cJSON_AddBoolToObject(payload, "iscapture", is_capture);        /* Placeholder/Default placeholder */
    cJSON_AddStringToObject(payload, "capture_interface", ceth);    /* Sync standard system log toggle */
    cJSON_AddStringToObject(payload, "packet_filter", filter);      /* Sync standard system log toggle */
    cJSON_AddStringToObject(payload, "dev1", redserver.dev1);      /* Sync standard system log toggle */
    cJSON_AddStringToObject(payload, "dev2", redserver.dev2);      /* Sync standard system log toggle */

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

int wbs_notify_thread(int interval_ms) {
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