/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <time.h>
#include <pthread.h>
#include "authx.h"
#include "log.h"
#include "hdr.h"
#include "util.h"

#define HEARTBEAT_INTERVAL_SEC 5            /* Heartbeat frequency during idle gap */
#define MAX_ALLOWED_FAILS      3            /* Failures required to trip liveness flag */
#define PACKET_BUFFER_SIZE     65535

static uint32_t static_auth_value = 0;

/* Standard PING structure for link monitoring */
typedef struct {
    char magic[4];      /* "PING" */
    uint32_t sequence;  /* Incrementing ID to track packet loss */
    uint64_t timestamp; /* To calculate Round Trip Time (RTT) */
} __attribute__((packed)) auth_heartbeat_ping_t;

/**
 * Send Auth request and receive response
 * @param payload     Optional payload data (can be NULL)
 * @param payload_len Length of payload
 * @param out_auth    Output: received Auth value
 * @return 0 on success, negative error code on failure
 */
static int auth_request(auth_ctx_t *ctx, const unsigned char *payload,
                        size_t payload_len,
                        uint32_t *out_auth) {
    *out_auth = 0;

    unsigned char send_buf[BUFFER_SIZE];
    unsigned char recv_buf[BUFFER_SIZE];
    uint16_t type, len16;
    uint32_t auth32, crc32;

    uint32_t total_len = HDR_SIZE + payload_len;
    if (total_len > AUTH_DATA_LENGTH) {
        log_error("Total length exceeds protocol limit: %u", total_len);
        return -1;
    }

    if (payload_len > 0) {
        memcpy(send_buf + HDR_SIZE, payload, payload_len);
    }
    hdr_build(send_buf, AUTH_REQ, total_len, 0);

    ssize_t sent_bytes = udp_send_raw(
        ctx->conn, 
        ctx->auth_ip, ctx->auth_port, 
        send_buf, total_len
    );
    
    if (sent_bytes < 0) {
        goto err;
    }

    struct sockaddr_in client_addr;
    ssize_t n = udp_recv_raw(ctx->conn, recv_buf, sizeof(recv_buf), &client_addr, 2000);
    if (n < 0) return -1;
    if (n != HDR_SIZE) {
        log_error("Response length error: expected %d, got %zd", HDR_SIZE, n);
        goto err;
    }

    if (hdr_parse(recv_buf, &type, &len16, &auth32, &crc32) != 0) {
        log_error("Failed to parse response header");
        goto err;
    }

    if (len16 != HDR_SIZE) {
        log_error("Len16 mismatch: expected %d, got %u", HDR_SIZE, len16);
        goto err;
    }

    if (!hdr_verify_crc(recv_buf, n)) {
        log_error("CRC verification failed");
        goto err;
    }

    if (type != AUTH_REP) {
        log_error("Response type mismatch: expected 0x%04x, got 0x%04x", AUTH_REP, type);
        goto err;
    }

    *out_auth = auth32;

    return 0;

err:
    if (out_auth) *out_auth = 0;
    return -1;
}

static int auth_refresh(auth_ctx_t *ctx) {
    uint32_t new_auth = 0;

    /* Execute the network transaction. 
     * Note: auth_request should implement internal timeouts to prevent 
     * the thread from hanging indefinitely if the server is unreachable. 
     */
    if (auth_request(ctx, NULL, 0, &new_auth) == 0) {
        /* Atomic Update: In a single-writer, multi-reader scenario on 
         * modern CPUs, writing a 32-bit integer is typically atomic. */
        ctx->auth_value = new_auth;

        /**
         * Static Cache Update:
         * This static variable serves as a quick-access cache for the
         * most recent Auth value. It is intended for use in performance-critical
         * Avoid using redserver to prevent interface contamination.
         */
        static_auth_value = new_auth;
        /* Timestamping: Records the exact time of successful synchronization.
         * This allows the main thread to verify the freshness of the data. */
        ctx->last_auth_update = time(NULL);

        return 0;
    }

    log_error("Auth refresh failed.");
    return -1;
}

/**
 * @brief Retrieves the static cached Auth value.
 * This function provides quick access to the most recently updated
 * authentication value without needing to reference the auth_t structure.
 * if the value has never been set, it returns 0.
 */
uint32_t auth_get_value(void) {
    return static_auth_value;
}

/**
 * @brief Application-level synchronous UDP loop ping validation probe.
 */
static int auth_ping_probe(auth_ctx_t *ctx) {
    if (!ctx) return -1;

    /* Thread-safe initialization using an atomic sequence sequence tracker */
    static _Atomic uint32_t global_seq = 0;
    uint64_t start_time = get_now_ms();
    uint32_t local_seq = atomic_fetch_add(&global_seq, 1);
    auth_heartbeat_ping_t send_pkt;
    auth_heartbeat_ping_t recv_pkt;
    struct sockaddr_in from;
    ssize_t n;
    uint64_t end_time;
    uint64_t rtt;

    memset(&send_pkt, 0, sizeof(send_pkt));
    memcpy(send_pkt.magic, "PING", 4);
    send_pkt.sequence = htonl(local_seq);
    send_pkt.timestamp = start_time;

    /* Dispatch heartbeat echo request downstream */
    ssize_t sent = udp_send_raw(ctx->conn, ctx->auth_ip, ctx->auth_port, &send_pkt, sizeof(send_pkt));
    if (sent < (ssize_t)sizeof(send_pkt)) {
        log_error("Heartbeat pipe jammed: system-level socket transmission error");
        return -1;
    }

    /* Wait for a matching echo response with an 800ms boundary */
    n = udp_recv_raw(ctx->conn, &recv_pkt, sizeof(recv_pkt), &from, 800);

    /* Enforce verification constraints on returning packet */
    if (n == (ssize_t)sizeof(auth_heartbeat_ping_t)) {
        if (memcmp(recv_pkt.magic, "PING", 4) == 0) {
            end_time = get_now_ms();
            rtt = end_time - start_time;
            
            if (rtt > 500) {
                log_warn("Degraded network topology: high latency detected: %lu ms", rtt);
            }
            return 0; /* Node is fully responsive and verified active */
        }
    }
    
    return (n == 0) ? -2 : -1;
}

/**
 * @brief Core tracking engine execution loop callback.
 * @note Implements micro-step sleeping to prevent shutdown blockades.
 */
static void* auth_monitor_thread_fn(void *arg) {
    auth_ctx_t *ctx = (auth_ctx_t *)arg;
    time_t last_ping_time = 0;
    time_t now;
    int current_fails;
    int ping_res;

    if (unlikely(!ctx)) return NULL;

    log_info("Auth monitor engine thread instantiated. TID: %lu", (unsigned long)ctx->auth_tid);

    /* Bootstrap Phase: Synchronize core token before opening up pipelines */
    if (auth_refresh(ctx) == 0) {
        atomic_store(&ctx->is_alive, true);
        atomic_store(&ctx->fail_count, 0);
    } else {
        atomic_store(&ctx->is_alive, false);
        atomic_store(&ctx->fail_count, 1);
    }

    /* Execution Frame Matrix */
    while (atomic_load(&ctx->running)) {
        now = time(NULL);

        /* Branch A: Hard Token Refresh Lifespan Exceeded */
        if (now - ctx->last_auth_update >= (time_t)ctx->auth_interval) {
            log_info("Token interval deadline breached, executing background refresh...");
            if (auth_refresh(ctx) == 0) {
                atomic_store(&ctx->fail_count, 0);
                atomic_store(&ctx->is_alive, true);
            } else {
                current_fails = atomic_fetch_add(&ctx->fail_count, 1) + 1;
                log_error("Asynchronous token synchronization failed. Continuous tracking: %d", current_fails);
                if (current_fails >= MAX_ALLOWED_FAILS) {
                    atomic_store(&ctx->is_alive, false);
                }
            }
        }

        /* Branch B: Active State Heartbeat Intermittent Verification */
        if (now - last_ping_time >= HEARTBEAT_INTERVAL_SEC) {
            last_ping_time = now;
            
            ping_res = auth_ping_probe(ctx);
            if (ping_res == 0) {
                atomic_store(&ctx->fail_count, 0);
                atomic_store(&ctx->is_alive, true);
            } else {
                current_fails = atomic_fetch_add(&ctx->fail_count, 1) + 1;
                log_warn("Liveness probe failure hit (code: %d). Pipeline fail gauge: %d", ping_res, current_fails);
                
                if (current_fails >= MAX_ALLOWED_FAILS) {
                    atomic_store(&ctx->is_alive, false);
                }
            }
        }

        /* Micro-step slicing: Guarantees sub-second thread termination latency */
        sleep(1);
    }
    return NULL;
}

/**
 * @brief Allocates execution frames and initializes worker threads.
 */
int auth_monitor_start(auth_ctx_t *ctx) {
    bool expected = false;

    if (unlikely(!ctx)) return -1;

    if (atomic_load(&ctx->running)) {
        log_warn("Re-entrancy blocked: Auth monitor lifecycle thread already initialized.");
        return 0;
    }

    ctx->conn = udp_init_listener(ctx->auth_port, 1);
    if (unlikely(!ctx->conn)) {
        log_error("Failed to initialize UDP listener for Auth monitor.");
        goto err;
    }

    /* Atomically test and set the 'running' state to block re-entrancy.
     * This eliminates the Check-Then-Act Race Condition across multiple initialization threads.
     */
    if (!atomic_compare_exchange_strong(&ctx->running, &expected, true)) {
        log_warn("Re-entrancy blocked: Auth monitor lifecycle thread already initialized or running.");
        return 0;
    }
    atomic_store(&ctx->is_alive, false);
    atomic_store(&ctx->fail_count, 0);

    if (pthread_mutex_init(&ctx->state_lock, NULL) != 0) {
        log_error("Failed to allocate kernel space primitives for state_lock");
        goto err;
    }

    if (pthread_create(&ctx->auth_tid, NULL, auth_monitor_thread_fn, ctx) != 0) {
        log_error("Critical crash: Operating system rejected worker thread allocation allocation.");
        pthread_mutex_destroy(&ctx->state_lock);
        goto err;
    }

    return 0;
err:
    atomic_store(&ctx->running, false);
    if (ctx->conn) {
        udp_close(ctx->conn);
        ctx->conn = NULL;
    }
    if (ctx->auth_ip) {
        free(ctx->auth_ip);
        ctx->auth_ip = NULL;
    }
    return -1;
}

/**
 * @brief Gracefully commands asynchronous routines to stop and deallocates memory.
 */
void auth_monitor_stop(auth_ctx_t *ctx) {
    if (unlikely(!ctx)) return;

    if (atomic_load(&ctx->running)) {
        atomic_store(&ctx->running, false);
    }

    if (ctx->auth_tid) {
        pthread_join(ctx->auth_tid, NULL);
        ctx->auth_tid = 0;
    }

    pthread_mutex_destroy(&ctx->state_lock);

    if (likely(ctx->auth_ip)) {
        free(ctx->auth_ip);
        ctx->auth_ip = NULL;
    }

    if (likely(ctx->conn)) {
        udp_close(ctx->conn);
        ctx->conn = NULL;
    }

    atomic_store(&ctx->is_alive, false);
    log_info("Auth monitor context dismantled and flushed out successfully.");
}