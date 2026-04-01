/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <time.h>
#include <pthread.h>
#include "auth.h"
#include "log.h"
#include "hdr.h"
#include "util.h"

static uint32_t static_auth_value = 0;

/* Standard PING structure for link monitoring */
typedef struct {
    char magic[4];      /* "PING" */
    uint32_t sequence;  /* Incrementing ID to track packet loss */
    uint64_t timestamp; /* To calculate Round Trip Time (RTT) */
} __attribute__((packed)) auth_heartbeat_ping_t;

/**
 * Send Auth request and receive response
 * @param host        Server IP address (string)
 * @param port        Server port
 * @param payload     Optional payload data (can be NULL)
 * @param payload_len Length of payload
 * @param out_auth    Output: received Auth value
 * @return 0 on success, negative error code on failure
 */
static int auth_request(const char *host,
                int port,
                const unsigned char *payload,
                size_t payload_len,
                uint32_t *out_auth) {
    *out_auth = 0;

    unsigned char send_buf[BUFFER_SIZE];
    unsigned char recv_buf[BUFFER_SIZE];
    uint16_t type, len16;
    uint32_t auth32, crc32;
    udp_conn_t *conn = NULL;

    uint32_t total_len = HDR_SIZE + payload_len;
    if (total_len > AUTH_DATA_LENGTH) {
        log_error("Total length exceeds protocol limit: %u", total_len);
        return -1;
    }

    if (payload_len > 0) {
        memcpy(send_buf + HDR_SIZE, payload, payload_len);
    }
    hdr_build(send_buf, AUTH_REQ, total_len, 0);

    // log_info("Sending request to %s:%d, total length=%u", host, port, total_len);

    conn = udp_init_listener(0, 1);
    if (!conn) {
        log_error("Failed to initialize UDP sender");
        return -1;
    }

    ssize_t sent_bytes = udp_send_raw(
        conn, 
        host, port, 
        send_buf, total_len
    );
    
    if (sent_bytes < 0) {
        goto err;
    }

    struct sockaddr_in client_addr;
    ssize_t n = udp_recv_raw(conn, recv_buf, sizeof(recv_buf), &client_addr, 2000);
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

    udp_close(conn);
    return 0;

err:
    if (out_auth) *out_auth = 0;
    udp_close(conn);
    return -1;
}

auth_t *auth_create(uint32_t interval) {
    auth_t *at = calloc(1, sizeof(auth_t));
    if (!at) return NULL;

    at->auth_interval = interval;
    at->auth_value = 0;
    at->last_auth_update = 0;

    return at;
}

int auth_refresh(auth_t *at, const char *aip, uint16_t aport) {
    uint32_t new_auth = 0;

    /* Execute the network transaction. 
     * Note: auth_request should implement internal timeouts to prevent 
     * the thread from hanging indefinitely if the server is unreachable. 
     */
    if (auth_request(aip, aport, NULL, 0, &new_auth) == 0) {
        /* Atomic Update: In a single-writer, multi-reader scenario on 
         * modern CPUs, writing a 32-bit integer is typically atomic. */
        at->auth_value = new_auth;

        /**
         * Static Cache Update:
         * This static variable serves as a quick-access cache for the
         * most recent Auth value. It is intended for use in performance-critical
         * Avoid using redserver to prevent interface contamination.
         */
        static_auth_value = new_auth;
        /* Timestamping: Records the exact time of successful synchronization.
         * This allows the main thread to verify the freshness of the data. */
        at->last_auth_update = time(NULL);

        return 0;
    }

    log_error("Auth refresh failed.\n");
    return -1;
}

/**
 * Retrieves the cached authentication value or refreshes it if expired.
 * This implementation uses a non-blocking I/O pattern to ensure proxy performance.
 *
 * @param out_auth Pointer to store the current authentication value.
 * @return 0 on success, or specific error code on failure.
 */
int auth_get(auth_t *at, uint32_t *out_auth) {
    if (at->last_auth_update == 0)
        return -1;

    *out_auth = at->auth_value;

    return 0;
}

/**
 * @brief Retrieves the static cached Auth value.
 * This function provides quick access to the most recently updated
 * authentication value without needing to reference the auth_t structure.
 * if the value has never been set, it returns 0.
 */
uint32_t auth_get_static_value(void) {
    return static_auth_value;
}

void auth_free(auth_t *at) {
    if (!at) return;
    free(at);
}

/**
 * @brief Probes a remote host to verify network liveness using a UDP-based echo mechanism.
 * This function implements a synchronous "Application-level Ping". It sends a 
 * specialized heartbeat packet and waits for an identical echo response from the target.
 *
 * @param conn  Pointer to the persistent UDP connection handle.
 * @param host  Destination IPv4 address string.
 * @param port  Destination port number.
 * @return int  0 on success (Pong received), 
 * -2 on timeout (No response within 800ms), 
 * -1 on fatal socket or validation error.
 */
int auth_ping_probe(udp_conn_t *conn, const char *host, uint16_t port) {
    /* Thread-safe static sequence counter for packet tracking */
    static uint32_t seq = 0;
    uint64_t start_time = get_now_ms();
    
    auth_heartbeat_ping_t send_pkt = {
        .magic = {'P', 'I', 'N', 'G'},
        .sequence = htonl(seq++),
        .timestamp = start_time
    };

    /* 1. Transmission Phase:
     * Dispatch the raw heartbeat packet. The udp_send_raw function handles 
     * internal retries for transient kernel buffer congestion.
     */
    ssize_t sent = udp_send_raw(conn, host, port, &send_pkt, sizeof(send_pkt));
    if (sent < (ssize_t)sizeof(send_pkt)) {
        return -1;
    }

    /* 2. Reception Phase:
     * Block for a maximum of 800ms to receive the echo response.
     * The from address is stored to verify the source if multi-homed.
     */
    auth_heartbeat_ping_t recv_pkt;
    struct sockaddr_in from;
    ssize_t n = udp_recv_raw(conn, &recv_pkt, sizeof(recv_pkt), &from, 800);

    /* 3. Validation Phase:
     * Verify that the received packet size matches and the 'PING' magic 
     * constant is present, ensuring it is a valid heartbeat echo.
     */
    if (n == (ssize_t)sizeof(auth_heartbeat_ping_t)) {
        if (memcmp(recv_pkt.magic, "PING", 4) == 0) {
            uint64_t end_time = get_now_ms();
            uint64_t rtt = end_time - start_time;
            
            // log_info("Heartbeat OK: seq=%u, RTT=%lu ms", ntohl(recv_pkt.sequence), rtt);
            
            /* "If the RTT is too large, you can handle it additionally, 
             * for example, by determining it as a 'suboptimal link'."*/
            if (rtt > 500) {
                log_warn("High latency detected on auth link: %lu ms", rtt);
            }
            /* Link and remote application process are verified alive */
            return 0; 
        }
    }
    
    /* Differentiate between a clean timeout and a system-level error */
    return (n == 0) ? -2 : -1;
}