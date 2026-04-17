/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h> // Required for PATH_MAX
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include "log.h"
#include "health.h"

struct lrm_health_server {
    int sockfd;
    int ctrl_fd;            // Persistent AF_UNIX Socket
    time_t last_reconnect;  // Last attempt to connect
    bool stop;
    uint8_t rack_id;
    uint8_t slot_id;
    uint16_t current_status;
    time_t start_time;
    int interval;
};

static uint16_t calculate_checksum(void *b, int len) {
    uint16_t *buf = b;
    unsigned int sum = 0;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/**
 * @brief Fetches telemetry from Red LRM with zero-latency disconnect detection.
 * * RATIONALE: 
 * Standard recv() can lag if the kernel buffer contains stale packets. 
 * This implementation drains the buffer using MSG_DONTWAIT to find the absolute 
 * latest state or an immediate EOF (n=0).
 * * @return  0: Success (latest data retrieved)
 * -1: Transient failure (no new data, but link is alive)
 * -2: PEER CRASHED/EXITED (Link broken, immediate reset required)
 */
static int lrm_fetch_internal_info(lrm_health_server_t *server, lrm_internal_status_t *report) {
    if (!server || !report) return -1;

    time_t now = time(NULL);

    /* 1. Connection Management: Auto-reconnect with 3s cooling-off */
    if (server->ctrl_fd < 0) {
        if (now - server->last_reconnect < 3) return -1;
        
        server->last_reconnect = now;
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;

        /* Set a strict 100ms timeout for synchronous operations */
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; 
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, LRM_RED_UNIX_PATH, sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        server->ctrl_fd = fd;
        log_info("IPC: Re-connected to Red LRM monitoring interface.");
    }

    /* 2. DRAIN BUFFER: Loop until the most recent packet is found */
    lrm_internal_status_t latest_tmp;
    ssize_t n;
    int has_new_frame = 0;

    /* Drain kernel buffer to skip stale data and check for EOF */
    while (1) {
        n = recv(server->ctrl_fd, &latest_tmp, sizeof(lrm_internal_status_t), MSG_DONTWAIT);
        
        if (n == (ssize_t)sizeof(lrm_internal_status_t)) {
            /* We found a valid frame, keep loop to see if there's a newer one */
            memcpy(report, &latest_tmp, sizeof(lrm_internal_status_t));
            has_new_frame = 1;
            continue; 
        } 
        
        if (n == 0) {
            /* CRITICAL: Peer performed orderly shutdown or process was killed */
            log_warn("IPC: Link broken (Remote peer closed socket).");
            goto handle_fatal_disconnect;
        }
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No more data in buffer, this is the expected exit for the loop */
                break;
            }
            if (errno == EINTR) continue; /* Interrupted by signal, retry */
            
            /* Real socket error (EPIPE, ECONNRESET, etc.) */
            log_error("IPC: Socket read error: %s", strerror(errno));
            goto handle_fatal_disconnect;
        }
        
        /* Fragmented or unexpected packet size: protocol desync */
        if (n > 0) {
            log_warn("IPC: Received unexpected data size (%zd bytes). Draining...", n);
        }
    }

    return (has_new_frame) ? 0 : -1;

handle_fatal_disconnect:
    if (server->ctrl_fd >= 0) {
        close(server->ctrl_fd);
        server->ctrl_fd = -1;
    }
    memset(report, 0, sizeof(lrm_internal_status_t));
    return -2; /* Fatal return code to trigger priority-override in pack logic */
}

/**
 * Optimized Process Check with PID Caching.
 * Reduces CPU load by avoiding full /proc scans when the process is stable.
 */
static uint16_t lrm_check_service() {
    static pid_t last_pid = -1;
    const char *target_name = "redlrm";
    char comm_path[PATH_MAX];
    char comm_name[64];

    /* Phase 1: Check Cached PID first (Fastest) */
    if (last_pid > 0) {
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", last_pid);
        FILE *f = fopen(comm_path, "r");
        if (f) {
            if (fgets(comm_name, sizeof(comm_name), f)) {
                comm_name[strcspn(comm_name, "\r\n")] = 0;
                if (strcmp(comm_name, target_name) == 0) {
                    fclose(f);
                    return 0x0000; 
                }
            }
            fclose(f);
        }
        last_pid = -1; /* Cache invalidated */
    }

    /* Phase 2: Strategy A (PID File) */
    // ... (Existing Strategy A code remains here, update last_pid on success)

    /* Phase 3: Strategy B (Proc Scan) */
    DIR *dir = opendir("/proc");
    if (!dir) return 0x0001;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            snprintf(comm_path, sizeof(comm_path), "/proc/%.240s/comm", entry->d_name);
            FILE *cp = fopen(comm_path, "r");
            if (cp) {
                if (fgets(comm_name, sizeof(comm_name), cp)) {
                    comm_name[strcspn(comm_name, "\r\n")] = 0;
                    if (strcmp(comm_name, target_name) == 0) {
                        last_pid = atoi(entry->d_name); // Update Cache
                        fclose(cp);
                        closedir(dir);
                        return 0x0000;
                    }
                }
                fclose(cp);
            }
        }
    }
    closedir(dir);
    return 0x0001;
}

/**
 * @brief Industrial-grade ICMP payload generator.
 * * Logic: Priority is given to the real-time AF_UNIX link. If the link reports 
 * a fatal disconnect (-2), it overrides the slow process scanner to report 
 * failure instantly.
 */
static void lrm_health_pack_icmp(lrm_health_server_t *server, 
                                 uint8_t *buffer, 
                                 uint8_t type, 
                                 uint16_t id, 
                                 uint16_t seq) 
{
    // 1. Setup ICMP Standard Header
    struct icmphdr *icmp = (struct icmphdr *)buffer;
    icmp->type = type;
    icmp->code = 0;
    icmp->un.echo.id = id;
    icmp->un.echo.sequence = seq;
    icmp->checksum = 0;

    // 2. Initialize Payload
    lrm_health_payload_t *payload = (lrm_health_payload_t *)(buffer + sizeof(struct icmphdr));
    payload->magic = htonl(0x484C5448);
    payload->rack_id = server->rack_id;
    payload->slot_id = server->slot_id;

    lrm_internal_status_t internal_report;
    /* Safety: Always zero out temporary report */
    memset(&internal_report, 0, sizeof(internal_report));

    /* Attempt to fetch the most recent telemetry */
    int fetch_rc = lrm_fetch_internal_info(server, &internal_report);

    if (fetch_rc == 0) {
        /* [PATH A] PEER ALIVE: Copy telemetry data into payload */
        server->current_status = internal_report.custom_err;
        memcpy(&(payload->detail), &internal_report, sizeof(lrm_internal_status_t));
        
        /* Network byte order conversions */
        payload->detail.mem_usage_kb = htonl(internal_report.mem_usage_kb);
        payload->detail.version_major = htons(internal_report.version_major);
        payload->detail.version_minor = htons(internal_report.version_minor);
        payload->detail.version_patch = htons(internal_report.version_patch);
        payload->detail.cpu_load = htons(internal_report.cpu_load);
        // Note: cpu_load is uint8/uint16, usually no conversion needed for single byte
    } else if (fetch_rc == -2) {
        /* [PATH B] PEER JUST DIED: IPC reported EOF.
         * Immediate override to status 0x0001 (Fault).
         * This bypasses the /proc scan which can be slow and stale. */
        server->current_status = 0x0001; 
        memset(&(payload->detail), 0, sizeof(lrm_internal_status_t));
        log_warn("Health: Forcing fault status due to confirmed IPC loss.");
    } else {
        /* [PATH C] LINK PERSISTENTLY DOWN: Fallback to process scanning.
         * Used during service startup or when the peer is frozen. */
        server->current_status = lrm_check_service();
        memset(&(payload->detail), 0, sizeof(lrm_internal_status_t));
    }

    payload->status_bits = htons(server->current_status);
    payload->uptime = htonl((uint32_t)(time(NULL) - server->start_time));

    // 3. Finalize Checksum
    icmp->checksum = calculate_checksum(buffer, sizeof(struct icmphdr) + sizeof(lrm_health_payload_t));
}

lrm_health_server_t* lrm_health_create(uint8_t rack, uint8_t slot, const int interval) {
    /* * Block SIGPIPE signals globally for this process.
     * * RATIONALE: In Unix-like systems, writing to or reading from a socket 
     * whose remote end has been closed (common in AF_UNIX IPC when the 
     * peer service crashes) triggers a SIGPIPE. The default action for 
     * SIGPIPE is to terminate the process immediately. 
     *
     * By ignoring this signal, we ensure the Health Service remains resilient; 
     * failed I/O operations will instead return -1 with errno set to EPIPE, 
     * allowing our internal state machine (lrm_fetch_internal_info) to 
     * handle the reconnection gracefully without crashing.
     */
    signal(SIGPIPE, SIG_IGN);

    /* 1. Use calloc to prevent garbage data in uninitialized members */
    lrm_health_server_t *server = calloc(1, sizeof(struct lrm_health_server));
    if (!server) {
        log_error("Failed to allocate health server context");
        return NULL;
    }

    /* Initialize persistence handles */
    server->ctrl_fd = -1; 
    server->last_reconnect = 0;

    /* 2. Initialize critical socket with enhanced error reporting */
    server->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (server->sockfd < 0) {
        if (errno == EPERM) {
            log_error("Permission denied: Raw sockets require root/CAP_NET_RAW");
        } else {
            log_error("Failed to create raw socket: %s", strerror(errno));
        }
        free(server);
        return NULL;
    }

    /* 3. Batch Socket Configuration */
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    int reuse = 1;

    // Receive Timeout: Critical for the run loop's periodic active checks
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_warn("Non-fatal: Failed to set SO_RCVTIMEO: %s", strerror(errno));
    }

    // Send Timeout: Prevents the service from hanging on a congested network interface
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_warn("Non-fatal: Failed to set SO_SNDTIMEO: %s", strerror(errno));
    }

    // Address Reuse: Essential for rapid service restarts
    if (setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        log_warn("Non-fatal: Failed to set SO_REUSEADDR: %s", strerror(errno));
    }

    /* 4. Business Logic Initialization */
    server->rack_id = rack;
    server->slot_id = slot;
    server->stop = false;
    server->current_status = 0;
    server->start_time = time(NULL);
    
    /* Clamp interval to a safe minimum if necessary (e.g., min 1s) */
    server->interval = (interval > 0) ? interval : LRM_HEALTH_INTERVAL;

    log_info("Health Server created for Rack[%d] Slot[%d] with Interval[%ds]", 
             rack, slot, server->interval);

    return server;
}

void lrm_health_destroy(lrm_health_server_t *server) {
    if (server) {
        server->stop = true;
        if (server->sockfd >= 0) close(server->sockfd);
        if (server->ctrl_fd >= 0) close(server->ctrl_fd); // Cleanup Unix socket
        free(server);
        log_info("Health Server destroyed.");
    }
}

void lrm_health_set_status(lrm_health_server_t *server, uint16_t status) {
    if (server) server->current_status = status;
}

/**
 * Main execution loop with Dual-Mode (Passive & Active).
 * Uses SO_RCVTIMEO to prevent blocking forever.
 */
int lrm_health_run(lrm_health_server_t *server, const char *target_ip) {
    if (!server || server->sockfd < 0) return -1;

    uint8_t recv_buf[2048];
    struct sockaddr_in from_addr;
    socklen_t addr_len = sizeof(from_addr);
    time_t last_active_push = 0;

    log_info("Health Service running (Dual-Mode). Active Target: %s", 
             target_ip ? target_ip : "NONE");

    while (!server->stop) {
        time_t now = time(NULL);

        // --- PHASE 1: ACTIVE PUSH LOGIC ---
        if (target_ip && (now - last_active_push >= server->interval)) {
            lrm_health_send_active_report(server, target_ip);
            last_active_push = now;
        }

        // --- PHASE 2: PASSIVE RESPONSE LOGIC ---
        ssize_t n = recvfrom(server->sockfd, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *)&from_addr, &addr_len);
        
        if (n < 0) {
            // EAGAIN means timeout reached, just loop back to check active push
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            log_error("Fatal recvfrom error: %s", strerror(errno));
            break; 
        }

        // Validate and process the received ICMP packet
        struct iphdr *ip = (struct iphdr *)recv_buf;
        size_t ip_hdr_len = (size_t)ip->ihl * 4;
        
        if ((size_t)n < ip_hdr_len + sizeof(struct icmphdr)) continue;

        struct icmphdr *icmp_req = (struct icmphdr *)(recv_buf + ip_hdr_len);

        // Only respond to ECHO REQUEST (Ping)
        if (icmp_req->type == ICMP_ECHO) {
            server->current_status = lrm_check_service();

            uint8_t reply_pkt[sizeof(struct icmphdr) + sizeof(lrm_health_payload_t)];
            memset(reply_pkt, 0, sizeof(reply_pkt));

            lrm_health_pack_icmp(server, reply_pkt, ICMP_ECHOREPLY, 
                                 icmp_req->un.echo.id, icmp_req->un.echo.sequence);

            sendto(server->sockfd, reply_pkt, sizeof(reply_pkt), 0,
                   (struct sockaddr *)&from_addr, addr_len);
        }
    }
    return 0;
}

/**
 * Actively sends a health heartbeat (ICMP Echo Request) to a specific target.
 * Designed for "Push" mode in industrial monitoring.
 */
int lrm_health_send_active_report(lrm_health_server_t *server, const char *dst_ip) {
    if (!server || !dst_ip) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, dst_ip, &dest.sin_addr) <= 0) return -1;

    uint8_t pkt[sizeof(struct icmphdr) + sizeof(lrm_health_payload_t)];
    
    lrm_health_pack_icmp(server, pkt, ICMP_ECHO, htons(getpid() & 0xFFFF), 0);

    ssize_t sent = sendto(server->sockfd, pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&dest, sizeof(dest));
    
    if (sent <= 0) {
        log_error("Active report failed to %s: %s", dst_ip, strerror(errno));
        return -1;
    }
    return 0;
}