/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sys/file.h>
#include <signal.h>
#include <fcntl.h>
#include "log.h"
#include "af_unix.h"

#define RED_LRM_VERSION_MAJOR    1
#define RED_LRM_VERSION_MINOR    2
#define RED_LRM_VERSION_PATCH    3
#define LRM_RED_UNIX_PATH       "/tmp/redlrm_internal.sock"
#define MAX_UNIX_CLIENTS         10

typedef struct {
    unsigned long long last_cpu_ticks;
    struct timespec last_time;
    long clock_ticks_per_sec;
    int proc_stat_fd;
    int proc_status_fd;
} lrm_collect_ctx_t;

/* Slot 0 is reserved for Listener */
static struct pollfd g_poll_fds[MAX_UNIX_CLIENTS + 1];
static int g_server_fd = -1;
static pthread_t g_server_tid;
static lrm_internal_status_t g_current_report;
static pthread_mutex_t g_data_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_running = 0;
static int g_collect_interval = 500; /*500ms*/

/**
 * @brief Sets a file descriptor to non-blocking mode.
 * @param fd The target file descriptor.
 * @return 0 on success, -1 on failure.
 */
static int set_nonblocking(int fd) {
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * @brief Initializes the pollfd array.
 */
static void init_poll_slots() {
    for (int i = 0; i < MAX_UNIX_CLIENTS + 1; i++) {
        g_poll_fds[i].fd = -1;
        g_poll_fds[i].events = POLLIN | POLLERR | POLLHUP;
        g_poll_fds[i].revents = 0;
    }
}

/**
 * @brief Calculates the current process CPU utilization percentage.
 *
 * RATIONALE: 
 * CPU load is a derivative metric calculated over a time interval. This function 
 * maintains internal state (last sample) to compute the delta between calls. 
 * It uses CLOCK_MONOTONIC to ensure stability against NTP time adjustments or 
 * manual system clock changes.
 *
 * @return uint16_t CPU load percentage (0-100). Returns 0 on the first call 
 * or if a calculation error occurs.
 */
static uint16_t lrm_utils_get_cpu_load_internal(lrm_collect_ctx_t *ctx) {
    if (ctx->proc_stat_fd < 0) return 0;

    char buf[512];
    ssize_t n = pread(ctx->proc_stat_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return 0;
    buf[n] = '\0';

    unsigned long utime = 0, stime = 0;
    int fields_read = sscanf(buf, 
        "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", 
        &utime, &stime);

    if (fields_read != 2) return 0;

    struct timespec current_time;
    if (clock_gettime(CLOCK_MONOTONIC, &current_time) != 0) return 0;

    unsigned long long current_cpu_ticks = (unsigned long long)utime + stime;
    uint16_t load_percent = 0;

    if (ctx->last_cpu_ticks > 0 && ctx->last_time.tv_sec > 0) {
        double seconds_elapsed = (current_time.tv_sec - ctx->last_time.tv_sec) + 
                                 (current_time.tv_nsec - ctx->last_time.tv_nsec) / 1e9;

        if (seconds_elapsed > 0.0001) {
            double cpu_seconds = (double)(current_cpu_ticks - ctx->last_cpu_ticks) / ctx->clock_ticks_per_sec;
            double utilization = (cpu_seconds / seconds_elapsed) * 100.0;
            if (utilization < 0.0) utilization = 0.0;
            if (utilization > 100.0) utilization = 100.0;
            load_percent = (uint16_t)(utilization + 0.5);
        }
    }

    ctx->last_cpu_ticks = current_cpu_ticks;
    ctx->last_time = current_time;
    return load_percent;
}

// uint16_t lrm_utils_get_cpu_load(void) {
//     static lrm_collect_ctx_t standalone_ctx = { .proc_stat_fd = -1 };
//     if (standalone_ctx.proc_stat_fd < 0) {
//         standalone_ctx.clock_ticks_per_sec = sysconf(_SC_CLK_TCK);
//         standalone_ctx.proc_stat_fd = open("/proc/self/stat", O_RDONLY);
//     }
//     return lrm_utils_get_cpu_load_internal(&standalone_ctx);
// }

/**
 * Internal Data Collection: Fetches deep telemetry data from the local process.
 * INDUSTRIAL GRADE: Uses robust /proc parsing, avoids buffer overflows, 
 * and handles potential file descriptor exhaustion.
 */
static void lrm_unix_internal_collect_with_ctx(lrm_collect_ctx_t *ctx, lrm_internal_status_t *report) {
    if (!report) return;

    report->version_major = RED_LRM_VERSION_MAJOR; 
    report->version_minor = RED_LRM_VERSION_MINOR;
    report->version_patch = RED_LRM_VERSION_PATCH;
    report->cpu_load = lrm_utils_get_cpu_load_internal(ctx);

    if (ctx->proc_status_fd >= 0) {
        char buf[1024];
        ssize_t n = pread(ctx->proc_status_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            char *match = strstr(buf, "VmRSS:");
            if (match) {
                char *ptr = match + 6;
                while (*ptr && (*ptr < '0' || *ptr > '9')) ptr++;
                if (*ptr) {
                    report->mem_usage_kb = (uint32_t)strtoul(ptr, NULL, 10);
                }
            }
        }
    }
}


/**
 * @brief Worker thread for the Unix Domain Socket server.
 * Handles telemetry collection, client management, and data broadcasting.
 * @param arg Unused thread argument.
 * @return void* NULL on thread exit.
 */
static void *lrm_unix_worker(void *arg) {
    (void)arg;
    struct sockaddr_un addr;
    
    /**
     * INDUSTRIAL OPTIMIZATION:
     * Initialize collection context with pre-opened proc file descriptors.
     * This avoids repeated open/close overhead in high-frequency sampling loops.
     */
    lrm_collect_ctx_t thread_ctx = {
        .proc_stat_fd = open("/proc/self/stat", O_RDONLY),
        .proc_status_fd = open("/proc/self/status", O_RDONLY),
        .clock_ticks_per_sec = sysconf(_SC_CLK_TCK),
        .last_cpu_ticks = 0
    };

    /* BLOCK SIGPIPE: Ensure the process doesn't terminate if a client closes the socket during send. */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    init_poll_slots();

    /**
     * STALE SOCKET CLEANUP:
     * Preemptively unlink the socket file to avoid EADDRINUSE errors.
     */
    if (access(LRM_RED_UNIX_PATH, F_OK) == 0) {
        unlink(LRM_RED_UNIX_PATH);
    }

    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        log_error("Unix Server: Failed to create socket: %s", strerror(errno));
        goto thread_cleanup;
    }

    /* Set server socket to non-blocking for robust accept() logic. */
    set_nonblocking(g_server_fd);

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LRM_RED_UNIX_PATH, sizeof(addr.sun_path) - 1);

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("Unix Server: Bind failed: %s", strerror(errno));
        goto thread_cleanup;
    }

    /* Allow monitoring tools to access the socket across different user contexts. */
    chmod(LRM_RED_UNIX_PATH, 0666);
    listen(g_server_fd, 5);
    
    g_poll_fds[0].fd = g_server_fd;
    g_poll_fds[0].events = POLLIN;

    log_info("Unix Server: Industrial service active on %s", LRM_RED_UNIX_PATH);

    while (g_running) {
        /**
         * Wait for I/O events with a timeout synchronized to the collection interval.
         * We do NOT 'continue' on timeout (ret==0) because we need to perform 
         * periodic data collection and broadcast.
         */
        int ret = poll(g_poll_fds, MAX_UNIX_CLIENTS + 1, g_collect_interval);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("Unix Server: Poll critical error: %s", strerror(errno));
            break;
        }

        /* --- STEP 1: Proactive Disconnection Detection (Logic C) --- */
        /* Check existing clients for EOF or hangup signals before broadcasting. */
        for (int i = 1; i <= MAX_UNIX_CLIENTS; i++) {
            if (g_poll_fds[i].fd > 0) {
                /* If poll indicates activity, or if we need a periodic health check */
                if (ret > 0 && (g_poll_fds[i].revents & (POLLIN | POLLHUP | POLLERR))) {
                    char dummy;
                    /* MSG_PEEK is used to detect EOF (0) without consuming actual data. */
                    ssize_t n = recv(g_poll_fds[i].fd, &dummy, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                        log_info("Unix Server: Client at slot [%d] (fd:%d) disconnected.", i, g_poll_fds[i].fd);
                        close(g_poll_fds[i].fd);
                        g_poll_fds[i].fd = -1;
                        g_poll_fds[i].revents = 0;
                    }
                }
            }
        }

        /* --- STEP 2: Non-blocking Accept Loop (Logic B) --- */
        /* Drain the accept queue to handle burst connection attempts. */
        if (ret > 0 && (g_poll_fds[0].revents & POLLIN)) {
            int new_fd;
            while (g_running) {
                new_fd = accept(g_server_fd, NULL, NULL);
                if (new_fd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    break;
                }

                set_nonblocking(new_fd);
                int assigned = 0;
                for (int i = 1; i <= MAX_UNIX_CLIENTS; i++) {
                    if (g_poll_fds[i].fd == -1) {
                        g_poll_fds[i].fd = new_fd;
                        g_poll_fds[i].revents = 0; 
                        assigned = 1;
                        log_info("Unix Server: Slot [%d] assigned to new fd:%d", i, new_fd);
                        break;
                    }
                }
                if (!assigned) {
                    log_warn("Unix Server: Max clients reached, rejecting fd:%d", new_fd);
                    close(new_fd);
                }
            }
        }

        /* --- STEP 3: Telemetry Broadcast (Logic A) --- */
        /* Execute data collection and broadcast to all active subscribers. */
        lrm_internal_status_t fresh_data;
        memset(&fresh_data, 0, sizeof(fresh_data));
        lrm_unix_internal_collect_with_ctx(&thread_ctx, &fresh_data);

        pthread_mutex_lock(&g_data_mutex);
        memcpy(&g_current_report, &fresh_data, sizeof(lrm_internal_status_t));
        lrm_internal_status_t snapshot = g_current_report;
        pthread_mutex_unlock(&g_data_mutex);

        for (int i = 1; i <= MAX_UNIX_CLIENTS; i++) {
            if (g_poll_fds[i].fd > 0) {
                /* Use MSG_DONTWAIT and MSG_NOSIGNAL for non-blocking, safe transmission. */
                ssize_t sent = send(g_poll_fds[i].fd, &snapshot, sizeof(snapshot), MSG_NOSIGNAL | MSG_DONTWAIT);
                if (sent < (ssize_t)sizeof(snapshot)) {
                    /* If buffer is full (EAGAIN), skip this frame; for critical errors, drop client. */
                    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                    
                    log_warn("Unix Server: Link to slot [%d] lost during send, closing.", i);
                    close(g_poll_fds[i].fd);
                    g_poll_fds[i].fd = -1;
                }
            }
        }
    }

thread_cleanup:
    /**
     * RESOURCE RELEASE SEQUENCE:
     * Ensure all file descriptors and persistent resources are closed.
     */
    if (thread_ctx.proc_stat_fd >= 0) close(thread_ctx.proc_stat_fd);
    if (thread_ctx.proc_status_fd >= 0) close(thread_ctx.proc_status_fd);

    for (int i = 0; i <= MAX_UNIX_CLIENTS; i++) {
        if (g_poll_fds[i].fd >= 0) {
            close(g_poll_fds[i].fd);
            g_poll_fds[i].fd = -1;
        }
    }
    unlink(LRM_RED_UNIX_PATH);
    // log_info("Unix Server: Service stopped and resources cleaned.");
    return NULL;
}

int lrm_unix_server_start(int interval_ms) {
    if (g_running) return 0;

    g_collect_interval = (interval_ms < 10) ? 100 : interval_ms;
    g_running = 1;

    if (pthread_create(&g_server_tid, NULL, lrm_unix_worker, NULL) != 0) {
        log_error("Unix Server: Failed to create worker thread.");
        g_running = 0;
        return -1;
    }
    
    return 0;
}

void lrm_unix_server_stop(void) {
    if (!g_running) return;
    
    g_running = 0;
    
    /* FORCE WAKEUP:
     * Using shutdown() with SHUT_RDWR triggers a state change on the socket 
     * that forces any blocking calls (like poll() or accept()) in the worker 
     * thread to return immediately with an error or EOF. 
     * This ensures the thread can exit the loop and begin its cleanup 
     * routine without waiting for the next timeout interval.
     */
    if (g_server_fd >= 0) {
        shutdown(g_server_fd, SHUT_RDWR);
    }

    pthread_join(g_server_tid, NULL);
    
    g_server_fd = -1;
    log_info("Unix Server: Service stopped and thread joined.");
}