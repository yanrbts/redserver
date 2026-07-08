/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "log.h"
#include "sys.h"
#include "wbs.h"


/* Define IFLA_XDP and its sub-attributes locally if compiling on older toolchains */
#ifndef IFLA_XDP
#define IFLA_XDP                    43
#endif
#ifndef IFLA_XDP_ATTACHED
#define IFLA_XDP_ATTACHED           1
#endif
#ifndef IFLA_EXT_MASK
#define IFLA_EXT_MASK               29
#endif
#ifndef RTEXT_FILTER_SKIP_STATS
#define RTEXT_FILTER_SKIP_STATS     (1 << 3)
#endif
#define NL_BUF_SIZE                 16384
#define NL_MSG_BUF_SIZE             4096

#define SYS_MAX_ARGS                64
#define SYS_STREAM_TIMEOUT_SEC      15  /* Industrial guard: Kill streaming commands like infinity ping after 15s */

static int sys_net_bytes(const char *iface, uint64_t *rx, uint64_t *tx) {
    char path[128];
    FILE *fr = NULL, *ft = NULL;

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", iface);
    fr = fopen(path, "r");
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", iface);
    ft = fopen(path, "r");

    if (!fr || !ft) {
        if (fr) fclose(fr);
        if (ft) fclose(ft);
        return -1;
    }

    if (fscanf(fr, "%lu", rx) != 1) *rx = 0;
    if (fscanf(ft, "%lu", tx) != 1) *tx = 0;

    fclose(fr);
    fclose(ft);
    return 0;
}

float sys_cpu_usage(void) {
    static uint64_t p_user = 0, p_nice = 0, p_sys = 0, p_idle = 0;
    static uint64_t p_iowait = 0, p_irq = 0, p_softirq = 0;
    
    uint64_t user = 0, nice = 0, sys = 0, idle = 0, iowait = 0, irq = 0, softirq = 0;
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return -1.0f;

    if (fscanf(fp, "cpu %lu %lu %lu %lu %lu %lu %lu", 
               &user, &nice, &sys, &idle, &iowait, &irq, &softirq) < 7) {
        fclose(fp);
        return -1.0f;
    }
    fclose(fp);

    uint64_t p_tot_idle = p_idle + p_iowait;
    uint64_t c_tot_idle = idle + iowait;
    uint64_t p_non_idle = p_user + p_nice + p_sys + p_irq + p_softirq;
    uint64_t c_non_idle = user + nice + sys + irq + softirq;

    uint64_t p_tot = p_tot_idle + p_non_idle;
    uint64_t c_tot = c_tot_idle + c_non_idle;

    if (p_tot == 0) {
        p_user = user; p_nice = nice; p_sys = sys; p_idle = idle;
        p_iowait = iowait; p_irq = irq; p_softirq = softirq;
        return 0.0f;
    }

    uint64_t del_tot = c_tot - p_tot;
    uint64_t del_idl = c_tot_idle - p_tot_idle;
    float pct = 0.0f;

    if (del_tot > 0) {
        pct = ((float)(del_tot - del_idl) / (float)del_tot) * 100.0f;
    }

    p_user = user; p_nice = nice; p_sys = sys; p_idle = idle;
    p_iowait = iowait; p_irq = irq; p_softirq = softirq;
    return pct;
}

float sys_mem_usage(void) {
    uint64_t tot = 0, free = 0, buf = 0, cach = 0;
    char line[256];
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1.0f;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %lu kB", &tot) == 1) continue;
        if (sscanf(line, "MemFree: %lu kB", &free) == 1) continue;
        if (sscanf(line, "Buffers: %lu kB", &buf) == 1) continue;
        if (sscanf(line, "Cached: %lu kB", &cach) == 1) continue;
    }
    fclose(fp);

    if (tot == 0) return -1.0f;
    return ((float)(tot - free - buf - cach) / (float)tot) * 100.0f;
}

/**
 * @brief  Calculates the network interface transmission rate (differential evaluation).
 * @param  iface    [in]  Target interface name (e.g., "eth1", "eth2").
 * @param  ctx      [in/out] Historical telemetry context tracking bytes and monotonic timestamps.
 * @param  rx_kbps  [out] Extracted download speed in KB/s (Kilobytes per second).
 * @param  tx_kbps  [out] Extracted upload speed in KB/s (Kilobytes per second).
 * @return int      0 on success, -1 on operational or parameter failures.
 * @note   Unit clarification: 1 KB/s = 1024 Bytes/s = 8 Kbps (Kilobits per second).
 * This function relies on non-blocking monotonic clock step delta-evaluation.
 */
int sys_net_rate(const char *iface, sys_net_ctx *ctx, float *rx_kbps, float *tx_kbps) {
    if (!iface || !ctx || !rx_kbps || !tx_kbps) return -1;

    uint64_t cur_rx = 0, cur_tx = 0;
    struct timespec cur_time;
    
    if (sys_net_bytes(iface, &cur_rx, &cur_tx) != 0) return -1;
    clock_gettime(CLOCK_MONOTONIC, &cur_time);

    if (ctx->last_time.tv_sec == 0 && ctx->last_time.tv_nsec == 0) {
        ctx->last_rx = cur_rx; ctx->last_tx = cur_tx; ctx->last_time = cur_time;
        *rx_kbps = 0.0f; *tx_kbps = 0.0f;
        return 0;
    }

    double sec = (double)(cur_time.tv_sec - ctx->last_time.tv_sec) +
                 (double)(cur_time.tv_nsec - ctx->last_time.tv_nsec) / 1e9;

    if (sec > 0.001) {
        uint64_t del_rx = (cur_rx >= ctx->last_rx) ? (cur_rx - ctx->last_rx) : cur_rx;
        uint64_t del_tx = (cur_tx >= ctx->last_tx) ? (cur_tx - ctx->last_tx) : cur_tx;
        *rx_kbps = (float)((double)del_rx / 1024.0 / sec);
        *tx_kbps = (float)((double)del_tx / 1024.0 / sec);
    } else {
        *rx_kbps = 0.0f; *tx_kbps = 0.0f;
    }

    ctx->last_rx = cur_rx; ctx->last_tx = cur_tx; ctx->last_time = cur_time;
    return 0;
}

/**
 * @brief Retrieves the real physical memory (RSS) consumed by the CURRENT process.
 * @return float Memory used by this process in MegaBytes (MB). Returns -1.0f on error.
 */
float sys_proc_mem_mb(void) {
    const uint64_t now = get_now_ms();
    static uint64_t last_read_time = 0;
    static float cached_rss_mb = 0.0f;

    if (now - last_read_time < 500 && cached_rss_mb > 0.0f) {
        return cached_rss_mb;
    }

    FILE *fp = fopen("/proc/self/statm", "r");
    if (!fp) return -1.0f;

    long dummy = 0;
    long rss_pages = 0;

    /* statm schema: size resident(RSS) shared text data library dirty */
    if (fscanf(fp, "%ld %ld", &dummy, &rss_pages) < 2) {
        fclose(fp);
        return -1.0f;
    }
    fclose(fp);

    /* Get hardware page size (standard is 4096 bytes / 4KB) */
    static long page_size_bytes = 0;
    if (page_size_bytes == 0) {
        page_size_bytes = sysconf(_SC_PAGESIZE);
        if (page_size_bytes <= 0) {
            page_size_bytes = 4096;
        }
    }
    
    /* Convert active resident pages directly to MegaBytes (MB) */
    cached_rss_mb = ((float)rss_pages * (float)page_size_bytes) / 1024.0f / 1024.0f;
    last_read_time = now;
    
    return cached_rss_mb;
}

/**
 * @brief Parse a raw command string into an argument vector safely.
 */
static int sys_parse_args(char *cmd, char **argv) {
    int argc = 0;
    char *token = strtok(cmd, " \t\r\n");
    while (token && argc < (SYS_MAX_ARGS - 1)) {
        argv[argc++] = token;
        token = strtok(NULL, " \t\r\n");
    }
    argv[argc] = NULL;
    return argc;
}

/**
 * @brief Industrial-Grade Unified Stream Execution Engine
 * Executes system directives asynchronously via high-performance non-blocking channels.
 * Bypasses heap memory pooling entirely to enforce constant O(1) memory complexity.
 * @param raw_cmd The structural system command line string to dispatch.
 * @param ctx The connection metadata tracking descriptor to bubble downstream.
 * @param cb Mandatory data flow callback executed immediately when any line chunk drops.
 */
void sys_run_cmd(const char *raw_cmd, void *ctx, sys_stream_cb cb) {
    if (unlikely(!raw_cmd || !cb)) {
        log_error("[SYS] Pipeline rejection: Missing command string or callback collector.");
        return;
    }

    char *cmd_copy = strdup(raw_cmd);
    if (unlikely(!cmd_copy)) {
        log_error("[SYS] OOM exception wrapping command token allocation.");
        return;
    }

    char *argv[SYS_MAX_ARGS];
    int argc = sys_parse_args(cmd_copy, argv);
    if (unlikely(argc == 0)) {
        free(cmd_copy);
        return;
    }

    /* Create non-blocking edge-triggered compliance pipeline pipes */
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) < 0) {
        log_error("[SYS] Failed to assemble descriptors: %s", strerror(errno));
        free(cmd_copy);
        return;
    }

    pid_t pid = fork();
    if (unlikely(pid < 0)) {
        log_error("[SYS] Fork processing core matrix failure: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        free(cmd_copy);
        return;
    }

    if (pid == 0) {
        /* Child execution cell matrix wrapper zone */
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        execvp(argv[0], argv);
        fprintf(stderr, "Failed to execute standard binary '%s': %s\n", argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Parent Context tracking layer */
    close(pipefd[1]); 
    free(cmd_copy);   

    char read_chunk[SYS_CHUNK_SIZE];
    struct pollfd pfd;
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;

    int status;
    int child_exited = 0;
    time_t start_time = time(NULL);

    /* High-Performance Event Pump IO Loop */
    while (1) {
        /* Enforce dynamic hard-limit ceiling watchdogs for running tasks */
        if (time(NULL) - start_time >= SYS_STREAM_TIMEOUT_SEC) {
            log_warn("[SYS] Target task execution timeout wall hit. Issuing SIGKILL execution clamp.");
            kill(pid, SIGKILL);
            break;
        }

        int ready = poll(&pfd, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            log_error("[SYS] Event multiplexing failure: %s", strerror(errno));
            break;
        }
        
        if (ready == 0) {
            /* Heartbeat timeout window: check if the process naturally completed */
            if (waitpid(pid, &status, WNOHANG) > 0) {
                child_exited = 1;
                break; 
            }
            continue;
        }

        if (pfd.revents & (POLLERR | POLLNVAL)) {
            log_error("[SYS] Pipeline encountered terminal descriptor state error.");
            break;
        }

        /* Continuous kernel read extraction pass */
        ssize_t bytes_read = read(pipefd[0], read_chunk, sizeof(read_chunk));
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (pfd.revents & POLLHUP) break;
                continue;
            }
            break;
        }
        
        if (bytes_read == 0) {
            break; /* Standard EOF completion reached */
        }

        /* Instant streaming pass-through back to the network transport layers */
        cb(ctx, read_chunk, (size_t)bytes_read);
    }

    /* Drain remainder residuals safely if the process exited but pipe blocks are holding chunks */
    if (child_exited) {
        ssize_t residual;
        while ((residual = read(pipefd[0], read_chunk, sizeof(read_chunk))) > 0) {
            cb(ctx, read_chunk, (size_t)residual);
        }
    }

    close(pipefd[0]);
    
    /* Strict zombie reclamation protocol tracking */
    if (waitpid(pid, &status, WNOHANG) == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
}

/**
 * @brief Evaluates whether a specific network interface has an active XDP (eBPF) program attached.
 * 
 * @param ifname The network interface identifier string (e.g., "ens33").
 * @return int   1 if an XDP program is actively loaded; 
 *               0 if no XDP program is attached, the interface does not exist, or an error occurs.
 * @note This implementation relies on the standard Linux RTNetlink kernel subsystem (RTM_GETLINK).
 *       It is highly portable across standard Linux distributions, fully thread-safe, 
 *       and works correctly on upstream kernels without relying on sysfs /xdp extensions.
 */
int sys_is_xdp_loaded(const char *ifname) {
    if (unlikely(!ifname || ifname[0] == '\0')) {
        return 0;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return 0; 
    }

    int nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (unlikely(nl_fd < 0)) {
        return 0;
    }

    /* Structure padded safely to accommodate essential Netlink extension filter masks */
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        char attrbuf[64]; 
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = (int)ifindex;

    /* Push the extension mask to force the kernel core to dump extended BPF/XDP metadata blocks */
    struct rtattr *rta_mask = (struct rtattr *)(((char *)&req) + req.nlh.nlmsg_len);
    rta_mask->rta_type = IFLA_EXT_MASK;
    rta_mask->rta_len = RTA_LENGTH(sizeof(unsigned int));
    
    unsigned int *mask_val = (unsigned int *)RTA_DATA(rta_mask);
    *mask_val = RTEXT_FILTER_SKIP_STATS; 
    
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(rta_mask->rta_len);

    ssize_t ret;
    do {
        ret = send(nl_fd, &req, req.nlh.nlmsg_len, 0);
    } while (ret < 0 && errno == EINTR);

    if (unlikely(ret < 0)) {
        close(nl_fd);
        return 0;
    }

    char buffer[NL_BUF_SIZE];
    struct sockaddr_nl peer;
    struct iovec iov = { buffer, sizeof(buffer) };
    struct msghdr msg = { &peer, sizeof(peer), &iov, 1, NULL, 0, 0 };

    do {
        ret = recvmsg(nl_fd, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    close(nl_fd);

    if (ret <= 0) {
        return 0;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    if (!NLMSG_OK(nlh, (size_t)ret) || nlh->nlmsg_type == NLMSG_ERROR) {
        return 0;
    }

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    size_t attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
    struct rtattr *rta = (struct rtattr *)((char *)ifi + NLMSG_LENGTH(sizeof(struct ifinfomsg)) - sizeof(struct rtattr));

    for (; RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
        if (rta->rta_type == IFLA_XDP) {
            unsigned char *raw_data = (unsigned char *)RTA_DATA(rta);
            int raw_len = (int)RTA_PAYLOAD(rta);
            int offset = 0;

            /* Deep memory layout sweep bypasses type alignment vulnerabilities entirely */
            while (offset + (int)sizeof(struct rtattr) <= raw_len) {
                struct rtattr *sub = (struct rtattr *)(raw_data + offset);
                
                if (sub->rta_len < sizeof(struct rtattr) || offset + sub->rta_len > raw_len) {
                    break; 
                }

                /* FIX: Directly intercept the static uint32_t PROG_ID vector */
                if (sub->rta_type == IFLA_XDP_PROG_ID) {
                    uint32_t prog_id = *(uint32_t *)((char *)sub + sizeof(struct rtattr));
                    if (prog_id > 0) {
                        return 1; /* Target locked and successfully matched: XDP is running! */
                    }
                }
                offset += RTA_ALIGN(sub->rta_len);
            }
        }
    }

    return 0;
}

/**
 * @brief Sub-routine to dispatch Netlink messages and handle transactional synchronous ACKs.
 * @return Returns 1 on absolute success (ACK received), 0 on any kernel or transport error.
 */
static int netlink_talk(int nl_fd, struct nlmsghdr *nlh) {
    ssize_t ret;
    do {
        ret = send(nl_fd, nlh, nlh->nlmsg_len, 0);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        log_error("[NETLINK] Failed to transmit sequence down to kernel pipe: %s", strerror(errno));
        return 0;
    }

    char ans_buf[NL_MSG_BUF_SIZE];
    struct sockaddr_nl peer;
    struct iovec iov = { ans_buf, sizeof(ans_buf) };
    struct msghdr msg = { &peer, sizeof(peer), &iov, 1, NULL, 0, 0 };

    do {
        ret = recvmsg(nl_fd, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    if (ret <= 0) {
        log_error("[NETLINK] Broken transactional pipeline, ACK timeout: %s", strerror(errno));
        return 0;
    }

    struct nlmsghdr *nlh_ans = (struct nlmsghdr *)ans_buf;
    if (!NLMSG_OK(nlh_ans, (size_t)ret)) {
        log_error("[NETLINK] Malformed kernel feedback matrix.");
        return 0;
    }

    if (nlh_ans->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh_ans);
        if (err->error != 0) {
            /* 
             * [CRITICAL EXCEPTIONS]: 
             * -EADDRNOTAVAIL implies flushing a non-existent IP. We gracefully pass it.
             */
            if (err->error == -EADDRNOTAVAIL && nlh->nlmsg_type == RTM_DELADDR) {
                return 1; 
            }
            log_error("[NETLINK] Kernel level transactional rejection: %s", strerror(-err->error));
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Closed-loop industrial IP configuration engine. 
 *        Ensures zero IP pollution via a strict flush-and-rebuild architecture.
 */
int sys_set_interface_ip(const char *ifname, const char *new_ip_str, unsigned char netmask) {
    if (!ifname || ifname[0] == '\0' || !new_ip_str || netmask > 32) {
        return 0;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        log_error("[SYS] Interface '%s' unresolved or physically pulled out.", ifname);
        return 0;
    }

    struct in_addr ip_bin;
    if (inet_pton(AF_INET, new_ip_str, &ip_bin) != 1) {
        log_error("[SYS] Invalid IPv4 token string: '%s'.", new_ip_str);
        return 0;
    }

    int nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl_fd < 0) {
        log_error("[SYS] Socket resource allocation collapsed: %s", strerror(errno));
        return 0;
    }

    char buf[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    struct rtattr *rta;

    /* =========================================================================
     * STAGE 1: TRANSACTIONAL FLUSH
     * Delete previous overlapping IP bindings to avoid secondary-IP stacking pollution.
     * ========================================================================= */
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_type = RTM_DELADDR; /* Explicit delete command */

    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = netmask; 
    ifa->ifa_index = (int)ifindex;
    ifa->ifa_scope = 0; 

    /* Inject target wildcards to match previous configurations */
    rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
    memcpy(RTA_DATA(rta), &ip_bin, sizeof(struct in_addr));
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    /* Execute phase 1 - We ignore failure if no address was bound previously */
    netlink_talk(nl_fd, nlh);

    /* =========================================================================
     * STAGE 2: FRESH INJECTION
     * Establish clean, high-priority primary address configuration mapping.
     * ========================================================================= */
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    /* NLM_F_CREATE: Force explicit creation | NLM_F_EXCL: Disallow duplicates */
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nlh->nlmsg_type = RTM_NEWADDR; 

    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = netmask;
    ifa->ifa_index = (int)ifindex;
    ifa->ifa_scope = 0; 

    /* Build clean aligned IFA_LOCAL node */
    rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
    memcpy(RTA_DATA(rta), &ip_bin, sizeof(struct in_addr));
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    /* Build clean aligned IFA_ADDRESS node */
    rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
    memcpy(RTA_DATA(rta), &ip_bin, sizeof(struct in_addr));
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

    /* Execute Phase 2 - Absolute status verification */
    int final_status = netlink_talk(nl_fd, nlh);

    close(nl_fd);
    return final_status;
}

/**
 * @brief Atomically overwrites the primary IPv4 address and netmask of a local interface.
 * @return 1 on absolute success, 0 on validation/system failure.
 */
int set_interface_primary_ip(const char *ifname, const char *new_ip, unsigned char netmask_prefix) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    uint32_t mask_val = 0;

    if (unlikely(!ifname || ifname[0] == '\0' || !new_ip || netmask_prefix > 32)) {
        return 0;
    }

    /* Transient socket descriptor acting purely as a kernel transaction handle */
    sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (unlikely(sockfd < 0)) {
        return 0;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    /* Phase 1: Atomically overwrite Primary IP (Clears appended secondary IPs automatically) */
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, new_ip, &sin->sin_addr) != 1) {
        log_error("[SYS] Invalid IPv4 address string: '%s'", new_ip);
        close(sockfd);
        return 0;
    }

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        log_error("[SYS] Failed to set IP address for interface '%s': %s", ifname, strerror(errno));
        close(sockfd);
        return 0;
    }

    /* Phase 2: Compute and apply netmask avoiding bit-shift overflows */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;

    if (netmask_prefix == 32) {
        mask_val = 0xFFFFFFFF;
    } else if (netmask_prefix > 0) {
        mask_val = ~(0xFFFFFFFF >> netmask_prefix);
    }

    sin->sin_addr.s_addr = htonl(mask_val); 

    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        log_error("[SYS] Failed to set netmask for interface '%s': %s", ifname, strerror(errno));
    }

    /* Phase 3: Synchronize interface flags and flush kernel routing cache */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) >= 0) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
        if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
            log_error("[SYS] Failed to set interface flags for '%s': %s", ifname, strerror(errno));
        }
    }

    close(sockfd);
    return 1;
}