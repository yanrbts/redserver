/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#define _GNU_SOURCE
#include "sys.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "wbs.h"
#include "redgw.h"

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
    long page_size_bytes = sysconf(_SC_PAGESIZE);
    
    /* Convert active resident pages directly to MegaBytes (MB) */
    float rss_mb = ((float)rss_pages * (float)page_size_bytes) / 1024.0f / 1024.0f;
    
    return rss_mb;
}