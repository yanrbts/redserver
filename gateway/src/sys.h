/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef __SYS_H__
#define __SYS_H__

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/**
 * @struct sys_net_ctx
 * @brief Context tracker for network delta rate evaluation.
 */
typedef struct {
    uint64_t last_rx;
    uint64_t last_tx;
    struct timespec last_time;
} sys_net_ctx;

/* Core extraction APIs */
float sys_cpu_usage(void);
float sys_mem_usage(void);
float sys_proc_mem_mb(void);
int sys_net_rate(const char *iface, sys_net_ctx *ctx, float *rx_kbps, float *tx_kbps);

#endif /* SYS_MON_H */