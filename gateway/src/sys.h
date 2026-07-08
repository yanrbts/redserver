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

#define SYS_CHUNK_SIZE  2048
/**
 * @brief Function pointer definition for streaming command chunked outputs back.
 */
typedef void (*sys_stream_cb)(void *ctx, const char *data, size_t len);

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
void sys_run_cmd(const char *raw_cmd, void *ctx, sys_stream_cb cb);
int sys_is_xdp_loaded(const char *ifname);
int sys_set_interface_ip(const char *ifname, const char *new_ip_str, unsigned char netmask);
int set_interface_primary_ip(const char *ifname, const char *new_ip, unsigned char netmask_prefix);

#endif /* SYS_MON_H */