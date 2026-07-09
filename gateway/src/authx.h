/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "udp.h"

#define AUTH_MIN_REFRESH_TIME 300
#define AUTH_MAX_REFRESH_TIME 600

typedef struct auth_ctx_s {
    char *auth_ip;
    int auth_port;

    uint32_t auth_interval;     /* Interval for Auth refresh (seconds) */
    uint32_t auth_value;        /* Current Auth value */
    time_t last_auth_update;    /* Last Auth update time */

    udp_conn_t *conn;
    pthread_t auth_tid;
    atomic_bool is_alive;
    atomic_bool running; 
    atomic_int fail_count;
    pthread_mutex_t state_lock; 
} auth_ctx_t;

uint32_t auth_get_value(void);
int auth_monitor_start(auth_ctx_t *ctx);
void auth_monitor_stop(auth_ctx_t *ctx);

#endif