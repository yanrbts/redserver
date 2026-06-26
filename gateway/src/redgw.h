/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __REDGW_H__
#define __REDGW_H__

#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>

#include "udp.h"
#define CONFIG_DEFAULT_FILE                 "./config.conf"
#define CONFIG_DEFAULT_PID_FILE             "/var/run/redgw.pid"
#define CONFIG_READ_LEN                     1024
#define CONFIG_DEFAULT_HOST                 "0.0.0.0"

struct redgwserver {
    /* General */
    pid_t pid;                  /* Main process pid. */
    mode_t umask;               /* The umask value of the process on startup */
    char *pidfile;              /* PID file path */
    char *configfile;           /* config file path */
    char *logfile;              /* Path of log file */
    int daemonize;              /* True if running as a daemon */

    char *gw_host;              /* Gateway IP to bind */
    int gw_port;                /* Gateway UDP port to bind */
    int ws_port;                /* websocket port */
    char *dev1;                 /* Network interface to bind for raw socket */
    int dev1_index;             /* Cached ifindex for dev1 */
    char *dev2;                 /* Network interface to bind for raw socket */
    int dev2_index;             /* Cached ifindex for dev2 */
    char *core_ip;              /* Core UDP server IP */
    int core_port;              /* Core UDP server port */
    char *auth_ip;              /* Auth server IP */
    int auth_port;              /* Auth server port */
    uint32_t auth_token;        /* Authentication token for core communication */

    void *handle;
    udp_conn_t *udpconn;        /* udp connect fd */
    raw_sock_t *rawconn;        /* raw udp conn */
    pthread_t cmd_tid;          /* cmd server thread id */
};

extern struct redgwserver redserver;

#endif /* __REDGW_H__ */