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

#define CONFIG_DEFAULT_PID_FILE             "/var/run/redgw.pid"
#define CONFIG_READ_LEN                     1024

struct redgwserver {
    /* General */
    pid_t pid;                  /* Main process pid. */
    mode_t umask;               /* The umask value of the process on startup */
    char *pidfile;              /* PID file path */
    char *configfile;           /* config file path */
    char *logfile;              /* Path of log file */
    int daemonize;              /* True if running as a daemon */

    char *core_ip;              /* Core UDP server IP */
    int core_port;              /* Core UDP server port */
    char *auth_ip;              /* Auth server IP */
    int auth_port;              /* Auth server port */

    void *handle;
    udp_conn_t *udpconn;        /* udp connect fd */
    raw_sock_t *rawconn;        /* raw udp conn */
};

#endif /* __REDGW_H__ */