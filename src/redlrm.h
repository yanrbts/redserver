#ifndef __REDLRM_H__
#define __REDLRM_H__

#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>

#include "proxy.h"
#include "udp.h"
#include "auth.h"
#include "nat.h"
#include "tmmgr.h"
#include "gcprobe.h"
#include "session_manager.h"

#define PROGRAM_NAME                        "redlrm"
#define VERSION                             "1.3.0"
#define DEFAULT_HOST                        "127.0.0.1"
#define UDP_CPORT_DEFAULT                   8898
#define UDP_SPORT_DEFAULT                   8899
#define CORE_PORT_DEFAULT                   5000
#define SWITCH_PORT_DEFAULT                 6000
#define CONFIG_DEFAULT_FILE                 "./config.conf"
#define CONFIG_DEFAULT_PID_FILE             "/var/run/redlrm.pid"
#define CONFIG_READ_LEN                     1024

// Error codes
enum ErrorCode {
    ERR_SUCCESS         = 0,
    ERR_SOCKET_CREATE   = -1,
    ERR_INVALID_ADDR    = -2,
    ERR_SEND_FAILED     = -3,
    ERR_RECV_FAILED     = -4,
    ERR_BAD_RESPONSE    = -5,
    ERR_CRC_FAIL        = -6,
    ERR_LENGTH_MISMATCH = -7,
    ERR_TYPE_MISMATCH   = -8,
    ERR_MEMORY          = -9
};

struct server {
    /* General */
    pid_t pid;                  /* Main process pid. */
    mode_t umask;               /* The umask value of the process on startup */
    char *pidfile;              /* PID file path */
    char *configfile;           /* config file path */
    char *logfile;              /* Path of log file */
    int daemonize;              /* True if running as a daemon */
    uint32_t localip;           /* Local IP address in network byte order */
    uint8_t localmac[6];        /* Local MAC address in binary */

    /* Networking */
    int sport;                  /* IP UDP listening port */
    int s_hb_port;              /* IP UDP heartbeat listening port */
    int cport;                  /* Core UDP listening port */
    pthread_t thripswith;       /* Thread for IP swith */
    pthread_t thrudpserver;     /* Thread for UDP server */
    /* auth */
    auth_t *at;                 /* auth object */
    pthread_t thrauth;          /* refresh auth thread */
    int auth_refresh_time;      /* Auth refresh time, between 5 to 10 minutes. 
                                 * Set in seconds.*/
    /* auth hear beat */
    pthread_t thr_auth_monitor;   /* Thread for AUTH hear beat  */
    auth_monitor_t *auth_monitor; /* authhearbeat context */

    char *mip;                  /* MIP address */
    char *core_ip;              /* Core UDP server IP */
    int core_port;              /* Core UDP server port */
    int core_hb_port;           /* Core heartbeat port */
    char *auth_ip;              /* Auth server IP */
    int auth_port;              /* Auth server port */
    char *switch_ip;            /* IP switch server IP */
    int switch_port;            /* IP switch server port */
    int stch_hb_port;           /* Switch heartbeat port */
    char *broadcast_ip;         /* Broadcast IP for GC discovery */

    nat_table_t *nat;           /* nat table */
    // gc_manager_t *gc_mgr;       /* 5GC manager */
    gc_probe_processor_t *gc_probe; /* */
    session_manager_t *smge;    /* session manager object */
    pthread_t aging_tid;        /* Thread for session aging */
    udp_conn_t *udpconn;        /* udp connect fd */
    raw_sock_t *rawudpconn;     /* raw udp conn */
    void *handle;

    timer_manager_t *tm;        /* time manager object */
    pthread_t cmd_tid;          /* cmd server thread id */
};

extern struct server redserver;
extern volatile sig_atomic_t server_running;

#endif