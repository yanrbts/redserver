#ifndef __PROXY_H__
#define __PROXY_H__

#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include "auth.h"
#include "udp.h"

struct proxyinfo {
    const char *host;       // IP address
    int port;               // Port number
    const char *auth_host;  // Auth server IP address
    int auth_port;          // Auth server port number
    int dstport;            // Destination port
    const char *dstip;      // Destination IP address
};

/* Global or shared authentication context */
typedef struct {
    udp_conn_t *conn;           /* Persistent UDP handle */
    const char *server_ip;      /* Auth server IP */
    uint16_t server_port;       /* Auth server Port */
    volatile bool is_alive;     /* Thread-safe liveness flag */
    volatile bool running;
    int fail_count;             /* Continuous failure counter */
    pthread_mutex_t lock;       /* Protects state changes */
} auth_monitor_t;

typedef struct {
    auth_t *at;
    const char *auth_host;  // Auth server IP address
    int auth_port;          // Auth server port number
} auth_refresh_t;

void *proxy_listen_core(void *arg);
void *auth_heartbeat_thread(void *arg);
void *auth_refresh_thread(void *arg);
void *aging_thread_fn(void *arg);

#endif