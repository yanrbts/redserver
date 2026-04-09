/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#define _BSD_SOURCE

#if defined(__linux__)
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <getopt.h>
#include <locale.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <ctype.h>
#include <signal.h>

#include "util.h"
#include "log.h"
#include "crc32.h"
#include "hdr.h"
#include "redlrm.h"
#include "gap.h"
#include "xdp_pkt_parser.h"
#include "xdp_receiver.h"
#include "pkteng.h"
#include "af_unix.h"
#include "gcprobe.h"
#include "cmd.h"
#include "cmdengine.h"

/* Global atomic flag */
volatile sig_atomic_t server_running = 1;
struct server redserver; /* Global server config */

static char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = malloc(l);

    memcpy(p,s,l);
    return p;
}

static int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

static void show_banner(void) {
    printf("\n");
    printf("\033[1;31m"); // 设置为红色
    printf("################################################################\n");
    printf("##                                                            ##\n");
    printf("##     ____           __    __     ____  __  ___              ##\n");
    printf("##    / __ \\___  ____/ /   / /    / __ \\/  |/  /              ##\n");
    printf("##   / /_/ / _ \\/ __  /   / /    / /_/ / /|_/ /               ##\n");
    printf("##  / _, _/  __/ /_/ /   / /___ / _, _/ /  / /                ##\n");
    printf("## /_/ |_|\\___/\\__,_/   /_____//_/ |_/_/  /_/                 ##\n");
    printf("##                                                            ##\n");
    printf("##  Version: %-6s    Status: [ RUNNING ]    Author: yanrb   ##\n", VERSION);
    printf("################################################################\n");
    printf("\033[0m"); // 恢复颜色

    printf("\n\033[1;33m[ Server Configuration ]\033[0m\n");
    printf("----------------------------------------------------------------\n");
    printf("  \033[1;33m> Service Port (sport)\033[0m      : \033[1;32m%d\033[0m\n", redserver.sport);
    printf("  \033[1;33m> Source HB Port (s_hb)\033[0m     : \033[1;32m%d\033[0m\n", redserver.s_hb_port);
    printf("  \033[1;33m> Auth IP (auth_ip)\033[0m         : \033[1;32m%s\033[0m\n", redserver.auth_ip);
    printf("  \033[1;33m> Auth Port (auth_port)\033[0m     : \033[1;32m%d\033[0m\n", redserver.auth_port);
    printf("  \033[1;33m> Core Dest Port (coreport)\033[0m : \033[1;32m%d\033[0m\n", redserver.core_port);
    printf("  \033[1;33m> Core HB Port (core_hb)\033[0m    : \033[1;32m%d\033[0m\n", redserver.core_hb_port);
    printf("  \033[1;33m> Switch HB Port (stch_hb)\033[0m  : \033[1;32m%d\033[0m\n", redserver.stch_hb_port);
    printf("----------------------------------------------------------------\n\n");
}

/* Given the filename, return the absolute path as an SDS string, or NULL
 * if it fails for some reason. Note that "filename" may be an absolute path
 * already, this will be detected and handled correctly.
 *
 * The function does not try to normalize everything, but only the obvious
 * case of one or more "../" appearning at the start of "filename"
 * relative path. */
static char *getAbsolutePath(char *filename) {
    char *ptr = NULL;
    char absolute_path[PATH_MAX];
    struct stat st;

    if (stat(filename, &st) != 0) {
        log_error("Error resolving file information");
        return NULL;
    }

    if (!S_ISREG(st.st_mode)) {
        log_info("%s is neither a regular file nor a directory.", filename);
        return NULL;
    }

    if (realpath(filename, absolute_path) != NULL) {
        ptr = zstrdup(absolute_path);
        return ptr;
    } else {
        log_error("Error resolving absolute path");
        return NULL;
    }
}
/**
 * Initialize server configuration with default values
 */
static void init_server_config(void) {
    redserver.pid = getpid();
    redserver.umask = 0;
    redserver.pidfile = NULL;
    redserver.configfile = zstrdup(CONFIG_DEFAULT_FILE);
    redserver.logfile = zstrdup("");
    redserver.daemonize = 0;
    redserver.sport = UDP_SPORT_DEFAULT;
    // redserver.s_hb_port = CG_DEFAULT_SRC_PORT;
    redserver.cport = UDP_CPORT_DEFAULT;
    redserver.localip = 0;
    memset(redserver.localmac, 0, sizeof(redserver.localmac));

    redserver.thripswith = 0;
    redserver.thrudpserver = 0;
    redserver.thr_auth_monitor = 0;
    redserver.thrauth = 0;
    redserver.at = NULL;
    redserver.auth_monitor = NULL;
    redserver.auth_refresh_time = AUTH_MIN_REFRESH_TIME;
    // redserver.gc_mgr = NULL;

    redserver.mip = zstrdup(DEFAULT_HOST);
    redserver.core_ip = zstrdup(DEFAULT_HOST);
    redserver.core_port = CORE_PORT_DEFAULT;
    redserver.auth_ip = zstrdup(DEFAULT_HOST);
    redserver.auth_port = SWITCH_PORT_DEFAULT;
    redserver.switch_ip = zstrdup(DEFAULT_HOST);
    redserver.switch_port = SWITCH_PORT_DEFAULT;
    redserver.core_hb_port = 0;
    redserver.stch_hb_port = 0;
    redserver.broadcast_ip = zstrdup(GC_BROADCAST_IP);

    redserver.nat = NULL;

    redserver.gc_probe = NULL;
    redserver.smge = NULL;
    redserver.aging_tid = 0;
    redserver.udpconn = NULL;
    redserver.handle = NULL;
    redserver.tm = NULL;
}

static void load_config_file(void) {
    FILE *fp;
    FILE *logfp;
    char *err = NULL;
    char tmp[256] = {0};
    char buf[CONFIG_READ_LEN+1];

    fp = fopen(redserver.configfile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error open config file");
        exit(1);
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *p = buf;
        /* Remove whitespace characters at the beginning of the line */
        while (isspace(*p))
            p++;
        /* Skip lines starting with # */
        if (*p == '#' || *p == '\0')
            continue;
        
        /* Remove newlines at the end of lines */
        p[strcspn(p, "\n")] = '\0';

        char *first = p;
        char *second = NULL;

        while (*p && !isspace(*p))
            p++;
        if (*p) {
            *p = '\0';
            second = p+1;
        }

        while (second && isspace(*second))
            second++;

        if (!first || !second) {
            fprintf(stderr, "Error: Invalid config line or missing parameter.\n");
            continue;
        }

        if (!strcasecmp(first, "mip")) {
            free(redserver.mip);
            redserver.mip = zstrdup(second);
        } else if (!strcasecmp(first, "sport")) {
            redserver.sport = atoi(second);
            if (redserver.sport < 0 || redserver.sport > 65535) {
                err = "Invalid UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "cport")) {
            redserver.cport = atoi(second);
            if (redserver.cport < 0 || redserver.cport > 65535) {
                err = "Invalid Core UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "coreip")) {
            free(redserver.core_ip);
            redserver.core_ip = zstrdup(second);
        } else if (!strcasecmp(first, "coreport")) {
            redserver.core_port = atoi(second);
            if (redserver.core_port < 0 || redserver.core_port > 65535) {
                err = "Invalid CORE UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "switchip")) {
            free(redserver.switch_ip);
            redserver.switch_ip = zstrdup(second);
        } else if (!strcasecmp(first, "switchport")) {
            redserver.switch_port = atoi(second);
            if (redserver.switch_port < 0 || redserver.switch_port > 65535) {
                err = "Invalid SWITCH UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "authip")) {
            free(redserver.auth_ip);
            redserver.auth_ip = zstrdup(second);
        } else if (!strcasecmp(first, "authport")) {
            redserver.auth_port = atoi(second);
            if (redserver.auth_port < 0 || redserver.auth_port > 65535) {
                err = "Invalid AUTH UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "logfile")) {
            memset(tmp, 0, sizeof(tmp));
            free(redserver.logfile);
            redserver.logfile = zstrdup(second);
            if (redserver.logfile[0] != '\0') {
                /* Test if we are able to open the file. The server will not
                 * be able to abort just for this problem later... */
                logfp = fopen(redserver.logfile,"a");
                if (logfp == NULL) {
                    snprintf(tmp, sizeof(tmp), "Can't open the log file: %s", strerror(errno));
                    err = tmp;
                    goto loaderr;
                }
                fclose(logfp);
            }
        } else if (!strcasecmp(first, "daemonize")) {
            if ((redserver.daemonize = yesnotoi(second)) == -1) {
                err = "argument must be 'yes' or 'no'"; goto loaderr;
            }
        } else if (!strcasecmp(first, "pidfile")) {
            free(redserver.pidfile);
            redserver.pidfile = zstrdup(second);
        } else if (!strcasecmp(first, "authrefreshtime")) {
            redserver.auth_refresh_time = atoi(second);
            if (redserver.auth_refresh_time < AUTH_MIN_REFRESH_TIME 
                || redserver.auth_refresh_time > AUTH_MAX_REFRESH_TIME) {
                err = "Invalid AUTH refresh time, between 5 to 10 minutes.";
                goto loaderr;
            }
        } else if (!strcasecmp(first, "coreheartbeatport")) {
            redserver.core_hb_port = atoi(second);
            if (redserver.core_hb_port < 0 || redserver.core_hb_port > 65535) {
                err = "Invalid CORE heartbeat UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "switchheartbeatport")) {
            redserver.stch_hb_port = atoi(second);
            if (redserver.stch_hb_port < 0 || redserver.stch_hb_port > 65535) {
                err = "Invalid SWITCH heartbeat UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "shearbeatport")) {
            redserver.s_hb_port = atoi(second);
            if (redserver.s_hb_port < 0 || redserver.s_hb_port > 65535) {
                err = "Invalid SWITCH heartbeat UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "broadcastip")) {
            free(redserver.broadcast_ip);
            redserver.broadcast_ip = zstrdup(second);
        }
    }
    fclose(fp);
    return;
loaderr:
    fprintf(stderr, "%s\n", err);
    exit(1);
}

static void daemonize(void) {
    int fd;

    if (fork() != 0) exit(0); /* parent exits */
    setsid(); /* create a new session */

    /* Every output goes to /dev/null. If redlrm is daemonized but
     * the 'logfile' is set to 'stdout' in the configuration file
     * it will not log at all. */
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

static void createPidFile(void) {
    /* If pidfile requested, but no pidfile defined, use
     * default pidfile path */
    if (!redserver.pidfile) redserver.pidfile = zstrdup(CONFIG_DEFAULT_PID_FILE);

    /* Try to write the pid file in a best-effort way. */
    FILE *fp = fopen(redserver.pidfile,"w");
    if (fp) {
        fprintf(fp,"%d\n",(int)getpid());
        fclose(fp);
    }
}

static void sigShutdownHandler(int sig) {
    char *msg;

    switch (sig) {
    case SIGINT:
        msg = "Received SIGINT scheduling shutdown...";
        break;
    case SIGTERM:
        msg = "Received SIGTERM scheduling shutdown...";
        break;
    default:
        msg = "Received shutdown signal, scheduling shutdown...";
    }

    server_running = 0;

    if (redserver.handle) xdp_receiver_exit(redserver.handle);

    log_info("%s",msg);
    /* SIGINT is often delivered via Ctrl+C in an interactive session.
     * If we receive the signal the second time, we interpret this as
     * the user really wanting to quit ASAP without waiting to persist
     * on disk. */
    // if (sig == SIGINT) {
    //     log_info("You insist... exiting now.");
    //     // exit(1); /* Exit with an error since this was not a clean shutdown. */
    // } else {
    //     log_info(msg);
    //     // exit(0);
    // }
}

static void setupSignalHandlers(void) {
    struct sigaction act;

    /* When the SA_SIGINFO flag is set in sa_flags then sa_sigaction is used.
     * Otherwise, sa_handler is used. */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    /* This is the termination signal sent by the kill(1) command by default.
     * Because it can be caught by applications, using SIGTERM gives programs
     * a chance to terminate gracefully by cleaning up before exiting */
    sigaction(SIGTERM, &act, NULL);
    /* This signal is generated by the terminal driver when we press the
     * interrupt key (often DELETE or Control-C). This signal is sent to all
     * processes in the foreground process group . This
     * signal is often used to terminate a runaway program, especially when it’s
     * generating a lot of unwanted output on the screen.*/
    sigaction(SIGINT, &act, NULL);
    return;
}

static void init_server(void) {
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();

    if (get_interface_binary_info(redserver.localmac, &redserver.localip) != 0) {
        log_error("Get Ip and mac failed!");
        exit(1);
    }

    redserver.at = auth_create((uint32_t)redserver.auth_refresh_time);
    redserver.auth_monitor = malloc(sizeof(*redserver.auth_monitor));
    memset(redserver.auth_monitor, 0, sizeof(*redserver.auth_monitor));

    redserver.nat = nat_table_create(10);

    gc_probe_port_t ports_config[] = {
        {redserver.core_hb_port, GC_MGR_BLACK},     // 模拟黑区设备端口
        {redserver.stch_hb_port, GC_MGR_SWITCH},    // 模拟交换机设备端口
    };
    size_t num_ports = sizeof(ports_config) / sizeof(ports_config[0]);

    // gc_mgr_port_t ports_config[] = {
    //     {redserver.core_hb_port, GC_MGR_BLACK},     // 模拟黑区设备端口
    //     {redserver.stch_hb_port, GC_MGR_SWITCH},    // 模拟交换机设备端口
    // };
    // size_t num_ports = sizeof(ports_config) / sizeof(ports_config[0]);
    // redserver.gc_mgr = gc_mgr_create(redserver.s_hb_port, ports_config, num_ports);
    // gc_mgr_set_new_target_cb(redserver.gc_mgr, on_new_target);
    // gc_mgr_set_child_state_cb(redserver.gc_mgr, on_child_state_change);

    redserver.gc_probe = gc_probe_proc_create(ports_config, num_ports, redserver.broadcast_ip);
    redserver.smge = session_mgr_create(5000);

    xdp_receiver_config_t cfg = {
        .bpf_obj_path = "./bin/xdp_kern.o",
        .ifname = "ens33",
        .user_ctx = redserver.gc_probe,   /* We could pass app-specific state here */
        .verbose = true
    };
    redserver.handle = xdp_receiver_init(&cfg, xdp_handle_ringbuf);
    redserver.udpconn = udp_init_listener(redserver.sport, 1);
    redserver.rawudpconn = raw_sock_open("ens33");

    pkt_set_object(
        redserver.smge, 
        redserver.at, 
        redserver.gc_probe, 
        redserver.udpconn, 
        redserver.rawudpconn,
        redserver.core_port,
        redserver.localip,
        redserver.localmac
    );

    xdp_reasm_init();
    gap_assemble_init();

    redserver.tm = tm_create(4);
    tm_add(redserver.tm, 1000, 5000, gap_assemble_cleanup, NULL);

    redserver.cmd_tid = cmd_start_core();
}

static void version(void) {
    printf("redlrm server v=%s\n", VERSION);
    exit(0);
}

static void usage(void) {
    fprintf(stderr,"Usage: ./redlrm [/path/to/config.conf]\n");
    fprintf(stderr,"       ./redlrm -v or --version\n");
    fprintf(stderr,"       ./redlrm -h or --help\n");
    fprintf(stderr,"Examples:\n");
    fprintf(stderr,"       ./redlrm (run the server with default conf)\n");
    fprintf(stderr,"       ./redlrm /etc/redlrm/config.conf\n");
    exit(1);
}

static int start_auth_hearbeat_service() {
    /* 1. Allocate and initialize context */
    if (!redserver.auth_monitor)
        redserver.auth_monitor = malloc(sizeof(*redserver.auth_monitor));

    auth_monitor_t *ctx = redserver.auth_monitor;
    memset(ctx, 0, sizeof(auth_monitor_t));
    
    ctx->server_ip = redserver.auth_ip;
    ctx->server_port = (uint16_t)redserver.auth_port;
    ctx->is_alive = false;
    ctx->running = true;
    pthread_mutex_init(&ctx->lock, NULL);

    ctx->conn = udp_init_listener(0, 1);
    if (!ctx->conn) {
        log_error("Failed to init UDP for heartbeat");
        goto err;
    }

    if (pthread_create(&redserver.thr_auth_monitor, NULL, auth_heartbeat_thread, ctx) != 0) {
        log_error("Failed to create heartbeat thread");
        goto err;
    }

    return 0;

err:
    if (ctx->conn) udp_close(ctx->conn);
    free(redserver.auth_monitor);
    redserver.auth_monitor = NULL;
    return -1;
}

static int start_auth_refresh_service(void) {
    auth_refresh_t af = {
        .at = redserver.at,
        .auth_host = redserver.auth_ip,
        .auth_port = redserver.auth_port
    };

    if (pthread_create(&redserver.thrauth, NULL, auth_refresh_thread, &af) != 0) {
        log_error("Failed to create auth thread");
        return -1;
    }
    return 0;
}

static int start_aging_service(void) {
    if (pthread_create(&redserver.aging_tid, NULL, aging_thread_fn, redserver.smge) != 0) {
        log_error("Failed to create aging thread");
        return -1;
    }
    return 0;
}

void stop_auth_heartbeat_service() {
    if (!redserver.auth_monitor) return;

    log_info("Stopping heartbeat service...");
    
    redserver.auth_monitor->running = false;

    if (redserver.thr_auth_monitor != 0) {
        pthread_join(redserver.thr_auth_monitor, NULL);
        redserver.thr_auth_monitor = 0;
    }

    pthread_mutex_lock(&redserver.auth_monitor->lock);
    if (redserver.auth_monitor->conn) {
        udp_close(redserver.auth_monitor->conn);
        redserver.auth_monitor->conn = NULL;
    }
    pthread_mutex_unlock(&redserver.auth_monitor->lock);
    pthread_mutex_destroy(&redserver.auth_monitor->lock);

    free(redserver.auth_monitor);
    redserver.auth_monitor = NULL; 

    log_info("Heartbeat service cleaned up successfully.");
}

void stop_aging_service() {
    if (redserver.aging_tid != 0) {
        // pthread_cancel(redserver.aging_tid);
        pthread_join(redserver.aging_tid, NULL);
        redserver.aging_tid = 0;
        log_info("Aging service stopped successfully.");
    }
}

void server_cleanup() {
    stop_auth_heartbeat_service();
    stop_aging_service();

    /* Remove the pid file if possible and needed. */
    if (redserver.daemonize || redserver.pidfile) {
        log_info("Removing the pid file.");
        unlink(redserver.pidfile);
    }
    
    auth_free(redserver.at);

    // gc_mgr_stop(redserver.gc_mgr);
    // gc_mgr_destroy(redserver.gc_mgr);

    nat_table_destroy(redserver.nat);

    free(redserver.configfile);
    free(redserver.pidfile);
    free(redserver.logfile);
    free(redserver.mip);
    free(redserver.auth_ip);
    free(redserver.core_ip);
    free(redserver.switch_ip);
    free(redserver.broadcast_ip);

    xdp_receiver_stop(&redserver.handle);
    gc_probe_proc_destroy(redserver.gc_probe);
    session_mgr_destroy(redserver.smge);
    udp_close(redserver.udpconn);
    raw_sock_close(redserver.rawudpconn);
    lrm_unix_server_stop();

    tm_destroy(redserver.tm);
    gap_assemble_destroy();
    xdp_reasm_show_stats();
    cmd_server_stop(&redserver.cmd_tid);
    
    log_info("Memory cleaned up successfully");
}

int main(int argc, char *argv[]) {
    int j;
    /* The setlocale() function is used to set or query the program's current locale.
     * 
     * The function is used to set the current locale of the program and the 
     * collation of the specified locale. Specifically, the LC_COLLATE parameter
     * represents the collation of the region. By setting it to an empty string,
     * the default locale collation is used.*/
    setlocale(LC_COLLATE, "");

    /* The  tzset()  function initializes the tzname variable from the TZ environment variable.  
     * This function is automati‐cally called by the other time conversion functions 
     * that depend on the timezone.*/
    tzset();

    init_server_config();

    if (argc >= 2) {
        j = 1;
        char *configfile = NULL;
        char *tp = NULL;
        /* Handle special options --help and --version */
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "--help") == 0 ||
            strcmp(argv[1], "-h") == 0) usage();
        
        /* First argument is the config file name? */
        if (argv[j][0] != '-' || argv[j][1] != '-') {
            configfile = argv[j];
            if ((tp = getAbsolutePath(configfile)) != NULL) {
                free(redserver.configfile);
                redserver.configfile = tp;
            } else {
                log_info("Warning: no config file specified, using the default config.");
            }
        }
    }

    load_config_file();

    // log_info("Proxy starting...");
    log_info("Switch side: %s:%d", redserver.switch_ip, redserver.switch_port);
    log_info("Core side: %s:%d", redserver.core_ip, redserver.core_port);
    log_info("Auth side: %s:%d", redserver.auth_ip, redserver.auth_port);

    
    if (redserver.daemonize)
        daemonize();

    if (redserver.daemonize || redserver.pidfile)
        createPidFile();

    init_server();

    show_banner();

    // struct proxyinfo a_arg = {
    //     .host = redserver.mip, 
    //     .port = redserver.sport, 
    //     .auth_host = redserver.auth_ip, 
    //     .auth_port = redserver.auth_port, 
    //     .dstport = redserver.core_port, 
    //     .dstip = redserver.core_ip
    // };

    // if (pthread_create(&redserver.thrudpserver, NULL, proxy_listen_core, &a_arg) != 0) {
    //     log_error("Failed to create C side thread");
    //     return 1;
    // }

    start_auth_refresh_service();

    start_auth_hearbeat_service();

    // gc_mgr_start(redserver.gc_mgr);
    start_aging_service();

    lrm_unix_server_start(200);

    tm_run(redserver.tm, 100);

    int ret = xdp_receiver_start(redserver.handle);
    if (ret < 0) {
        log_error("Receiver loop exited with error: %d\n", ret);
    }

    // pthread_join(redserver.thrudpserver, NULL);

    server_cleanup();

    log_info("redlrm service shutdown");

    return 0;
}