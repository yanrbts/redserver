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
#include <limits.h>

#include "util.h"
#include "log.h"
#include "redgw.h"
#include "xdp_receiver.h"
#include "xdp_pkt_parser.h"
#include "cmd.h"
#include "cmdengine.h"
#include "wbs.h"
#include "sys.h"

/* Maximum path length for Linux sysctl net parameters */
#define SYSCTL_PATH_MAX 256

struct redgwserver redserver; /* Global server config */

/**
 * @brief Safely writes a configuration value to a specified sysctl kernel parameter file.
 * @details Handles system call interruptions (EINTR) and prevents file descriptor leaks 
 * via O_CLOEXEC flags. Employs defensive programming for production safety.
 * @param path The absolute hardware path under /proc/sys/
 * @param value The configuration string to write (e.g., "1", "2")
 * @return 0 on success, -1 on absolute failure.
 */
static int sysctl_write_value(const char *path, const char *value) {
    if (!path || !value) {
        return -1;
    }

    /* O_CLOEXEC is mandatory in industrial software to prevent FD leaks over exec() */
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        /* Intentionally muted log; failure might be caused by missing root privileges */
        return -1; 
    }

    char buf[16];
    /* Appending '\n' ensures the kernel standard parser flushes correctly */
    int len = snprintf(buf, sizeof(buf), "%s\n", value);
    if (len >= (int)sizeof(buf) || len < 0) {
        close(fd);
        return -1;
    }

    const char *ptr = buf;
    size_t remaining = (size_t)len;
    ssize_t written;

    /* Defensive loop to handle partial writes and EINTR (signal interruptions) */
    while (remaining > 0) {
        written = write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue; /* Interrupted by signal, retry immediately */
            }
            close(fd);
            return -1; /* Real write error occurred */
        }
        ptr += written;
        remaining -= (size_t)written;
    }

    /* close() can also be interrupted by EINTR; loop ensures complete resource release */
    while (close(fd) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Configures interface-specific ARP isolation settings to eliminate ARP Flux.
 * @note Forces arp_ignore=1 and arp_announce=2 on the target interface.
 * @param ifname Target network interface descriptor (e.g., "ens33", "ens37")
 * @return 0 on success, -1 on infrastructure failure.
 */
static int net_tune_arp_isolation(const char *ifname) {
    if (!ifname || strlen(ifname) == 0 || strlen(ifname) > 64) {
        return -1;
    }

    char path_ignore[SYSCTL_PATH_MAX];
    char path_announce[SYSCTL_PATH_MAX];

    /* Format safe network path configurations for the specific interface */
    if (snprintf(path_ignore, sizeof(path_ignore), "/proc/sys/net/ipv4/conf/%s/arp_ignore", ifname) >= (int)sizeof(path_ignore)) {
        return -1;
    }
    if (snprintf(path_announce, sizeof(path_announce), "/proc/sys/net/ipv4/conf/%s/arp_announce", ifname) >= (int)sizeof(path_announce)) {
        return -1;
    }

    /* Force inject strict filter rules into kernel memory map */
    if (sysctl_write_value(path_ignore, "1") < 0) {
        return -1;
    }
    if (sysctl_write_value(path_announce, "2") < 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief Automatically configures global and default fallback network routing parameters.
 * @details Establishes a system-wide baseline for multi-homed network setups.
 * @return 0 on success, -1 if the system denies operation.
 */
static int net_tune_arp_global(void) {
    if (sysctl_write_value("/proc/sys/net/ipv4/conf/all/arp_ignore", "1") < 0) return -1;
    if (sysctl_write_value("/proc/sys/net/ipv4/conf/all/arp_announce", "2") < 0) return -1;
    if (sysctl_write_value("/proc/sys/net/ipv4/conf/default/arp_ignore", "1") < 0) return -1;
    if (sysctl_write_value("/proc/sys/net/ipv4/conf/default/arp_announce", "2") < 0) return -1;
    return 0;
}

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

        if (!strcasecmp(first, "gwport")) {
            redserver.gw_port = atoi(second);
            if (redserver.gw_port < 0 || redserver.gw_port > 65535) {
                err = "Invalid UDP port"; goto loaderr;
            }
        } if (!strcasecmp(first, "wsport")) {
            redserver.ws_port = atoi(second);
            if (redserver.ws_port < 0 || redserver.ws_port > 65535) {
                err = "Invalid WS UDP port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "gwhost")) {
            free(redserver.gw_host);
            redserver.gw_host = zstrdup(second);
        } else if (!strcasecmp(first, "device1")) {
            free(redserver.dev1);
            redserver.dev1 = zstrdup(second);
        } else if (!strcasecmp(first, "device2")) {
            free(redserver.dev2);
            redserver.dev2 = zstrdup(second);
        } else if (!strcasecmp(first, "coreip")) {
            free(redserver.core_ip);
            redserver.core_ip = zstrdup(second);
        } else if (!strcasecmp(first, "coreport")) {
            redserver.core_port = atoi(second);
            if (redserver.core_port < 0 || redserver.core_port > 65535) {
                err = "Invalid CORE UDP port"; goto loaderr;
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
        }
    }
    fclose(fp);
    return;
loaderr:
    fprintf(stderr, "%s\n", err);
    exit(1);
}

/**
 * Initialize server configuration with default values
 */
static void init_server_config(void) {
    redserver.pid = 0;
    redserver.umask = 027;
    redserver.pidfile = NULL;
    redserver.configfile = zstrdup(CONFIG_DEFAULT_FILE);
    redserver.logfile = NULL;
    redserver.daemonize = 0; // Default to daemonize

    redserver.gw_host = zstrdup(CONFIG_DEFAULT_HOST);
    redserver.gw_port = 0;
    redserver.ws_port = 0;
    redserver.dev1 = NULL;
    redserver.dev2 = NULL;
    redserver.dev1_index = 0;
    redserver.dev2_index = 0;

    redserver.core_ip = NULL;
    redserver.core_port = 0;
    redserver.auth_ip = NULL;
    redserver.auth_port = 0;
    redserver.auth_token = 1;
    redserver.handle = NULL;
    redserver.udpconn = NULL;
    redserver.rawconn = NULL;
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
    if (redserver.handle) xdp_receiver_exit(redserver.handle);

    log_info("%s",msg);
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

    const char *iface_black  = redserver.dev1 ? redserver.dev1 : "ens37";
    const char *iface_client = redserver.dev2 ? redserver.dev2 : "ens33";

    wbs_start(redserver.gw_host, redserver.ws_port);

    log_info("Initializing kernel network stack tuning for multi-NIC environment...");
    
    // if (net_tune_arp_global() < 0 || 
    //     net_tune_arp_isolation(iface_black) < 0 || 
    //     net_tune_arp_isolation(iface_client) < 0) {
        
    //     log_warn("Tuning kernel ARP settings failed, maybe file system is read-only.");
    //     exit(1);
    // } else {
    //     log_info("Kernel ARP isolation successfully initialized: [%s] & [%s] are now isolated.", 
    //              iface_black, iface_client);
    // }

    redserver.dev1_index = (int)if_nametoindex(iface_black);
    redserver.dev2_index = (int)if_nametoindex(iface_client);
    if (redserver.dev1_index == 0 || redserver.dev2_index == 0) {
        log_error("Failed to resolve ifindex for interfaces: %s or %s", iface_black, iface_client);
        exit(1);
    }

    xdp_receiver_config_t cfg = {
        .bpf_obj_path = "./obj/xdp_kern.o",
        .ifname_A = redserver.dev1 ? redserver.dev1 : "ens37",
        .ifname_B = redserver.dev2 ? redserver.dev2 : "ens33",
        .user_ctx = &redserver,
        .verbose = true
    };
    redserver.handle = xdp_receiver_init(&cfg, xdp_handle_ringbuf);
    if (unlikely(!redserver.handle)) {
        log_error("Failed to initialize XDP unified receiver matrix.");
        exit(1);
    }
    
    redserver.udpconn = udp_init_listener(redserver.gw_port, 1);
    if (udp_bind_device(redserver.udpconn, redserver.dev1 ? redserver.dev1 : "ens37") < 0) {
        log_error("Failed to bind UDP socket to device %s", redserver.dev1 ? redserver.dev1 : "ens37");
        exit(1);
    }
    redserver.rawconn = raw_sock_open(redserver.dev2);
    redserver.cmd_tid = cmd_start_core();
    xdp_reasm_init();

    if (wbs_notify_thread(1000) != 0) {
        log_error("Failed to inject telemetry thread!\n");
    }
}

void server_cleanup() {
    /* Remove the pid file if possible and needed. */
    if (redserver.daemonize || redserver.pidfile) {
        log_info("Removing the pid file.");
        unlink(redserver.pidfile);
    }

    free(redserver.configfile);
    free(redserver.pidfile);
    free(redserver.logfile);
    free(redserver.gw_host);
    free(redserver.dev1);
    free(redserver.auth_ip);
    free(redserver.core_ip);

    xdp_receiver_stop(&redserver.handle);
    udp_close(redserver.udpconn);
    raw_sock_close(redserver.rawconn);
    wbs_stop();

    log_info("Memory cleaned up successfully");
}

static void version(void) {
    printf("redgw server v=%s\n", "1.0.1");
    exit(0);
}

static void usage(void) {
    fprintf(stderr,"Usage: ./redgw [/path/to/config.conf]\n");
    fprintf(stderr,"       ./redgw -v or --version\n");
    fprintf(stderr,"       ./redgw -h or --help\n");
    fprintf(stderr,"Examples:\n");
    fprintf(stderr,"       ./redgw (run the server with default conf)\n");
    fprintf(stderr,"       ./redgw /etc/redgw/config.conf\n");
    exit(1);
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

    if (redserver.daemonize)
        daemonize();

    if (redserver.daemonize || redserver.pidfile)
        createPidFile();

    init_server();

    int ret = xdp_receiver_start(redserver.handle);
    if (ret < 0) {
        log_error("Receiver loop exited with error: %d\n", ret);
    }

    server_cleanup();

    log_info("redlrm service shutdown");

    return 0;
}