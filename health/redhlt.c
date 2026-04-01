/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "health.h"
#include "log.h"

/* Global pointer for signal handler to perform graceful cleanup */
static lrm_health_server_t *g_health_server = NULL;
static const char *lock_file = "/var/run/redhlth.lock";

/**
 * Signal handler to ensure resources are released properly on termination.
 */
static void handle_signal(int sig) {
    log_info("Received signal %d, initiating graceful shutdown...", sig);
    if (g_health_server) {
        lrm_health_destroy(g_health_server);
    }
    unlink(lock_file);
    exit(0);
}

/**
 * Ensures only a single instance of the health service is running.
 */
static int check_single_instance(const char *file) {
    int fd = open(file, O_RDWR | O_CREAT, 0666);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * Displays command-line interface instructions.
 */
static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -r, --rack <id>      Set Rack ID (0-255)\n");
    printf("  -s, --slot <id>      Set Slot ID (0-255)\n");
    printf("  -t, --target <ip>    Target IP for active heartbeat (Push mode)\n");
    printf("  -i, --interval <sec> Active heartbeat interval in seconds\n");
    printf("  -h, --help           Show this help message\n");
}

/**
 * Entry point for the Red LRM Independent Health Monitoring Process.
 */
int main(int argc, char *argv[]) {
    uint8_t rack_id = 1; 
    uint8_t slot_id = 1;
    char *target_ip = NULL; /* Active push destination */
    int interval = LRM_HEALTH_INTERVAL; /* Default interval for active push */
    int opt;

    /* 1. Parse command-line arguments */
    static struct option long_options[] = {
        {"rack",   required_argument, 0, 'r'},
        {"slot",   required_argument, 0, 's'},
        {"target", required_argument, 0, 't'},
        {"interval", required_argument, 0, 'i'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "r:s:t:i:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'r': rack_id = (uint8_t)atoi(optarg); break;
            case 's': slot_id = (uint8_t)atoi(optarg); break;
            case 't': target_ip = strdup(optarg);      break; /* Duplicate string for safety */
            case 'i': interval = atoi(optarg);         break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    /* 2. Logging Initialization */
    log_info("Initializing Red LRM Health Monitoring (Rack:%u, Slot:%u)", rack_id, slot_id);
    if (target_ip) {
        log_info("Active report mode enabled. Target: %s", target_ip);
    } else {
        log_info("Passive mode enabled. Waiting for management board probes.");
    }

    /* 3. Privilege Validation */
    if (getuid() != 0) {
        log_error("Insufficient privileges. This service must be run as root.");
        if (target_ip) free(target_ip);
        return EXIT_FAILURE;
    }

    /* 4. Single Instance Validation */
    if (check_single_instance(lock_file) < 0) {
        log_error("Failed to acquire lock: Another instance is already running.");
        if (target_ip) free(target_ip);
        return EXIT_FAILURE;
    }

    /* 5. Signal Handler Registration */
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 6. Server Context Creation */
    g_health_server = lrm_health_create(rack_id, slot_id, interval);
    if (!g_health_server) {
        log_error("Critical failure: Could not initialize health server context.");
        unlink(lock_file);
        if (target_ip) free(target_ip);
        return EXIT_FAILURE;
    }

    /* 7. Service Execution 
     * Passing target_ip to support dual-mode (Passive + Active).
     */
    if (lrm_health_run(g_health_server, target_ip) != 0) {
        log_error("Runtime error detected in health service loop.");
    }

    /* 8. Graceful Cleanup */
    lrm_health_destroy(g_health_server);
    unlink(lock_file);
    if (target_ip) free(target_ip);
    
    log_info("Service stopped.");
    return EXIT_SUCCESS;
}