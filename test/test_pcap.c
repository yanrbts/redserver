/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "pktpcap.h"

static pcap_backend_t *engine = NULL;
static volatile int keep_running = 1;

/**
 * @brief Asynchronous signal interceptor to gracefully command shutdown phases.
 */
static void handle_signals(int sig) {
    (void)sig;
    keep_running = 0;
    
    /* 
     * If the user hits Ctrl+C, we proactively signal the internal thread 
     * to break its loop, unblocking any pending synchronization barriers.
     */
    if (engine) {
        pcap_engine_stop(engine);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    char input_buf[256];
    
    /* Enable simultaneous dual-channel output routing (STDOUT and binary PCAP storage) */
    uint8_t modes = PCAP_OUT_CONSOLE | PCAP_OUT_FILE;
    const char *filepath = "./dynamic_output.pcap";

    /* Register POSIX signal handlers for reliable runtime cleanup */
    signal(SIGINT, handle_signals);
    signal(SIGTERM, handle_signals);

    printf("[Control-Plane] Initializing thread-safe ingestion context on: %s...\n", iface);
    
    /* Step 1: Instantiate the backend context container */
    engine = pcap_engine_init(iface, "", 1, modes, filepath);
    if (!engine) {
        fprintf(stderr, "[Control-Plane Fatal] Core instantiation failed\n");
        return -1;
    }

    /* 
     * Step 2: Launch the data-plane engine.
     * The component automatically handles internal POSIX worker thread deployment,
     * immediately returning execution control right back to this main thread.
     */
    printf("[Control-Plane] Spawning internal background ingestion thread layer...\n");
    if (pcap_engine_start(engine, NULL, NULL) < 0) {
        fprintf(stderr, "[Control-Plane Fatal] Failed to bootstrap encapsulated data-plane thread.\n");
        pcap_engine_destroy(engine);
        return -1;
    }

    /* 
     * Step 3: Main thread transforms entirely into the Administrative Control Panel.
     * Free from blocking processing logic, it drives interactive CLI configurations natively.
     */
    sleep(1); /* Give the backend a brief window to print starting driver telemetry rows */

    while (keep_running) {
        printf("\n=======================================================\n");
        printf(" [DYNAMIC CONTROL PANEL] Enter new BPF filter rule:\n");
        printf(" (Examples: \"tcp\", \"udp and port 53\", or empty to Reset)\n");
        printf("=======================================================\n");
        printf(">> ");
        fflush(stdout);

        /* Block on user input without dragging down packet-ingestion line rates */
        if (fgets(input_buf, sizeof(input_buf), stdin) == NULL) {
            break;
        }

        /* Clean newline character endings trailing from user shell inputs */
        input_buf[strcspn(input_buf, "\n")] = '\0';

        if (!keep_running) break;

        /* Execute lock-split thread-safe hot-swap directly into the running device */
        int ret = pcap_engine_update_filter(engine, input_buf);
        if (ret < 0) {
            fprintf(stderr, "[PCAP] Update failed. Invalid rule composition.\n");
        }
    }

    /* 
     * Step 4: Graceful resource reclamation.
     * pcap_engine_destroy automatically ensures worker thread join operations,
     * flushes cached page blocks to storage, and safely dismantles active handles.
     */
    printf("\n[Control-Plane] Initiating structural teardown sequence...\n");
    pcap_engine_destroy(engine);
    printf("[Control-Plane] Managed context closed down securely.\n");

    return 0;
}