/*
 * XDP Receiver Test Application
 * Copyright (c) 2026, Red LRM.
 * Author: [yanruibing]
 * Description: High-performance packet capture test tool using XDP Ring Buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "xdp_receiver.h"
#include "xdp_pkt_parser.h"

/* Opaque handle for the receiver context */
static void *g_rx_handle = NULL;

/**
 * @brief Signal handler to ensure graceful shutdown.
 * @param sig Signal number (SIGINT, SIGTERM).
 */
static void signal_handler(int sig) {
    printf("\n[*] Termination signal (%d) received. Exiting...\n", sig);
    if (g_rx_handle) {
        /* KEY POINT: Thread-safe trigger to break the internal polling loop */
        xdp_receiver_exit(g_rx_handle);
    }
}

/**
 * @brief Custom packet processing callback.
 * This function is called for every packet received via the BPF ring buffer.
 */
static int my_packet_handler(void *user_ctx, const uint8_t *pkt, size_t pkt_len) {
    (void)user_ctx; /* Unused in this example, but could be used for app-specific state */
    pkt_info_t info = {0};
    
    /* Use our parser module to decode the raw Ethernet frame */
    if (xdp_pkt_parse_all(pkt, pkt_len, &info) == 0) {
        /* Filter: For example, only log UDP traffic */
        if (info.ip.proto == IPPROTO_UDP) {
            printf("[UDP CALLBACK] ");
            xdp_pkt_dump_log(&info);
        } else if (info.ip.proto == IPPROTO_TCP) {
            printf("[TCP CALLBACK] ");
            xdp_pkt_dump_log(&info);
        } else {
            /* Fallback for other IP protocols */
            printf("[IP CALLBACK] Proto: %d, Len: %zu\n", info.ip.proto, pkt_len);
        }
    }
    
    return 0; /* Return 0 to keep the receiver running */
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <bpf_obj_path>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 xdp_prog.o\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *obj_path = argv[2];

    /* 1. Setup Signal Handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* 2. Configure the Receiver */
    xdp_receiver_config_t cfg = {
        .bpf_obj_path = obj_path,
        .ifname = ifname,
        .user_ctx = NULL,   /* We could pass app-specific state here */
        .verbose = true
    };

    printf("[*] Initializing XDP Receiver on interface: %s\n", ifname);

    /* 3. Initialize the Receiver with our custom callback */
    g_rx_handle = xdp_receiver_init(&cfg, my_packet_handler);
    if (!g_rx_handle) {
        fprintf(stderr, "[!] Failed to initialize XDP receiver\n");
        return EXIT_FAILURE;
    }

    /* 4. Start the Blocking Loop */
    /* This will stay here until xdp_receiver_exit() is called by the signal handler */
    int ret = xdp_receiver_start(g_rx_handle);
    if (ret < 0) {
        fprintf(stderr, "[!] Receiver loop exited with error: %d\n", ret);
    }

    /* 5. Resource Cleanup */
    printf("[*] Shutting down...\n");
    xdp_receiver_stop(&g_rx_handle);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}