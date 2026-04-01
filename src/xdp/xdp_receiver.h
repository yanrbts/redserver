/*
 * XDP Ring Buffer Receiver
 * Copyright (c) 2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef __XDP_RECEIVER_H__
#define __XDP_RECEIVER_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @struct packet_event
 * @brief Represents the data structure passed from BPF kernel space.
 * This structure must match the definition in the XDP kernel program exactly.
 */
struct packet_event {
    uint32_t pkt_len;         /**< Actual length of the network packet in bytes */
    uint8_t  data[2048];      /**< Flexible array member containing raw Ethernet frame */
} __attribute__((packed));

/**
 * @struct xdp_receiver_config
 * @brief Configuration parameters for initializing the XDP receiver.
 */
typedef struct xdp_receiver_config {
    const char *bpf_obj_path;   /**< Path to the compiled BPF object file (.o) */
    const char *ifname;         /**< Target network interface name (e.g., "eth0") */
    void       *user_ctx;       /**< User-defined context passed back in callbacks */
    bool        verbose;        /**< Enable detailed library logging */
} xdp_receiver_config_t;

/**
 * @brief Callback function type for packet processing.
 * @param user_ctx The user context provided in xdp_receiver_config_t.
 * @param pkt Pointer to the start of the raw Ethernet packet.
 * @param pkt_len Length of the packet data.
 * @return 0 to continue, negative value to signal a stop to the receiver.
 */
typedef int (*xdp_packet_cb)(void *user_ctx, const uint8_t *pkt, size_t pkt_len);

/**
 * @brief Initializes the XDP receiver instance.
 * Loads the BPF object, attaches the program to the specified interface, 
 * and prepares the ring buffer for polling.
 * @param cfg Pointer to the configuration structure.
 * @param cb Optional user callback. If NULL, a default parser will be used.
 * @return An opaque handle to the receiver context on success, NULL on failure.
 */
void* xdp_receiver_init(const xdp_receiver_config_t *cfg, xdp_packet_cb cb);

/**
 * @brief Starts the packet processing loop.
 * This is a blocking call. It polls the ring buffer for new packets until 
 * xdp_receiver_exit() is called or an unrecoverable error occurs.
 * @param ctx The receiver context handle returned by xdp_receiver_init.
 * @return 0 on successful exit, or a negative error code.
 */
int xdp_receiver_start(void *ctx);

/**
 * @brief Signals the receiver loop to terminate.
 * This function is thread-safe and can be called from signal handlers 
 * to gracefully stop a running xdp_receiver_start() loop.
 * @param ctx The receiver context handle.
 */
void xdp_receiver_exit(void *ctx);

/**
 * @brief Stops the receiver and cleans up all allocated resources.
 * Detaches the XDP program from the interface, closes BPF maps, frees 
 * the ring buffer, and releases memory. The context pointer will be set to NULL.
 * @param ctx_ptr Pointer to the receiver context handle.
 */
void xdp_receiver_stop(void **ctx_ptr);

#endif /* __XDP_RECEIVER_H__ */