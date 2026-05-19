/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __PKTPCAP_H__
#define __PKTPCAP_H__

#include <pcap.h>
#include <stdint.h>
#include <errno.h>

#define PCAP_OUT_NONE           ((uint8_t)0x00)
#define PCAP_OUT_CONSOLE        ((uint8_t)0x01)
#define PCAP_OUT_FILE           ((uint8_t)0x02)
#define PCAP_OUT_VALID_MASK     (PCAP_OUT_CONSOLE | PCAP_OUT_FILE) /**< Valid output mode bitmask for sanity checks */

#define PCAP_MAX_PACKET_SIZE    1600  /**< adapt to standard MTU + Ethernet header boundaries */
typedef struct {
    struct pcap_pkthdr header;
    uint32_t len;
    uint8_t data[PCAP_MAX_PACKET_SIZE];
} pcap_packet_node_t;

typedef struct pcap_backend_ctx pcap_backend_t;

/**
 * @brief Initializes the high-performance packet capture engine.
 * 
 * @param ifname Name of the network interface (e.g., "eth0").
 * @param bpf_filter Berkeley Packet Filter (BPF) expression string. Pass NULL for no filtering.
 * @param promiscuous Set to 1 to enable promiscuous mode, 0 to disable.
 * @param output_mode Combined routing bitmasks (PCAP_OUT_CONSOLE, PCAP_OUT_FILE, or both).
 * @param save_path Absolute or relative file path for the output .pcap file (Ignored if PCAP_OUT_FILE is unset).
 * @return pcap_backend_t* Pointer to the initialized engine instance, or NULL on failure.
 */
pcap_backend_t* pcap_engine_init(const char *ifname, 
                                 const char *bpf_filter,
                                 int promiscuous, 
                                 uint8_t output_mode,
                                 const char *save_path);

/**
 * @brief Spawns an internal asynchronous worker thread and starts the packet capture pipeline.
 * @details This function is completely non-blocking. It delegates the heavy blocking loop to a dedicated,
 *          internally managed POSIX thread, fully isolating the data plane from the calling thread.
 * 
 * @param ctx Pointer to the engine instance handle.
 * @param callback Custom user processing callback. Pass NULL to deploy the engine's built-in managed handler.
 * @param user_data Custom user pointer context passed directly into the custom callback.
 * @return int Returns 0 on successful thread spawning, or a negative value on failure.
 * 
 * @retval  0 Success: Worker thread spawned and running successfully.
 * @retval -1 Invalid Argument: The provided \p ctx is NULL.
 * @retval -2 Thread Creation Failed: Operating system resource exhaustion (pthread_create failed).
 */
int pcap_engine_start(pcap_backend_t *ctx, pcap_handler callback, u_char *user_data);

/**
 * @brief Asynchronously signals and synchronously joins the active worker thread to stop capture.
 * @details This function breaks the internal loop, waits for the worker thread to exit safely 
 *          (guaranteeing file descriptor flush), and resets internal active flags.
 * 
 * @param ctx Pointer to the engine instance handle.
 * @return int Returns 0 on successful graceful shutdown, or a negative value if the engine was not running.
 */
int pcap_engine_stop(pcap_backend_t *ctx);

/**
 * @brief Dynamically updates or injects a new BPF filter at runtime during active capture.
 * @note This function is fully thread-safe and can be safely invoked while the background thread is running.
 * 
 * @param ctx Pointer to the engine instance handle.
 * @param new_bpf_filter New Berkeley Packet Filter expression string. Pass NULL or "" to clear all filters.
 * @return int Returns 0 on successful hot-swapping, or a negative value on compilation/injection failure.
 */
int pcap_engine_update_filter(pcap_backend_t *ctx, const char *new_bpf_filter);
int pcap_engine_set_filter(const char *new_bpf_filter);

/**
 * @brief Destroys the engine instance, safely stopping active threads, flushing buffers, and reclaiming system resources.
 * @note If the internal thread is still actively capturing, this will implicitly call pcap_engine_stop() first.
 * 
 * @param ctx Pointer to the engine instance handle.
 */
void pcap_engine_destroy(pcap_backend_t *ctx);

/**
 * @brief Dynamically hot-swaps the packet distribution target bitmask in a lock-free, thread-safe manner.
 * 
 * This method directly updates the active output routing state using atomic stores, bypassing
 * the heavy structural filter_mutex to prevent critical-path data plane stalls.
 * 
 * @param mode  New bitmask combination topology (e.g., PCAP_OUT_FILE | PCAP_OUT_MEMORY).
 * @return int  0 upon successful injection, or -1 if the backend context is invalid.
 */
int pcap_engine_set_output_mode(uint8_t mode);


// /**
//  * @brief Serializes and submits a structural packet node object into the generic ring buffer.
//  * @param ctx Pointer to the engine instance handle.
//  * @param node Pointer to the self-contained source structure block.
//  * @return 0 on success, negative code on constraint error.
//  */
// int pcap_write_node(pcap_backend_t *ctx, const pcap_packet_node_t *node);

// /**
//  * @brief Reconstructs and fills a structural packet node object out of the generic ring buffer.
//  * @param ctx Pointer to the engine instance handle.
//  * @param out_node Target memory structure block to receive the unmarshalled packet.
//  * @return 0 on success, -1 on empty buffer, -2 on concurrency collision or tearing.
//  */
// int pcap_read_node(pcap_backend_t *ctx, pcap_packet_node_t *out_node);

#endif /* __PKTPCAP_H__ */