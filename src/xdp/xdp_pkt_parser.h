/*
 * Packet Parser Module
 * Copyright (c) 2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef __PKT_PARSER_H__
#define __PKT_PARSER_H__

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

enum PKTTYPE {
    PKT_TYPE_PROBE = 0x0857,
    PKT_TYPE_ENG = 0x0800,
    PKT_TYPE_CTRL = 0x0856,
};
/**
 * @struct pkt_info_t
 * @brief Unified structure to store parsed protocol information.
 */
typedef struct {
    struct {
        uint8_t  src[6];     /**< Source MAC address */
        uint8_t  dst[6];     /**< Destination MAC address */
        uint16_t proto;      /**< EtherType (e.g., 0x0800 for IPv4) */
    } eth;

    struct {
        uint32_t src_ip;     /**< Source IPv4 address (network byte order) */
        uint32_t dst_ip;     /**< Destination IPv4 address (network byte order) */
        uint8_t  proto;      /**< L4 protocol (IPPROTO_UDP or IPPROTO_TCP) */
        uint8_t  ttl;        /**< Time to Live */
        uint16_t id;          /* IPv4 Identification */
        uint16_t frag_off;    /* Fragment Offset & Flags */
        int      is_fragment; /* 1 if MF is set or Offset > 0 */
    } ip;

    struct {
        uint16_t src_port;   /**< Source Port (host byte order) */
        uint16_t dst_port;   /**< Destination Port (host byte order) */
        uint16_t len;        /**< L4 length (for UDP) */
    } l4;

    const uint8_t *payload;      /**< Pointer to the start of application data */
    size_t         payload_len;  /**< Length of the application data */
} pkt_info_t;

/**
 * @brief Parse a raw Ethernet frame into a structured pkt_info_t.
 * @param data Pointer to the raw packet buffer.
 * @param len Total length of the packet buffer.
 * @param info Pointer to the output structure.
 * @return 0 on success, negative value if the packet is malformed or unsupported.
 */
int xdp_pkt_parse_all(const uint8_t *data, size_t len, pkt_info_t *info);

/**
 * @brief Primary packet dispatcher for data received via the XDP Ring Buffer.
 * This function serves as the entry point for the userspace processing logic. 
 * It differentiates between tunneled infrastructure traffic (e.g., Engine or Probe 
 * messages) and raw client data. Depending on the identified packet type, it 
 * routes the data for reverse decapsulation or forward encapsulation.
 * @param ctx     User-defined context pointer (typically used for state management).
 * @param data    Pointer to the raw byte stream received from the XDP socket.
 * @param data_sz The total size of the received data buffer in bytes.
 * @return int    Returns 0 on successful processing. Non-zero values may indicate 
 * an error depending on the ring buffer callback requirements.
 */
int xdp_handle_ringbuf(void *ctx, const uint8_t *data, size_t data_sz);

/**
 * @brief Initializes the IP reassembly subsystem and binds metadata to buffers.
 * This function performs a "Cold/Hot" memory split optimization:
 * 1. It clears the Metadata Table (Hot Data), which contains search keys and bitmaps.
 * 2. It statically binds each metadata slot to a pre-allocated large data buffer (Cold Data).
 * * By pre-binding pointers during initialization, we ensure that:
 * - The xdp_get_reasm_slot() function remains lock-free and avoids dynamic allocation.
 * - Linear probing during hash collisions only touches compact metadata, 
 * drastically improving CPU L1/L2 cache hit rates.
 * @note This MUST be called once at program startup before any packets are processed.
 * In multi-threaded environments, ensure this table is either per-thread 
 * or protected by a sharding mechanism.
 */
void xdp_reasm_init(void);

/**
 * @brief Periodically exports and logs the IP reassembly subsystem metrics.
 * * This function retrieves the global statistics using atomic load operations 
 * (implemented via __sync_val_compare_and_swap) to ensure "tear-free" reads. 
 * This is critical in multi-core environments where one CPU might be incrementing 
 * a counter while another is reading it.
 * * Metrics monitored:
 * - Completed: Number of successfully reassembled IPv4 datagrams.
 * - Overlap Drops: Count of detected overlapping fragments (indicative of Teardrop attacks).
 * - Timeout Drops: Number of incomplete fragment chains reclaimed after the 2000ms TTL.
 * - OOB Errors: Fragments that attempted to exceed the 65,535-byte IP limit.
 * @note This should be called from a management thread or a periodic timer 
 * (e.g., every 10 seconds) to provide visibility into the data plane's health.
 */
void xdp_reasm_show_stats(void);

/**
 * @brief Print parsed packet details to stdout in a professional format.
 * @param info Pointer to the parsed information.
 */
void xdp_pkt_dump_log(const pkt_info_t *info);

#endif /* __PKT_PARSER_H__ */