/**
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ether.h>  /* For struct ethhdr */
#include <linux/if_ether.h> /* For ETH_P_IP, ETH_ALEN protocol constants */
#include <netinet/ip.h>     /* FIXED: Contains full 'struct iphdr' definition */
#include <netinet/udp.h>    /* FIXED: Contains full 'struct udphdr' definition */
#include <arpa/inet.h>      /* For htons(), ntohs() byte-order swapping */

#include "util.h"
#include "hdr.h"
#include "log.h"
#include "gateway.h"
#include "redgw.h"
#include "cmdengine.h"

#define OMNI_POOL_SIZE      (512 * 1024)    /* 512KB Per-Thread Dedicated High-Speed Raw Memory Core */

typedef struct {
    uint8_t storage[OMNI_POOL_SIZE] __attribute__((aligned(16)));
    size_t  cursor;
    size_t  event_snapshot;
} omni_pool_t;

/* Instantiate the pool natively inside the thread's local storage frame */
static __thread omni_pool_t g_omni_thread_pool;

/**
 * @brief 1. Marks the entry point of a secure processing zone/function.
 * Saves the current state of the pool cursor.
 */
void gw_scope_begin(void) {
    g_omni_thread_pool.event_snapshot = g_omni_thread_pool.cursor;
}

/**
 * @brief Marks the exit point of a secure processing zone/function.
 * Rolls back the cursor to the exact state it was in before entering this scope.
 * This instantly destroys all allocations inside this scope with 0% CPU cost, 
 * without touching memory outside this scope!
 */
void gw_scope_exit(void) {
    g_omni_thread_pool.cursor = g_omni_thread_pool.event_snapshot;
}

/**
 * @brief Allocates a strictly isolated, 16-byte aligned memory chunk.
 * @param required_len Absolute byte size needed for the packet frame.
 * @return uint8_t* Safe aligned pointer to destination storage, or NULL if out of memory bounds.
 */
uint8_t *gw_alloc(size_t required_len) {
    /* 16-Byte Hardware Alignment Padding Calculation */
    size_t aligned_len = (required_len + 15U) & ~15U;

    if (unlikely((g_omni_thread_pool.cursor + aligned_len) > OMNI_POOL_SIZE)) {
        return NULL;
    }

    void *allocated_ptr = (void *)&g_omni_thread_pool.storage[g_omni_thread_pool.cursor];
    g_omni_thread_pool.cursor += aligned_len;

    return allocated_ptr;
}

typedef enum {
    GW_DIR_TO_CLIENT = 0,
    GW_DIR_TO_CORE  
} gw_direction_t;

/**
 * @brief Decoupled packet inspector with strict text-column alignment.
 */
static void gw_log_egress(const uint8_t *buf, size_t len, gw_direction_t direction) {
    if (!cmd_islogpkt_enabled()) return;

    if (unlikely(!buf || len < sizeof(struct ethhdr))) {
        log_error("[EGRESS] Truncated link-layer package slice dropped: %zu bytes", len);
        return;
    }

    const uint8_t *dst_mac = &buf[0];
    const uint8_t *src_mac = &buf[6];
    
    size_t l3_offset = sizeof(struct ethhdr);
    uint16_t eth_type = (buf[12] << 8) | buf[13];

    /* VLAN 穿透追踪 */
    if (unlikely(eth_type == 0x8100 || eth_type == 0x88A8)) {
        if (len < (sizeof(struct ethhdr) + 4)) return;
        eth_type = (buf[16] << 8) | buf[17]; 
        l3_offset += 4;
    }

    const char *dir_tag  = (direction == GW_DIR_TO_CORE) ? "CORE_STREAM" : "CLIENT_LINK";
    const char *dir_arrow = (direction == GW_DIR_TO_CORE) ? "RED => BLACK"  : "BLACK => RED";

    if (unlikely(len < (l3_offset + sizeof(struct iphdr)))) {
        goto _fallback_log;
    }

    uint8_t ip_ver = (buf[l3_offset] >> 4) & 0x0F;
    if (likely(ip_ver == 4)) {
        const struct iphdr *ip = (const struct iphdr *)(buf + l3_offset);
        size_t ip_hl = (size_t)(ip->ihl * 4);

        if (likely(len >= (l3_offset + ip_hl + sizeof(struct udphdr)))) {
            const struct udphdr *udp = (const struct udphdr *)(buf + l3_offset + ip_hl);

            char src_ip_str[32];
            char dst_ip_str[32];
            snprintf(src_ip_str, sizeof(src_ip_str), "%d.%d.%d.%d",
                     ((const uint8_t *)&ip->saddr)[0], ((const uint8_t *)&ip->saddr)[1],
                     ((const uint8_t *)&ip->saddr)[2], ((const uint8_t *)&ip->saddr)[3]);
            snprintf(dst_ip_str, sizeof(dst_ip_str), "%d.%d.%d.%d",
                     ((const uint8_t *)&ip->daddr)[0], ((const uint8_t *)&ip->daddr)[1],
                     ((const uint8_t *)&ip->daddr)[2], ((const uint8_t *)&ip->daddr)[3]);

            log_info("\n"
                     "+--------------------------------------------------------------------+\n"
                     "|  Direction  : [%-12s] (%-13s)                       |\n"
                     "|  Metadata   : EtherType [0x%04X] | Length [%-6zu Bytes]           |\n"
                     "|--------------------------------------------------------------------|\n"
                     "|  Layer 2    : [SRC] %02X:%02X:%02X:%02X:%02X:%02X  ->  [DST] %02X:%02X:%02X:%02X:%02X:%02X |\n"
                     "|  Layer 3    : [SRC] %-17s  ->  [DST] %-17s |\n"
                     "|  Layer 4    : [SRC] Port %-12u  ->  [DST] Port %-12u |\n"
                     "+--------------------------------------------------------------------+",
                     dir_tag, dir_arrow, eth_type, len,
                     src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
                     dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                     src_ip_str, dst_ip_str,
                     ntohs(udp->source), ntohs(udp->dest));
            return;
        }
    }

_fallback_log:
    log_info("\n"
             "+--------------------------------------------------------------------+\n"
             "|  Direction  : [%-12s] (%-13s)                         |\n"
             "|  Metadata   : EtherType [0x%04X] | WireLength [%-6zu Bytes]        |\n"
             "|--------------------------------------------------------------------|\n"
             "|  Warning    : Non-Standard Custom Sovereign Protocol Frame         |\n"
             "|               (Non-IPv4/UDP).                                      |\n"
             "+--------------------------------------------------------------------+",
             dir_tag, dir_arrow, eth_type, len);
}

/**
 * High-performance Packet Fusion Matrix
 * Assembles the user custom header and embeds the raw captured XDP frames.
 * @param dst_buf       Output vector memory boundary (Must hold payload_len + HDR_SIZE)
 * @param max_dst_len   Maximum allocated capacity of dst_buf (Safety defense boundary)
 * @param src_payload   Pointer to the incoming raw L2 frame captured from XDP
 * @param payload_len   Size of the incoming payload block
 * @param type          S sovereignty tracking type code
 * @param auth_token    Crypto/Verification token 
 * @return Total linear length of the constructed egress frame, 0 on failure.
 */
size_t gw_pack(unsigned char *dst_buf,
               const unsigned char *src_payload, 
               size_t payload_len, 
               uint16_t type, 
               uint32_t auth_token)
{
    if (unlikely(!dst_buf || !src_payload || payload_len == 0)) {
        log_error("Invalid memory pointer reference or zero-length payload detected");
        return 0;
    }

    size_t total_packet_len = HDR_SIZE + payload_len;

    // 4. Global architecture limit check
    if (total_packet_len > OMNI_POOL_SIZE) {
        log_error("Assembled packet length [%zu] blows past max GLOBAL BUFFER_SIZE boundary", total_packet_len);
        return 0;
    }

    // 6. Build the custom network header
    hdr_build(dst_buf, type, (uint32_t)total_packet_len, auth_token);

    return total_packet_len;
}

/**
 * @brief Zero-Copy High-Performance Packet Unpacking Engine.
 * Validates wire integrity, executes metadata parsing, and returns a zero-copy
 * memory reference pointing directly into the original packet's payload offset.
 *
 * @param payload_out [Output] Pointer to store the zero-copy reference to the payload slice.
 * @param pkt         Pointer to the raw immutable incoming wire packet buffer.
 * @param pkt_len     Total byte length of the incoming packet read from the network interface.
 * @param type_out    [Output] Parsed message type token (host byte order).
 * @param auth_out    [Output] Parsed authorization identifier (host byte order).
 * @return size_t     Recovered payload byte size, or 0 on any operational validation failure.
 */
size_t gw_unpack(const unsigned char **dst_buf,
                    const unsigned char *pkt,
                    ssize_t pkt_len,
                    uint16_t *type_out,
                    uint32_t *auth_out)
{
    if (unlikely(!dst_buf || !pkt || pkt_len < (ssize_t)HDR_SIZE)) {
        log_error("Invalid argument or length shorter than HDR_SIZE");
        return 0;
    }

    /* High-Throughput Hint: CRC validation runs over the whole network packet slice */
    if (unlikely(!hdr_verify_crc(pkt, pkt_len))) {
        log_error("Packet CRC verification failed for incoming packet of length %zd bytes", pkt_len);
        return 0;
    }

    uint16_t parsed_len = 0;
    uint32_t parsed_crc = 0;
    if (unlikely(hdr_parse(pkt, type_out, &parsed_len, auth_out, &parsed_crc) != 0)) {
        log_error("Failed to parse packet header");
        return 0;
    }

    /* Structural Invariant Check: Verify length claimed by header matches real wire bytes */
    if (unlikely((ssize_t)parsed_len != pkt_len)) {
        log_error("Length mismatch: header=%u, wire=%zd", parsed_len, pkt_len);
        return 0;
    }

    size_t payload_len = (size_t)pkt_len - HDR_SIZE;

    /*  
     * Completely eliminate max_dst_len limitations and remove the costly memcpy block.
     * Directly export the absolute memory address offsetting past the 12-byte protocol header.
     */
    *dst_buf = pkt + HDR_SIZE;

    return payload_len;
}

/**
 * High-performance Packaging & Streaming Gateway to Core.
 * Intercepts raw data assets, prepends the custom packed header, 
 * and pumps the resulting vector directly into the core engine via UDP.
 *
 * @param data  Pointer to the raw binary network payload asset (Host Order)
 * @param len   Size of the payload asset in bytes
 * @return Number of wire bytes transmitted, or -1 on failure.
 */
ssize_t gw_send_to_core(const uint8_t *data, size_t len) {
    if (unlikely(!data || len == 0)) {
        log_error("Invalid data pointer or zero length for sending to core");
        return -1;
    }
    gw_log_egress(data, len, GW_DIR_TO_CORE);
    /*
     * ZERO-COPY HEADROOM DECREMENT:
     * Rewind the data pointer by HDR_SIZE bytes to access the pre-allocated network 
     * headroom. This allows `gw_pack` to inject the encapsulation header directly in 
     * front of the payload without triggering a costly secondary `memcpy`.
     *
     * This math assumes the caller left at least `HDR_SIZE` bytes of writable headroom 
     * preceding `data`. If `data` starts at a strict boundary origin (e.g., standard 
     * `omni_alloc`), this offset decrement will cause out-of-bounds corruption or SIGSEGV.
     */
    uint8_t *buf = (uint8_t*)data - HDR_SIZE;

    size_t packed_len = gw_pack(buf,
                            data, 
                            len, 
                            AUTH_DATA,           // Converted internally to big-endian
                            redserver.auth_token // Converted internally to big-endian
                        );

    if (unlikely(packed_len == 0)) {
        log_error("Failed to construct header matrix for core stream telemetry");
        return -1;
    }

    /* Line-rate Layer-4 UDP dispatch using your internal raw transport driver
     * Automatically ships the continuous packed data stream [Header (12B) + Payload (len B)] */
    ssize_t sent_bytes = udp_send_raw(redserver.udpconn, 
                                      redserver.core_ip, 
                                      redserver.core_port, 
                                      (void *)buf, 
                                      packed_len);
    
    if (unlikely(sent_bytes < 0)) {
        log_error("Failed to send data to core via udp_send_raw: %s", strerror(errno));
        return -1;
    }
    
    return sent_bytes;
}

/**
 * @brief Recalculates L3 IPv4 checksum and disables L4 UDP validation.
 * @details Bypasses external L2 EtherType checking by directly scanning the IP version prefix.
 * @param buf Raw pointer to the decomposed Layer-2 network frame buffer.
 * @param len Total cumulative byte size of the frame payload inside the buffer.
 */
static void gw_fix_cksum(uint8_t *buf, size_t len) {
    if (unlikely(!buf || len < (sizeof(struct ethhdr) + sizeof(struct iphdr)))) return;

    struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));

    /* Extract IP version bitmask directly to bypass non-standard L2 EtherType */
    uint8_t ip_ver = (buf[sizeof(struct ethhdr)] >> 4) & 0x0F;
    if (likely(ip_ver == 4)) {
        size_t ip_hl = (size_t)(ip->ihl * 4);
        
        if (likely(len >= (sizeof(struct ethhdr) + ip_hl))) {
            /* Fix L3 IP Checksum */
            ip->check = 0; 
            ip->check = ip_calculate_checksum((const uint16_t *)ip, (int)ip_hl);

            /* Disable L4 UDP Checksum to force client OS acceptance */
            if (ip->protocol == IPPROTO_UDP) {
                if (likely(len >= (sizeof(struct ethhdr) + ip_hl + sizeof(struct udphdr)))) {
                    struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct ethhdr) + ip_hl);
                    udp->check = 0; 
                }
            }
        }
    }
}

/**
 * @brief High-performance Reverse Data Decapsulation and Client-directed Egress Engine.
 * Slices the incoming tunneled wire packet, bypasses the outer encapsulation shell (42B),
 * verifies integrity, strips custom header, fixes corrupted IP checksums, and shoots back to wire.
 *
 * @param data  Non-null pointer to the continuous hardware packet buffer harvested from core interface.
 * @param len   Total cumulative byte size of the raw wire packet array.
 * @return      Number of wire bytes successfully injected into the L2 interface, or -1 on critical failure.
 */
ssize_t gw_send_to_client(const uint8_t *data, size_t len) {
    const size_t tunnel_shell_len = 14U + 20U + 8U;
    const size_t minimum_required_len = tunnel_shell_len + HDR_SIZE;

    /* Defensive Sanity Verification against Null Stream Reference or Truncated Payload bounds */
    if (unlikely(!data || len < minimum_required_len)) {
        log_error("Invalid data payload reference or packet size falls under minimum required threshold (%zu bytes)", 
                  minimum_required_len);
        return -1;
    }

    const unsigned char *rx = NULL;
    uint16_t parsed_type = 0U;
    uint32_t parsed_auth = 0U;

    /* Strategic Memory Slicing to extract the sovereign encapsulated packet */
    const uint8_t *payload = data + tunnel_shell_len;
    const size_t payload_len = len - tunnel_shell_len;

    /* gw_unpack completely recovers the pure original Layer-2 packet frame inside rx */
    size_t rawlen = gw_unpack(&rx, 
                                payload,
                                (ssize_t)payload_len, 
                                &parsed_type, 
                                &parsed_auth);

    if (unlikely(rawlen == 0U)) {
        log_error("Failed to decapsulate core package stream due to integrity, length mismatch or parser anomalies");
        return -1;
    }

    if (unlikely(parsed_type != AUTH_DATA)) {
        log_warn("Security Dropped: Unverified or rogue message type signature code intercepted: 0x%04X", 
                 parsed_type);
        return -1;
    }

    /*
     * Modifying data payloads/IP mappings inside user-space completely breaks original
     * checksum matrices. We must recalibrate L3 IP Checksum before hardware link injection.
     */
    gw_fix_cksum((uint8_t *)rx, rawlen);
    gw_log_egress(rx, rawlen, GW_DIR_TO_CLIENT);

    ssize_t sent_bytes = raw_send_udp_adaptive_frag(redserver.rawconn, rx, rawlen);
    
    if (unlikely(sent_bytes < 0)) {
        log_error("Line-rate raw Layer-2 link injection back to client egress node failed: %s",
                  strerror(errno));
        return -1;
    }

    return sent_bytes;
}