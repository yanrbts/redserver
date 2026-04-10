/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 *
 *
 * @file gap.h
 * @brief Definitions for tunneled packets in red-black isolation gateway
 *
 * This header defines the structure for encapsulated packets where the payload
 * of the outer UDP (port 52719) contains a forged Ethernet/IP/UDP frame with
 * authentication and the real inner operations data.
 *
 * Outer UDP packet structure (simplified):
 *   +-------------------------+
 *   | Ethernet Header (14 B)  |  ← Forged
 *   +-------------------------+
 *   | IP Header (20 B)        |  ← Forged
 *   +-------------------------+
 *   | UDP Header (8 B)        |  ← Forged
 *   +-------------------------+
 *   | AUTH (4 B)              |  ← Authentication field
 *   +-------------------------+
 *   | tunnel_inner_payload_t  |  ← Real operations payload
 *   +-------------------------+
 * 
 * +-------------------------+
 * |  +-------------------+  |
 * |  |   Data json       |  |
 * |  +-------------------+  |
 * |  |   dataLen 2 bytes |  |
 * |  +-------------------+  |
 * |  |   Num 1 byte      |  |
 * |  +-------------------+  |
 * |  |   Total 2 bytes   |  |
 * |  +-------------------+  |
 * |  |   rcpId 1 byte    |  |
 * |  +-------------------+  |
 * |  |   Method 6 bytes  |  |
 * |  +-------------------+  |
 * |  |   URL 128 bytes   |  |
 * |  +-------------------+  |
 * +-------------------------+
 * |        UDP port         |
 * +-------------------------+
 * |        IP               |
 * +-------------------------+
 * |        MAC              |
 * +-------------------------+
 * |        AUTH             |
 * +-------------------------+
 * |        UDP 5271         |
 * +-------------------------+
 * |        IP               |
 * +-------------------------+
 * |        MAC              |
 * +-------------------------+
 * 
 * control packet structure:
 * +-------------------------+
 * |   UDP port 60002-50002  |
 * +-------------------------+
 * |        IP 红黑固定IP     |
 * +-------------------------+
 * |        MAC  0x0800      |
 * +-------------------------+
 * |        AUTH             |
 * +-------------------------+
 * |        UDP 红/黑-52719   |
 * +-------------------------+
 * |        IP               |
 * +-------------------------+
 * |        MAC              |
 * +-------------------------+
 */
#ifndef __GAP_H__
#define __GAP_H__

#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include "util.h"
#include "udp.h"

#define GAP_METHOD_LEN      6
#define GAP_AUTH_LEN        12
#define GAP_URL_LEN         128
#define GAP_MAX_FRAGMENT    1300
#define GAP_IP_HDR_LEN      20
#define GAP_UDP_HDR_LEN     8

#define GAP_PACKET_SIZE(json_len) \
    (offsetof(tunnel_payload_t, inner_data) + offsetof(tunnel_inner_payload_t, data) + (json_len))
#define GAP_INNER_PACKET_SIZE(json_len) \
    (offsetof(tunnel_inner_payload_t, data) + (json_len))

// typedef struct {
//     uint16_t dataLen;                   // Length of the following JSON data (network byte order)
//     uint8_t  num;                       // Current fragment number (1-based)
//     uint16_t total;                     // Total number of fragments (network byte order)
//     uint8_t  rcpId;                     // Report ID
//     uint8_t  method[GAP_METHOD_LEN];    // Method name (fixed 6 bytes, possibly padded with 0)
//     uint8_t  url[GAP_URL_LEN];          // URL or path (fixed 128 bytes, padded with 0)
//     uint8_t  data[];                    // JSON data length bytes
// } __attribute__((packed)) tunnel_inner_payload_t;

typedef struct {
    uint8_t  url[GAP_URL_LEN];          // URL or path (fixed 128 bytes, padded with 0)
    uint8_t  method[GAP_METHOD_LEN];    // Method name (fixed 6 bytes, possibly padded with 0)
    uint8_t  rcpId;                     // Report ID
    uint16_t total;                     // Total number of fragments (network byte order)
    uint8_t  num;                       // Current fragment number (1-based)
    uint16_t dataLen;                   // Length of the following JSON data (network byte order)
    uint8_t  data[];                    // JSON data length bytes
} __attribute__((packed)) tunnel_inner_payload_t;

/* The following fields represent a 
 * "forged" full Layer 2 + Layer 3 + Layer 4 packet used as payload */
typedef struct {
    uint8_t  auth[GAP_AUTH_LEN];                    // Authentication field 12 bytes
    uint8_t  ether_header[14];                      // Ethernet header (Destination MAC + Source MAC + EtherType 0x0800)
    uint8_t  ip_header[GAP_IP_HDR_LEN];             // IPv4 header (version, header length, protocol = 17 for UDP, source/destination IP, etc.)
    uint8_t  udp_header[GAP_UDP_HDR_LEN];           // UDP header (source port, destination port, length, checksum)
    uint8_t  inner_data[];                          // Inner payload data (variable length)
} __attribute__((packed)) tunnel_payload_t;


/**
 * @brief Builds one or more tunneled packets, fragmenting the JSON if necessary.
 *
 * If the JSON data exceeds MAX_JSON_PER_FRAGMENT, it is split into multiple packets.
 * Each packet has the same auth, method, url, rcpId, but different num/total/dataLen.
 *
 * Caller is responsible for freeing each payloads[i] and the payloads array itself.
 *
 * @param json_data       Full JSON data buffer
 * @param json_len        Total JSON length
 * @param dst_mac         Destination MAC (6 bytes)
 * @param src_mac         Source MAC (6 bytes)
 * @param src_ip_nbo      Source IPv4 (4 bytes, Network Byte Order)
 * @param dst_ip_nbo      Destination IPv4 (4 bytes, Network Byte Order)
 * @param src_port        Forged source port (host order)
 * @param dst_port        Forged destination port (host order)
 * @param auth            Authentication field (GAP_AUTH_LEN bytes)
 * @param rcpId           Report/message ID (same for all fragments)
 * @param method          Method name (shared)
 * @param url             URL/path (shared)
 * @param payloads_out    Output: array of tunnel_payload_t*
 * @param num_payloads    Output: number of packets (1 or more)
 * @return 0 on success, -1 on failure
 */
int gap_build_tunneled_packets(
    const uint8_t *json_data,
    size_t json_len,
    const uint8_t *src_mac,
    const uint8_t *dst_mac,
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t auth,
    uint8_t rcpId,
    const char *method,
    const char *url,
    tunnel_payload_t ***payloads_out,
    size_t *num_payloads
);

/**
 * @brief Constructs one or more tunneled packets from a raw data buffer.
 * This function fragments the input 'data' into multiple tunnel_payload_t packets 
 * if the total size exceeds GAP_MAX_FRAGMENT. It preserves the original rcpId, 
 * method, and url from the source data header and prepends a new 
 * tunnel_inner_payload_t to each fragment.
 *
 * @param data         [In] Pointer to the source buffer (contains inner header + payload).
 * @param len          [In] Total length of the source buffer.
 * @param src_mac      [In] 6-byte source MAC address for the forged Ethernet header.
 * @param dst_mac      [In] 6-byte destination MAC address for the forged Ethernet header.
 * @param src_ip_nbo   [In] Source IPv4 address in Network Byte Order.
 * @param dst_ip_nbo   [In] Destination IPv4 address in Network Byte Order.
 * @param src_port     [In] Forged source UDP port (Host Order).
 * @param dst_port     [In] Forged destination UDP port (Host Order).
 * @param auth         [In] 32-bit authentication value.
 * @param payloads_out [Out] Pointer to an allocated array of tunnel_payload_t pointers.
 * @param num_payloads [Out] Total number of fragments generated.
 * @return 0 on success, -1 on failure.
 * @note The caller is responsible for freeing each packet and the payloads array 
 * via gap_free_tunneled_packets().
 */
int gap_build_tunneled_packets_ex(
    const uint8_t *data,
    size_t len,
    const uint8_t *src_mac,
    const uint8_t *dst_mac,
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t auth,
    tunnel_payload_t ***payloads_out,
    size_t *num_payloads
);

/**
 * @brief Safely frees the payloads array and all contained tunnel_payload_t packets.
 * 
 * @param payloads Pointer to the array of tunnel_payload_t pointers.
 * @param num_payloads The number of packets in the array.
 */
void gap_free_tunneled_packets(tunnel_payload_t **payloads, size_t num_payloads);

/**
 * @brief Constructs a control packet with forged Ethernet + IP + UDP headers,
 *        authentication field, and real payload. Returns the allocated packet.
 *
 * This function creates a complete control payload that can be sent over UDP.
 * The caller is responsible for freeing the returned pointer.
 *
 * @param real_data Pointer to the real payload data (e.g., JSON)
 * @param real_len  Length of the real payload
 * @param dst_mac   Destination MAC address (6 bytes)
 * @param src_mac   Source MAC address to forge (6 bytes)
 * @param src_ip_nbo    Source IPv4 (4 bytes, Network Byte Order)
 * @param dst_ip_nbo    Destination IPv4 (4 bytes, Network Byte Order)
 * @param src_port  Forged source UDP port (host order)
 * @param dst_port  Forged destination UDP port (host order)
 * @param auth      Authentication field (4 bytes)
 * @param packet_len Out parameter: total length of the returned packet
 * @return Allocated packet buffer on success, NULL on failure
 * @warning Caller must gap_free_single_payload() the returned pointer.
 */
tunnel_payload_t* gap_build_control_packet(
    const uint8_t *real_data,
    size_t real_len,
    const uint8_t *src_mac,        // 6 bytes
    const uint8_t *dst_mac,        // 6 bytes
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,            
    uint16_t src_port,             // host order
    uint16_t dst_port,             // host order
    uint32_t auth,                 // 4 bytes
    size_t *packet_len             // output: total packet size
);

/**
 * @brief Constructs a raise packet with forged Ethernet header and authentication field.
 * This is used for critical alerts that need to be sent to the black zone without the full IP/UDP encapsulation.
 * The caller is responsible for freeing the returned pointer.
 * @param real_data Pointer to the real payload data (e.g., JSON)
 * @param real_len  Length of the real payload
 * @param dst_mac   Destination MAC address (6 bytes)
 * @param src_mac   Source MAC address to forge (6 bytes)
 * @param src_ip_nbo    Source IPv4 (4 bytes, Network Byte Order)
 * @param dst_ip_nbo    Destination IPv4 (4 bytes, Network Byte Order)
 * @param src_port  Forged source UDP port (host order)
 * @param dst_port  Forged destination UDP port (host order)
 * @param auth      Authentication field (4 bytes)
 * @param packet_len Out parameter: total length of the returned packet
 * @return Allocated packet buffer on success, NULL on failure
 * @warning Caller must gap_free_single_payload() the returned pointer.
 */
tunnel_payload_t* gap_build_ctrl54_packet(
    const uint8_t *real_data,
    size_t real_len,
    const uint8_t *src_mac,        // 6 bytes
    const uint8_t *dst_mac,        // 6 bytes
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,            
    uint16_t src_port,             // host order
    uint16_t dst_port,             // host order
    uint32_t auth,                 // 4 bytes
    size_t *packet_len             // output: total packet size
);

/**
 * @brief Creates a temporary socket and sends one or more tunnel_payload_t packets.
 * @param dst_ip  The physical destination IP of the next-hop gateway.
 * @param dst_port The physical destination UDP port (e.g., 52719).
 * @param payloads Array of tunnel_payload_t pointers.
 * @param num_payloads Number of packets in the array.
 * @param conn udp connect sock
 * @return 0 on success, -1 on failure.
 */
int gap_send_tunneled_to_target(
    const char *dst_ip,
    uint16_t dst_port,
    tunnel_payload_t **payloads,
    size_t num_payloads,
    udp_conn_t *conn
);

/**
 * @brief Sends a batch of tunneled packets through a raw socket.
 * This implementation opens a raw socket for the duration of the batch,
 * iterates through the packets, calculates their dynamic lengths, 
 * and performs the transmission.
 *
 * @param if_name Target interface name (e.g., "eth0").
 * @param packets Array of pointers to tunnel_payload_t structures.
 * @param num     Number of packets in the array.
 */
void gap_raw_send_to_target(const char *if_name, tunnel_payload_t **packets, size_t num);

/**
 * @brief Unpacks the tunneled packet received from the Black Zone.
 * @param tunnel_buf    [In]  Raw buffer received from the UDP socket.
 * @param tunnel_len    [In]  Total length of the received buffer.
 * @param proxy_port    [Out] Extracted inner proxy port for NAT lookup.
 * @param business_data [Out] Pointer to the actual JSON business data.
 * @param business_len  [Out] Length of the JSON business data.
 * @return int 0 on success, -1 on format error, -2 on length mismatch.
 */
int gap_unpack_packets(unsigned char *tunnel_buf, size_t tunnel_len, 
                       uint16_t *proxy_port, 
                       unsigned char **business_data, size_t *business_len);


/**
 * @brief Calculates the total size of a GAP packet including headers and payload.
 * @param payload_ptr Pointer to the tunnel_payload_t structure.
 * @return Total size in bytes, or 0 if payload_ptr is NULL.
 */   
static inline size_t get_gap_packet_total_size(const void *payload_ptr) {
    if (!payload_ptr) return 0;

    const tunnel_inner_payload_t *inner = (const tunnel_inner_payload_t *)((tunnel_payload_t *)payload_ptr)->inner_data;
    
    if (!inner) return 0;

    uint16_t fragment_data_len = ntohs(inner->dataLen);
    return GAP_PACKET_SIZE(fragment_data_len);
}

/**
 * @brief Retrieves a pointer to the inner header of a tunneled packet.
 * @param payload Pointer to the raw payload data.
 * @param len Length of the payload buffer.
 * @return Pointer to the tunnel_inner_payload_t if valid, NULL otherwise.
 */
static inline tunnel_inner_payload_t* gap_get_inner(const uint8_t *payload, size_t len) {
    if (unlikely(!payload || len < sizeof(tunnel_inner_payload_t))) {
        return NULL;
    }
    return (tunnel_inner_payload_t *)payload;
}

/**
 * @brief Safely frees a single tunnel_payload_t packet.
 * @param pkt Pointer to the tunnel_payload_t packet to free.
 */
static inline void gap_free_single_payload(tunnel_payload_t *pkt) {
    if (pkt) {
        free(pkt);
    }
}

/**
 * @brief Initializes the global memory pool for fragment reassembly.
 * @return 0 on success, -1 on allocation failure.
 */
int gap_assemble_init(void);

/**
 * @brief Completely releases the global memory pool.
 * Should be called during application shutdown (e.g., in a SIGTERM handler)
 * to prevent memory leaks and reset all session pointers to NULL.
 */
void gap_assemble_destroy(void);

/**
 * @brief Reassembles tunnel fragments into a complete JSON buffer.
 * @param frag Pointer to the incoming fragment structure.
 * @param out_full_size Output parameter for the total assembled length.
 * @return Pointer to the allocated complete buffer (Caller MUST free), or NULL.
 */
uint8_t* gap_assemble_tunnel_payload(const tunnel_inner_payload_t *frag, size_t *out_full_size);

/**
 * @brief Deallocates the final assembled packet buffer.
 * @param complete_pkt Pointer returned by gap_assemble_tunnel_payload.
 * Call this function once the upper-layer logic (e.g., JSON parsing or 
 * transmission) has finished processing the reassembled data.
 */
void gap_assemble_free_packet(uint8_t *complete_pkt);

/**
 * @brief Periodically scans and cleans up expired reassembly sessions.
 * This should be called by a timer or the main loop to prevent "zombie" sessions
 * from occupying the pool slots indefinitely.
 */
void gap_assemble_cleanup(void *user_data);

#endif