/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
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
 *   | tunnel_inner_payload_t         |  ← Real operations payload
 *   +-------------------------+
 */
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <errno.h>
#include "gap.h"
#include "auth.h"
#include "log.h"
#include "hdr.h"

/* * ASSERTION 1: 
 * Verify that the tunnel_payload_t structure follows a strictly packed layout.
 * We check if the offset of 'inner_data' matches the sum of all preceding headers:
 * Auth field + Ethernet header (14) + IP header (20) + UDP header (8).
 * This ensures no unexpected padding was inserted by the compiler.
 */
_Static_assert(offsetof(tunnel_payload_t, inner_data) == (GAP_AUTH_LEN + 14 + 20 + 8), 
               "tunnel_payload_t layout error: unexpected padding detected before inner_data");

/* * ASSERTION 2:
 * Verify that the GAP_PACKET_SIZE macro calculation is mathematically consistent.
 * When json_len is 0, the macro must exactly equal the memory offset from the 
 * start of tunnel_payload_t to the beginning of the flexible 'data' array.
 */
_Static_assert(GAP_PACKET_SIZE(0) == offsetof(tunnel_payload_t, inner_data) + 
                                       offsetof(tunnel_inner_payload_t, data),
               "GAP_PACKET_SIZE macro calculation mismatch with actual struct memory offset");

/* * ASSERTION 3:
 * Verify the internal alignment of the tunnel_inner_payload_t structure.
 * The 'data' flexible array must start immediately after the 'url' field.
 * Field sizes: dataLen(2) + num(1) + total(2) + rcpId(1) + method(GAP_METHOD_LEN) + url(GAP_URL_LEN).
 */
_Static_assert(offsetof(tunnel_inner_payload_t, data) == (2 + 1 + 2 + 1 + GAP_METHOD_LEN + GAP_URL_LEN),
               "tunnel_inner_payload_t layout error: unexpected padding detected before data");


#define GAP_FM_MAX_REASSEMBLY_SESSIONS     256
#define GAP_FM_MAX_JSON_SIZE               (64 * 1024) /* 64KB Max assembled size */
#define GAP_FM_SESSION_TIMEOUT_SEC         5           /* 5 seconds timeout */

typedef struct {
    uint8_t  rcpId;            /* Unique Session ID (Report ID) */
    uint16_t totalFragments;   /* Expected total number of fragments */
    uint16_t fragmentsArrived; /* Counter for received fragments */
    size_t   assembledSize;    /* Final total length of assembled data */
    uint8_t  *buffer;          /* Heap pointer for the JSON assembly buffer */
    uint8_t  method[6];        /* GAP_METHOD_LEN = 6 */
    uint8_t  url[128];         /* GAP_URL_LEN = 128 */
    time_t   last_seen;        /* Timestamp of last fragment (for timeout) */
    uint64_t arrivalMask;      /* CRITICAL: Tracks specific fragments to prevent duplicates */
    bool     isUsed;           /* Slot occupancy flag */
} reassembly_session_t;

static reassembly_session_t sessions[GAP_FM_MAX_REASSEMBLY_SESSIONS];
static uint8_t *global_buffer_pool = NULL;

/**
 * @struct pseudo_header
 * @brief Represents the UDP Pseudo Header used for checksum calculation.
 * * Defined in RFC 768 to ensure the UDP packet has reached the intended 
 * destination IP and protocol.
 */
struct pseudo_header {
    uint32_t source_address; // Source IPv4 address (Network Byte Order) 
    uint32_t dest_address;   // Destination IPv4 address (Network Byte Order)
    uint8_t  placeholder;    // Reserved byte, must be set to 0
    uint8_t  protocol;       // IP protocol ID (17 for UDP)
    uint16_t udp_length;     // UDP header length + Data length (Network Byte Order)
};

// extern struct server redserver;

/**
 * @brief Computes the IP/TCP/UDP Internet Checksum (RFC 1071).
 *
 * This implementation is "industrial-grade" because it addresses:
 * 1. Endianness Independence: Uses explicit byte-shifting to ensure identical 
 * results on both Little-Endian (x86/ARM) and Big-Endian (MIPS) systems.
 * 2. Alignment Safety: Accesses data via uint8_t pointers to prevent 
 * alignment-related exceptions (SIGBUS) on strict-alignment architectures.
 * 3. RFC Compliance: Correctly treats an odd-length trailing byte as the 
 * Most Significant Byte (MSB) of a 16-bit word.
 *
 * @param vdata  Pointer to the data buffer to be checksummed.
 * @param length Length of the data in bytes.
 * @return The 16-bit one's complement sum in network byte order.
 */
// static uint16_t gap_calculate_ip_checksum(const void *vdata, size_t length) {
//     const uint8_t *ptr = (const uint8_t *)vdata;
//     uint32_t sum = 0;

//     /* 1. Main loop: Process 16-bit words (2 bytes) at a time */
//     while (length > 1) {
//         /* * Manually reconstruct the 16-bit word in Network Byte Order (Big-Endian).
//          * This avoids host-endianness issues (e.g., swapping on x86).
//          */
//         sum += ((uint32_t)ptr[0] << 8) | (uint32_t)ptr[1];
//         ptr += 2;
//         length -= 2;
//     }

//     /* 2. Handle the remaining odd byte, if any */
//     if (length > 0) {
//         /* * RFC 1071: The last byte is treated as the high-order byte of a 
//          * 16-bit word, with the low-order byte padded with zeros.
//          */
//         sum += ((uint32_t)ptr[0] << 8);
//     }

//     /* 3. Fold the 32-bit sum into 16 bits */
//     /* * First fold: Add the carry bits (top 16 bits) to the lower 16 bits.
//      * For a maximum IPv4 packet size, the sum will not exceed 0x2FFFD.
//      */
//     sum = (sum >> 16) + (sum & 0xFFFF);
    
//     /* * Second fold: Add any carry generated by the previous addition.
//      */
//     sum += (sum >> 16);

//     /* 4. Take the one's complement and truncate to 16 bits */
//     /* The result is returned in a form suitable for network headers. */
//     return (uint16_t)~sum;
// }

static uint16_t gap_calculate_ip_checksum(void *vdata, size_t length) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)vdata;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length > 0) {
        sum += (*(uint8_t *)ptr);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

/**
 * @brief Calculates the UDP checksum including the IPv4 pseudo-header.
 * @param ip_hdr   Pointer to the prepared IP header.
 * @param udp_hdr  Pointer to the prepared UDP header.
 * @param data_len Length of the UDP payload (excluding the 8-byte UDP header).
 * @return 16-bit checksum in network byte order.
 */
static uint16_t gap_calculate_udp_checksum(struct iphdr *ip_hdr, struct udphdr *udp_hdr, size_t data_len) {
    struct pseudo_header psh;
    uint32_t sum = 0;
    uint16_t *ptr;
    int len;

    /* 1. Initialize Pseudo Header */
    psh.source_address = ip_hdr->saddr;
    psh.dest_address = ip_hdr->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    
    uint16_t udp_total_len = (uint16_t)(sizeof(struct udphdr) + data_len);
    psh.udp_length = htons(udp_total_len);

    /* 2. Sum Pseudo Header */
    ptr = (uint16_t *)&psh;
    for (len = sizeof(struct pseudo_header); len > 1; len -= 2) {
        sum += *ptr++;
    }

    /* 3. Sum UDP Header */
    ptr = (uint16_t *)udp_hdr;
    for (len = sizeof(struct udphdr); len > 1; len -= 2) {
        sum += *ptr++;
    }

    /* 4. Sum UDP Payload (InnerData + JSON) */
    ptr = (uint16_t *)((uint8_t *)udp_hdr + sizeof(struct udphdr));
    len = (int)data_len;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    /* FIX: Handle odd byte by shifting it to the upper 8 bits */
    if (len > 0) {
        sum += (uint16_t)(*(uint8_t *)ptr << 8);
    }

    /* 5. Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t result = (uint16_t)(~sum);

    /* FIX: RFC 768 requires result 0 to be transmitted as 0xFFFF */
    if (result == 0) {
        result = 0xFFFF;
    }

    return result;
}


/**
 * @brief Locates an existing session or allocates a new slot using Linear Probing.
 * @return Pointer to session slot, or NULL if pool is full/out-of-order.
 */
static reassembly_session_t* gap_find_session_slot(uint32_t rcpId, uint8_t num) {
    uint32_t start_idx = rcpId % GAP_FM_MAX_REASSEMBLY_SESSIONS;
    time_t now = time(NULL);

    for (uint32_t i = 0; i < GAP_FM_MAX_REASSEMBLY_SESSIONS; i++) {
        uint32_t curr = (start_idx + i) % GAP_FM_MAX_REASSEMBLY_SESSIONS;
        reassembly_session_t *s = &sessions[curr];

        /* 1. Logic for Stale Session Reclamation (Garbage Collection) */
        if (s->isUsed && (now - s->last_seen > GAP_FM_SESSION_TIMEOUT_SEC)) {
            s->isUsed = false;
        }

        /* 2. Match Existing Session */
        if (s->isUsed && s->rcpId == rcpId) {
            return s;
        }

        /* 3. Slot Assignment (Only permitted if first fragment arrives) */
        if (!s->isUsed && num == 1) {
            /* Keep the buffer pointer, reset everything else */
            uint8_t *saved_ptr = s->buffer;
            memset(s, 0, sizeof(reassembly_session_t));
            s->buffer = saved_ptr;

            s->rcpId = rcpId;
            s->isUsed = true;
            s->last_seen = now;
            return s;
        }
    }
    return NULL; 
}

/**
 * @brief Re-encapsulates the assembled buffer into a continuous tunnel_inner_payload_t.
 * @return Allocated pointer (Caller MUST free), or NULL.
 */
static inline tunnel_inner_payload_t* gap_pack_assembled_payload(const reassembly_session_t *s, size_t *out_len) {
    if (!s || !s->buffer) return NULL;

    size_t header_size = sizeof(tunnel_inner_payload_t);
    size_t total_size = header_size + s->assembledSize;

    /* Allocate one contiguous block for Header + Flexible Array Data */
    tunnel_inner_payload_t *pkt = (tunnel_inner_payload_t *)malloc(total_size);
    if (!pkt) return NULL;

    /* Fill Header with network byte order */
    pkt->dataLen = htons((uint16_t)s->assembledSize);
    pkt->num     = 1;          /* Now represents a single merged packet */
    pkt->total   = htons(1);   /* Total is now 1 */
    pkt->rcpId   = s->rcpId;
    
    /* Restore metadata from session */
    memcpy(pkt->method, s->method, 6);
    memcpy(pkt->url, s->url, 128);

    /* Copy actual JSON data into the flexible array member 'data[]' */
    memcpy(pkt->data, s->buffer, s->assembledSize);

    if (out_len) *out_len = total_size;
    return pkt;
}

/**
 * @brief Populates the IPv4 header fields.
 * * Note: Checksum is NOT calculated here. It must be called after 
 * the UDP header is finalized to ensure consistency.
 *
 * @param ip           Pointer to the IP header structure.
 * @param src_nbo      Source IP address (Network Byte Order).
 * @param dst_nbo      Destination IP address (Network Byte Order).
 * @param inner_size   Length of the tunneled payload.
 */
static void gap_fill_ip_header(struct iphdr *ip, uint32_t src_nbo, uint32_t dst_nbo, size_t inner_size) {
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    /* Total length = IP Header (20) + UDP Header (8) + Inner Data */
    ip->tot_len  = htons(GAP_IP_HDR_LEN + GAP_UDP_HDR_LEN + inner_size);
    ip->id       = 0;
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check    = 0; /* Must be 0 before calculation */
    ip->saddr    = src_nbo;
    ip->daddr    = dst_nbo;
}

/**
 * @brief Populates the UDP header fields.
 * * Note: Checksum is initialized to 0. The actual checksum calculation 
 * should be performed after the IP header fields are filled.
 *
 * @param udp          Pointer to the UDP header structure.
 * @param src_port     Source port (Host Order).
 * @param dst_port     Destination port (Host Order).
 * @param inner_size   Length of the tunneled payload.
 */
static void gap_fill_udp_header(struct udphdr *udp, uint16_t src_port, uint16_t dst_port, size_t inner_size) {
    udp->source = htons(src_port);
    udp->dest   = htons(dst_port);
    udp->len    = htons(GAP_UDP_HDR_LEN + inner_size);
    udp->check  = 0; /* Must be 0 before calculation */
}

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
) {
    if (!json_data || json_len == 0 ||
        !dst_mac || !src_mac ||
        !auth || !payloads_out || !num_payloads) {
        return -1;
    }

    // Calculate number of fragments
    size_t inner_header_len = offsetof(tunnel_inner_payload_t, data);
    if (GAP_MAX_FRAGMENT <= inner_header_len) {
        log_error("GAP_MAX_FRAGMENT (%zu) is too small to hold the header (%zu)", 
                (size_t)GAP_MAX_FRAGMENT, inner_header_len);
        return -1;
    }

    size_t max_per_frag = GAP_MAX_FRAGMENT - inner_header_len;
    if (max_per_frag <= 0) {
        log_error("Header size exceeds limit!");
        return -1;
    }

    /* Calculate fragmentation logic */
    size_t num_frags = (json_len + max_per_frag - 1) / max_per_frag;
    if (num_frags == 0) num_frags = 1;

    // Allocate output array
    tunnel_payload_t **payloads = calloc(num_frags, sizeof(tunnel_payload_t*));
    if (!payloads) {
        log_error("Failed to allocate payloads array");
        return -1;
    }

    size_t frag_idx = 0;
    size_t offset = 0;

    while (offset < json_len) {
        size_t inner_size;
        size_t header_size;
        size_t total_size;
        tunnel_payload_t *tp = NULL;
        tunnel_inner_payload_t *inner = NULL;
        struct udphdr *udp;
        struct iphdr *ip;
        size_t this_len = json_len - offset;

        if (this_len > max_per_frag) this_len = max_per_frag;

        // Calculate total packet size
        inner_size = offsetof(tunnel_inner_payload_t, data) + this_len;
        header_size = offsetof(tunnel_payload_t, inner_data);
        total_size = header_size + inner_size;

        tp = malloc(total_size);
        if (!tp) {
            log_error("Failed to allocate tunnel_payload_t for fragment %zu", frag_idx + 1);
            goto err;
        }
        memset(tp, 0, total_size);

        /* Fill Inner Business Data */
        inner = (tunnel_inner_payload_t *)tp->inner_data;
        inner->dataLen = htons((uint16_t)this_len);
        inner->num     = (uint8_t)(frag_idx + 1);
        inner->total   = htons((uint16_t)num_frags);
        inner->rcpId   = rcpId;

        if (method) {
            size_t m_len = strnlen(method, GAP_METHOD_LEN);
            memcpy(inner->method, method, m_len);
        }
        if (url) {
            size_t u_len = strnlen(url, GAP_URL_LEN);
            memcpy(inner->url, url, u_len);
        }
        memcpy(inner->data, json_data + offset, this_len);

        /* Fill Forged Ethernet Header (Direct binary memcpy) */
        memcpy(tp->ether_header, dst_mac, 6);
        memcpy(tp->ether_header + 6, src_mac, 6);
        tp->ether_header[12] = 0x08;
        tp->ether_header[13] = 0x00; // EtherType = IPv4     

        /* Fill Forged IP/UDP Headers (Using Binary IPs) */
        ip = (struct iphdr *)tp->ip_header;
        udp = (struct udphdr *)tp->udp_header;
        gap_fill_ip_header(ip, src_ip_nbo, dst_ip_nbo, inner_size);
        gap_fill_udp_header(udp, src_port, dst_port, inner_size);

        /* Checksum Calculations */
        udp->check = gap_calculate_udp_checksum(ip, udp, inner_size);
        ip->check = gap_calculate_ip_checksum(ip, ip->ihl * 4);

        /* Final Auth Field (8 bytes: Type/Len + Auth + CRC) */
        hdr_build((unsigned char *)tp, AUTH_DATA, total_size, auth);

        payloads[frag_idx] = tp;
        frag_idx++;
        offset += this_len;
    }

    *payloads_out = payloads;
    *num_payloads = num_frags;

    return 0;
err:
    if (payloads) {
        for (size_t i = 0; i < frag_idx; i++) {
            free(payloads[i]);
        }
        free(payloads);
    }
    if (payloads_out) *payloads_out = NULL;
    if (num_payloads) *num_payloads = 0;

    return -1;
}

/**
 * @brief Builds one or more tunneled packets for raw data with inner headers.
 * * This version fragments the data, preserves the rcpId from the original 
 * buffer, and prepends a tunnel_inner_payload_t to each fragment.
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
) {
    if (!data || len < sizeof(tunnel_inner_payload_t) || 
        !dst_mac || !src_mac || !auth || !payloads_out || !num_payloads) {
        return -1;
    }
    /* 2. Calculate fragmentation constraints */
    size_t inner_header_static_len = offsetof(tunnel_inner_payload_t, data);

    if (len < inner_header_static_len) return -1;

    size_t header_offset = offsetof(tunnel_payload_t, inner_data);

    /* 1. Extract rcpId from the original data header */
    /* Since the incoming 'data' contains tunnel_inner_payload_t info, we read the rcpId */
    tunnel_inner_payload_t *orig_inner = (tunnel_inner_payload_t *)data;
    
    /* GAP_MAX_FRAGMENT is the limit for (InnerHeader + RealData) */
    if (GAP_MAX_FRAGMENT <= inner_header_static_len) {
        log_error("gap_build_tunneled_packets_ex: GAP_MAX_FRAGMENT too small");
        return -1;
    }

    /* * The payload data to be fragmented starts after the static header of the input data.
     * We assume 'data' contains: [Static Inner Header] + [Actual Payload]
     */
    size_t total_payload_to_copy = len - inner_header_static_len;
    size_t max_data_per_frag = GAP_MAX_FRAGMENT - inner_header_static_len;
    
    size_t num_frags = (total_payload_to_copy + max_data_per_frag - 1) / max_data_per_frag;
    if (num_frags == 0) num_frags = 1;

    /* 3. Allocate output array */
    tunnel_payload_t **payloads = calloc(num_frags, sizeof(tunnel_payload_t*));
    if (!payloads) {
        log_error("gap_build_tunneled_packets_ex: calloc failed");
        return -1;
    }

    size_t frag_idx = 0;
    size_t current_offset = inner_header_static_len; // Start copying after the original static header

    /* 4. Fragmentation Loop */
    while (current_offset < len) {
        size_t this_data_len = len - current_offset;
        if (this_data_len > max_data_per_frag) {
            this_data_len = max_data_per_frag;
        }

        size_t inner_payload_total_size = inner_header_static_len + this_data_len;
        size_t total_alloc_size = header_offset + inner_payload_total_size;

        tunnel_payload_t *tp = malloc(total_alloc_size);
        if (!tp) {
            log_error("gap_build_tunneled_packets_ex: malloc failed at frag %zu", frag_idx);
            goto err;
        }
        memset(tp, 0, total_alloc_size);

        /* A. Fill tunnel_inner_payload_t */
        tunnel_inner_payload_t *inner = (tunnel_inner_payload_t *)tp->inner_data;
        inner->dataLen = htons((uint16_t)this_data_len);
        inner->num     = (uint8_t)(frag_idx + 1);
        inner->total   = htons((uint16_t)num_frags);
        inner->rcpId   = orig_inner->rcpId; // Use the extracted original rcpId

        /* Copy shared metadata (method, url) if your architecture requires it 
         * For raw data ex, we typically only need the headers and the payload. */
        memcpy(inner->method, orig_inner->method, GAP_METHOD_LEN);
        memcpy(inner->url, orig_inner->url, GAP_URL_LEN);
        /* Copy the actual payload chunk */
        memcpy(inner->data, data + current_offset, this_data_len);

        /* B. Fill Forged Ethernet Header */
        memcpy(tp->ether_header, dst_mac, 6);
        memcpy(tp->ether_header + 6, src_mac, 6);
        tp->ether_header[12] = 0x08;
        tp->ether_header[13] = 0x00; // IPv4

        /* C. Prepare IP and UDP headers */
        struct iphdr *ip = (struct iphdr *)tp->ip_header;
        struct udphdr *udp = (struct udphdr *)tp->udp_header;

        gap_fill_ip_header(ip, src_ip_nbo, dst_ip_nbo, inner_payload_total_size);
        gap_fill_udp_header(udp, src_port, dst_port, inner_payload_total_size);

        /* D. Checksums */
        udp->check = gap_calculate_udp_checksum(ip, udp, inner_payload_total_size);
        ip->check  = gap_calculate_ip_checksum(ip, ip->ihl * 4);

        /* E. Build Final Auth Header */
        hdr_build((unsigned char *)tp, AUTH_DATA, total_alloc_size, auth);

        payloads[frag_idx] = tp;
        frag_idx++;
        current_offset += this_data_len;
    }

    *payloads_out = payloads;
    *num_payloads = num_frags;

    return 0;

err:
    if (payloads) {
        for (size_t i = 0; i < frag_idx; i++) {
            if (payloads[i]) free(payloads[i]);
        }
        free(payloads);
    }
    *payloads_out = NULL;
    *num_payloads = 0;
    return -1;
}

/**
 * @brief Safely frees the payloads array and all contained tunnel_payload_t packets.
 * 
 * @param payloads Pointer to the array of tunnel_payload_t pointers.
 * @param num_payloads The number of packets in the array.
 */
void gap_free_tunneled_packets(tunnel_payload_t **payloads, size_t num_payloads) {
    if (!payloads) return;

    for (size_t i = 0; i < num_payloads; i++) {
        if (payloads[i]) {
            free(payloads[i]);
            payloads[i] = NULL;
        }
    }
    free(payloads);
}

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
 * @warning Caller must free() the returned pointer.
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
) {
    if (!dst_mac || !src_mac ||
        !auth || !packet_len) {
        log_error("gap_build_control_packet: invalid input parameters");
        return NULL;
    }

    size_t total_size;
    tunnel_payload_t *tp;
    struct iphdr *ip;
    struct udphdr *udp;

    // Calculate total size
    total_size = offsetof(tunnel_payload_t, inner_data) + real_len;

    tp = (tunnel_payload_t*)malloc(total_size);
    if (!tp) {
        return NULL;
    }
    memset(tp, 0, total_size);

    memcpy(tp->inner_data, real_data, real_len);

    // 1. Fill forged Ethernet header
    memcpy(tp->ether_header, dst_mac, 6);
    memcpy(tp->ether_header + 6, src_mac, 6);
    tp->ether_header[12] = 0x08;
    tp->ether_header[13] = 0x00;  // EtherType = IPv4

    ip = (struct iphdr *)tp->ip_header;
    udp = (struct udphdr *)tp->udp_header;

    /* Step 1: Fill Header Fields (No Checksums yet) */
    gap_fill_ip_header(ip, src_ip_nbo, dst_ip_nbo, real_len);
    gap_fill_udp_header(udp, src_port, dst_port, real_len);

    /* Step 2: Calculate UDP Checksum (Requires IP pseudo-header + UDP fields)
     * This matches your requirement: udp->check = 0; then calculate. */
    udp->check = gap_calculate_udp_checksum(ip, udp, real_len);

    /* Step 3: Calculate IP Checksum (Final step)
     * This matches your requirement: ip->check = 0; then calculate. */
    ip->check = gap_calculate_ip_checksum(ip, ip->ihl * 4);

    // Fill auth (first field)
    hdr_build((unsigned char *)tp, AUTH_DATA, total_size, auth);

    // Return the packet and its length
    *packet_len = total_size;

    return tp;
}

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
) {
    if (!dst_mac || !src_mac ||
        !auth || !packet_len) {
        log_error("gap_build_raise_packet: invalid input parameters");
        return NULL;
    }

    size_t total_size;
    tunnel_payload_t *tp;
    struct iphdr *ip;
    struct udphdr *udp;

    // Calculate total size
    total_size = offsetof(tunnel_payload_t, inner_data) + real_len;

    tp = (tunnel_payload_t*)malloc(total_size);
    if (!tp) {
        return NULL;
    }
    memset(tp, 0, total_size);

    memcpy(tp->inner_data, real_data, real_len);

    // 1. Fill forged Ethernet header
    memcpy(tp->ether_header, dst_mac, 6);
    memcpy(tp->ether_header + 6, src_mac, 6);
    tp->ether_header[12] = 0x08;
    tp->ether_header[13] = 0x56;  // EtherType = 0x0856 (custom for "raise" packets)

    ip = (struct iphdr *)tp->ip_header;
    udp = (struct udphdr *)tp->udp_header;

    /* Step 1: Fill Header Fields (No Checksums yet) */
    gap_fill_ip_header(ip, src_ip_nbo, dst_ip_nbo, real_len);
    gap_fill_udp_header(udp, src_port, dst_port, real_len);

    /* Step 2: Calculate UDP Checksum (Requires IP pseudo-header + UDP fields)
     * This matches your requirement: udp->check = 0; then calculate. */
    udp->check = gap_calculate_udp_checksum(ip, udp, real_len);

    /* Step 3: Calculate IP Checksum (Final step)
     * This matches your requirement: ip->check = 0; then calculate. */
    ip->check = gap_calculate_ip_checksum(ip, ip->ihl * 4);

    // Fill auth (first field)
    hdr_build((unsigned char *)tp, AUTH_DATA, total_size, auth);

    // Return the packet and its length
    *packet_len = total_size;

    return tp;
}

/**
 * @brief Creates a temporary socket and sends one or more tunnel_payload_t packets.
 * @param dst_ip  The physical destination IP of the next-hop gateway.
 * @param dst_port The physical destination UDP port (e.g., 52719).
 * @param payloads  Array of tunnel_payload_t pointers.
 * @param num_payloads Number of packets in the array.
 * @return 0 on success, -1 on failure.
 */
int gap_send_tunneled_to_target(
    const char *dst_ip,
    uint16_t dst_port,
    tunnel_payload_t **payloads,
    size_t num_payloads,
    udp_conn_t *conn
) {
    if (!dst_ip || !payloads || !conn || num_payloads == 0) {
        log_error("gap_send_tunneled_to_target: Invalid arguments");
        return -1;
    }

    /* 1. Create a temporary socket for this batch transmission */
    /* We don't need a high RCVBUF here as we are only sending */
    // udp_conn_t *conn = udp_init_listener(0, 1); // Port 0 for ephemeral port
    if (!conn) {
        log_error("Failed to initialize UDP sender");
        return -1;
    }

    /* 2. Iterate and send each payload */
    for (size_t i = 0; i < num_payloads; i++) {
        if (payloads[i] == NULL) continue;

        /* Calculate current fragment size: 
           Outer Headers + Inner Header + actual Fragment Data length */
        size_t total_packet_size = get_gap_packet_total_size(payloads[i]);

        /* 3. Use the encapsulated send function */
        ssize_t sent_bytes = udp_send_raw(conn, dst_ip, dst_port, 
                                          payloads[i], total_packet_size);

        if (sent_bytes < 0) {
            log_error("Send failed at fragment %zu/%zu: %s", i + 1, num_payloads, strerror(errno));
            // udp_close(conn);
            return -1;
        }

        log_debug("Successfully sent fragment %zu/%zu (%zd bytes) to %s:%u", 
                  i + 1, num_payloads, sent_bytes, dst_ip, dst_port);
    }

    /* 4. Cleanup socket */
    // udp_close(conn);
    return 0;
}

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
void gap_raw_send_to_target(const char *if_name, tunnel_payload_t **packets, size_t num) {
    if (!if_name || !packets || num == 0) {
        return;
    }

    /* 1. Open the raw socket context (optimized setup) */
    raw_sock_t *ctx = raw_sock_open(if_name);
    if (!ctx) {
        fprintf(stderr, "gap_raw_send_to_target: Failed to open raw socket on %s\n", if_name);
        return;
    }

    /* 2. Loop through the packet array */
    for (size_t i = 0; i < num; i++) {
        if (!packets[i]) continue;

        /* Calculate the actual data length of this specific fragment.
         * Total Length = Fixed Header Size + Dynamic JSON Size.
         * inner_data is a flexible array member, so we cast it to access dataLen. */
        tunnel_inner_payload_t *inner = (tunnel_inner_payload_t *)packets[i]->inner_data;
        
        /* Note: dataLen is in Network Byte Order in the struct */
        uint16_t json_len = ntohs(inner->dataLen);

        /* Full length to send: 
         * sizeof(tunnel_payload_t) includes auth, ether, ip, and udp headers.
         * sizeof(tunnel_inner_payload_t) includes the inner metadata headers.
         * json_len is the variable part. */
        size_t total_send_len = GAP_PACKET_SIZE(json_len);

        /* 3. Use the generic send interface.
         * We pass packets[i]->ether_header as the destination hint for sockaddr_ll. */
        ssize_t result = raw_sock_send(
            ctx, 
            packets[i]->ether_header, 
            packets[i]->ether_header, 
            total_send_len - GAP_AUTH_LEN
        );

        if (result < 0) {
            fprintf(stderr, "gap_raw_send_to_target: Failed to send fragment %zu/%zu: %s\n", 
                    i + 1, num, strerror(errno));
        }
    }

    /* 4. Close the socket to release system resources */
    raw_sock_close(ctx);
}

/**
 * @brief Unpacks the tunneled packet received from the Black Zone.
 * @param tunnel_buf    [In]  Raw buffer received from the UDP socket.
 * @param tunnel_len    [In]  Total length of the received buffer.
 * @param proxy_port    [Out] Extracted inner proxy port for NAT lookup.
 * @param business_data [Out] Pointer to the actual JSON business data.
 * @param business_len  [Out] Length of the JSON business data.
 * @return int 0 on success, 1 on format not payload data, -1 on length mismatch.
 */
int gap_unpack_packets(unsigned char *tunnel_buf, size_t tunnel_len, 
                       uint16_t *proxy_port, 
                       unsigned char **business_data, size_t *business_len) {
    
    /* 1. Basic length check for the outer tunnel structure */
    if (tunnel_len < sizeof(tunnel_payload_t)) {
        return -1;
    }

    /* 2. Map to the outer tunnel structure */
    tunnel_payload_t *payload = (tunnel_payload_t *)tunnel_buf;

    /* 3. Extract the Proxy Port from the forged UDP header.
     * On the return path, the 'dest port' identifies the original terminal. */
    struct udphdr *inner_udp = (struct udphdr *)(payload->udp_header);
    *proxy_port = ntohs(inner_udp->dest); 

    /* 4. Calculate the start of the raw inner data.
     * Since 'inner_data' is a flexible array in tunnel_payload_t,
     * it points exactly to the byte following the udp_header. */
    *business_data = payload->inner_data;

    /* 5. Calculate business data length.
     * It is the total length minus the size of the tunnel headers. */
    *business_len = tunnel_len - sizeof(tunnel_payload_t);

    /* 6. Validate there is actually data present */
    if (*business_len == 0) {
        return 1; 
    }

    return 0;
}

/**
 * @brief Reassembles tunnel fragments into a complete JSON buffer using a memory pool.
 * @param frag Pointer to the incoming fragment structure.
 * @param out_full_size Output parameter for the total assembled length of the final packet.
 * @return Pointer to the newly allocated complete packet (Caller MUST free), or NULL if incomplete.
 */
uint8_t* gap_assemble_tunnel_payload(const tunnel_inner_payload_t *frag, size_t *out_full_size) {
    if (!frag || !out_full_size) return NULL;

    uint8_t  id       = frag->rcpId;
    uint16_t total    = ntohs(frag->total);
    uint16_t frag_len = ntohs(frag->dataLen);
    uint8_t  num      = frag->num; /* 1-based index */
    time_t   now      = time(NULL);

    if (num == 0 || num > total || total > 64 || frag_len > GAP_MAX_FRAGMENT) {
        return NULL;
    }

    /* Direct access to the session slot in the pre-allocated pool */
    reassembly_session_t *s = &sessions[id];

    /* --- 1. Timeout & Stale Session Cleanup --- */
    if (s->isUsed) {
        if ((now - s->last_seen > GAP_FM_SESSION_TIMEOUT_SEC) || (num == 1)) {
            s->isUsed = false;
        }
    }

    /* --- 2. Session Initialization or Reset Logic --- */
    if (num == 1) {
        /* Force reset the pool segment for a new sequence. 
         * Using memset here ensures no data contamination from previous sessions.
         */
        memset(s->buffer, 0, GAP_FM_MAX_JSON_SIZE);

        s->rcpId = id;
        s->totalFragments = total;
        s->fragmentsArrived = 0;
        s->assembledSize = 0;
        s->arrivalMask = 0;
        s->isUsed = true;

        /* Store metadata required for final re-packaging */
        memcpy(s->method, frag->method, 6);
        memcpy(s->url, frag->url, 128);
    } else {
        /* Drop fragments if the session hasn't been started by fragment #1 */
        if (!s->isUsed) {
            return NULL; 
        }
    }

    uint64_t bit = (1ULL << (num - 1));
    if (s->arrivalMask & bit) {
        return NULL;
    }

    /* --- 3. Offset Calculation & Boundary Check --- */
    size_t offset = (size_t)(num - 1) * GAP_MAX_FRAGMENT;

    if (offset + frag_len > GAP_FM_MAX_JSON_SIZE) {
        s->isUsed = false;
        return NULL; /* Overflow protection */
    }

    /* --- 4. Data Placement --- */
    memcpy(s->buffer + offset, frag->data, frag_len);
    s->arrivalMask |= bit;
    s->fragmentsArrived++;
    s->last_seen = now;
    
    /* Track the actual logical size of the assembled JSON */
    if (offset + frag_len > s->assembledSize) {
        s->assembledSize = offset + frag_len;
    }

    /* --- 5. Completion Check --- */
    if (s->fragmentsArrived == s->totalFragments) {
        uint64_t expected_mask = (total == 64) ? ~0ULL : (1ULL << total) - 1;
        if (s->arrivalMask != expected_mask) {
            return NULL;
        }

        /* Pack the assembled pool data into a standalone packet.
         * gap_pack_assembled_payload performs the final malloc.
         */
        uint8_t *final_pkt = (uint8_t *)gap_pack_assembled_payload(s, out_full_size);
        
        /* Session is done. We don't free s->buffer because it belongs to the pool,
         * we just mark the slot as unused.
         */
        s->isUsed = false;

        return (uint8_t *)final_pkt;
    }
    log_debug("Waiting for more fragments");
    return NULL; /* Waiting for more fragments */
}

void gap_assemble_free_packet(uint8_t *complete_pkt) {
    if (complete_pkt) {
        free(complete_pkt);
    }
}

/**
 * @brief Initializes the global memory pool for fragment reassembly.
 * @return 0 on success, -1 on allocation failure.
 */
int gap_assemble_init(void) {
    /* Allocate 16MB (256 * 64KB) contiguously; calloc ensures a clean start */
    global_buffer_pool = (uint8_t *)calloc(GAP_FM_MAX_REASSEMBLY_SESSIONS, GAP_FM_MAX_JSON_SIZE);
    if (!global_buffer_pool) {
        return -1;
    }

    for (int i = 0; i < GAP_FM_MAX_REASSEMBLY_SESSIONS; i++) {
        /* Map each session to a fixed 64KB offset within the pool */
        sessions[i].buffer = global_buffer_pool + (i * GAP_FM_MAX_JSON_SIZE);
        
        /* Reset state and bind index to rcpId */
        sessions[i].isUsed = false;
        sessions[i].rcpId  = (uint8_t)i; 
        sessions[i].fragmentsArrived = 0;
        sessions[i].assembledSize = 0;
        sessions[i].arrivalMask = 0;
    }
    
    return 0;
}

void gap_assemble_destroy(void) {
    if (global_buffer_pool) {
        free(global_buffer_pool);
        global_buffer_pool = NULL;
    }

    for (int i = 0; i < GAP_FM_MAX_REASSEMBLY_SESSIONS; i++) {
        sessions[i].buffer = NULL;
        sessions[i].isUsed = false;
    }
    log_info("Fragment reassembly system shutdown: JSON assembly memory pool released.");
}

/**
 * @brief Periodically scans and cleans up expired reassembly sessions.
 * This should be called by a timer or the main loop to prevent "zombie" sessions
 * from occupying the pool slots indefinitely.
 */
void gap_assemble_cleanup(void *user_data) {
    (void)user_data;

    time_t now = time(NULL);
    int cleaned_count = 0;

    for (int i = 0; i < GAP_FM_MAX_REASSEMBLY_SESSIONS; i++) {
        /* If the slot is in use and exceeds the timeout threshold */
        if (sessions[i].isUsed && (now - sessions[i].last_seen > GAP_FM_SESSION_TIMEOUT_SEC)) {
            sessions[i].isUsed = false;
            sessions[i].fragmentsArrived = 0;
            sessions[i].assembledSize = 0;
            sessions[i].arrivalMask = 0;
            /* Note: We don't need to memset here; num == 1 will do it later. */
            cleaned_count++;
        }
    }

    if (cleaned_count > 0) {
        log_debug("Reassembly Maintenance: Cleaned up %d stale sessions.", cleaned_count);
    }
}