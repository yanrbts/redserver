/*
 * Packet Parser Implementation
 * Copyright (c) 2026, Red LRM.
 * Author: [yanruibing]
 */
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdatomic.h>

#include "util.h"
#include "log.h"
#include "xdp_pkt_parser.h"
#include "cmdengine.h"
#include "pktpcap.h"
#include "hdr.h"
#include "gateway.h"
#include "redgw.h"

/* Standard IPv4 Fragmentation Masks (RFC 791) */
#define IP_MF_FLAG              0x2000                              /* More Fragments flag */
#define IP_OFFSET_MASK          0x1FFF                              /* Fragment Offset mask (13 bits) */
#define MAX_REASM_SLOTS         1024
#define MAX_IP_PKT_SIZE         65535
#define FRAG_UNIT               8                                   /* IP fragments are in 8-byte blocks */
#define BITMAP_U64_COUNT        (MAX_IP_PKT_SIZE / FRAG_UNIT / 64)

/* Parse Result Codes */
enum parse_result {
    PARSE_OK             =  0,
    PARSE_FRAG_IN_PROG   =  1,   /* Fragment cached, datagram incomplete */
    PARSE_ERR_L2_TYPE    = -1,   /* Not an IPv4 packet */
    PARSE_ERR_L3_SHORT   = -2,   /* IP header malformed/truncated */
    PARSE_ERR_REASM      = -3,   /* Reassembly error or overflow */
    PARSE_ERR_L4_TRUNC   = -4    /* L4 header smaller than expected */
};

/**
 * @brief Rate-limited logging macro
 * @param interval  Seconds between log resets
 * @param max_count Maximum logs allowed within that interval
 */
#define LOG_WARN_RATELIMITED(interval, max_count, fmt, ...) do {                        \
    static time_t last_reset = 0;                                                       \
    static int current_logs = 0;                                                        \
    time_t now = time(NULL);                                                            \
                                                                                        \
    if (now - last_reset >= (interval)) {                                               \
        last_reset = now;                                                               \
        current_logs = 0;                                                               \
    }                                                                                   \
                                                                                        \
    if (current_logs < (max_count)) {                                                   \
        log_warn(fmt, ##__VA_ARGS__);                                                   \
        current_logs++;                                                                 \
    } else if (current_logs == (max_count)) {                                           \
        log_warn("Log limit reached for this interval, silencing further output...");   \
        current_logs++;                                                                 \
    }                                                                                   \
} while(0)

static const uint16_t xdp_eng_port_maps[] = {
    PKT_OPE_SRC_PORT,
    PKT_CTRL_SRC_PORT,
    PKT_ADD_PORT
};
#define ENG_MAP_SIZE (sizeof(xdp_eng_port_maps) / sizeof(xdp_eng_port_maps[0]))

/**
 * @brief Zero-argument overhead port validator against the static registry.
 * @details Since the mapping matrix is immutable and aligned at compile time,
 * the compiler frequently unrolls this loop into a direct unbranched register compare tree.
 * @param target_port Host byte-order port harvested from the incoming inner frame.
 * @return 1 if matched, 0 otherwise.
 */
static inline int pkt_is_engine_port(uint16_t target_port) {
    /* Loop unrolling automatically takes over due to fixed ENG_MAP_SIZE bound */
    for (size_t i = 0; i < ENG_MAP_SIZE; i++) {
        if (xdp_eng_port_maps[i] == target_port) {
            return 1; /* Hit target bound, hot exit */
        }
    }
    return 0;
}

/* Cold Data: The actual large buffer for reassembly */
typedef struct {
    uint8_t  data[MAX_IP_PKT_SIZE];
} reasm_buf_t;

/* Hot Data: Metadata used for hash lookup and state tracking */
typedef struct {
    reasm_buf_t *buffer;            /* 8 bytes */
    uint64_t    last_seen;          /* 8 bytes */
    uint32_t    src_ip;             /* 4 bytes */
    uint32_t    dst_ip;             /* 4 bytes */
    uint32_t    expected_total_len; /* 4 bytes */
    uint16_t    ip_id;              /* 2 bytes */
    uint8_t     proto;              /* 1 byte  */
    bool        is_active;          /* 1 byte  */
    bool        header_received;    /* 1 byte  Offset 0 received*/
    bool        last_frag_received; /* 1 byte  MF=0 received */
    uint64_t    bitmap[BITMAP_U64_COUNT]; 
} __attribute__((aligned(64))) reasm_slot_t;

/* Reassembly Statistics 
 * Aligned to 64 bytes to prevent Cache Line bouncing between CPU cores.
 */
typedef struct {
    uint64_t reasm_overlap_drops;   /* Overlapping fragments (potential attacks) */
    uint64_t reasm_timeout_counts;  /* Expired slots reclaimed */
    uint64_t reasm_oob_errors;      /* Fragments exceeding MAX_IP_PKT_SIZE */
    uint64_t reasm_completed;       /* Successfully reassembled datagrams */
} __attribute__((aligned(64))) reasm_stats_t;

static reasm_slot_t reasm_table[MAX_REASM_SLOTS];
static reasm_buf_t  data_pool[MAX_REASM_SLOTS];
static reasm_stats_t global_stats;

/**
 * @brief Locates or allocates a reassembly slot for an IPv4 datagram.
 * This function uses a hash-based lookup with a limited linear probe (up to 8 slots)
 * to find an existing reassembly session or claim an expired/inactive one.
 * @param ip Pointer to the IPv4 header of the current fragment.
 * @return reasm_slot_t* Pointer to the assigned slot, or NULL if the table is full.
 */
static reasm_slot_t* xdp_get_reasm_slot(const struct iphdr *ip) {
    uint16_t id_h = ntohs(ip->id);
    /* Generate a simple hash using the IPv4 4-tuple (Src, Dst, ID, Proto) */
    uint32_t hash = (ip->saddr ^ ip->daddr ^ id_h ^ ip->protocol) % MAX_REASM_SLOTS;
    uint64_t now = get_now_ms();

    /* Linear probing: check the primary hash bucket and the next 7 adjacent slots */
    for (int i = 0; i < 8; i++) {
        reasm_slot_t *slot = &reasm_table[(hash + i) % MAX_REASM_SLOTS];

        /* Check for an existing active session matching this fragment's 4-tuple */
        if (slot->is_active && slot->ip_id == id_h && slot->src_ip == ip->saddr) {
            slot->last_seen = now; // Update timestamp to prevent premature expiration
            return slot;
        }

        /* * Slot Acquisition Logic:
         * 1. If the slot is inactive, it's free for use.
         * 2. If the slot is active but hasn't been updated for > 2000ms, 
         * consider the reassembly failed/timed out and reclaim the slot.
         */
        if (!slot->is_active || (now - slot->last_seen > 2000)) {
            if (slot->is_active) {
                /* Increment timeout counter atomically */
                __sync_fetch_and_add(&global_stats.reasm_timeout_counts, 1);
            }
            /* Keep buf_ptr, reset everything else */
            reasm_buf_t *saved_buf = slot->buffer;
            /* Initialize/Reset the slot for a new datagram */
            memset(slot, 0, sizeof(reasm_slot_t));
            
            slot->buffer   = saved_buf;
            slot->src_ip   = ip->saddr;
            slot->dst_ip   = ip->daddr;
            slot->ip_id    = id_h;
            slot->proto    = ip->protocol;
            slot->is_active = true;
            slot->last_seen = now;
            
            return slot;
        }
    }

    /* Return NULL if no matching or available slot is found within the probe limit */
    return NULL;
}

/**
 * Tracks fragment spans and detects parallel skb_clone twins.
 * @bitmap:        Pointer to the connection slot bit-array.
 * @offset:        Fragment offset in bytes.
 * @len:           Length of the fragment payload in bytes.
 * @is_clone:      [Out] Evaluated true if packet is a strict physical mirror.
 * * Return: True if an erratic, asymmetrical overlapping attack/anomaly is found.
 * False if the range is successfully registered or identified as a clean clone.
 */
static inline bool set_bitmap_range(uint64_t *bitmap, uint32_t offset, uint32_t len, bool *is_clone) {
    /* 8-byte alignment granularity constraint (FRAG_UNIT = 8) */
    uint32_t start_bit = offset >> 3;
    uint32_t num_bits  = (len + 7) >> 3;
    
    if (unlikely(num_bits == 0)) {
        if (is_clone) *is_clone = false;
        return false;
    }

    uint32_t end_bit   = start_bit + num_bits;
    uint32_t start_idx = start_bit / 64;
    uint32_t end_idx   = (end_bit - 1) / 64;

    /* Fail-safe out-of-bounds containment */
    if (unlikely(end_idx >= BITMAP_U64_COUNT)) {
        return true; 
    }

    if (is_clone) *is_clone = false;

    bool has_new_bits = false;
    bool has_old_bits = false;

    /* Loop through affected u64 array blocks instead of stepping bit-by-bit */
    for (uint32_t idx = start_idx; idx <= end_idx; idx++) {
        uint32_t bit_s = (idx == start_idx) ? (start_bit % 64) : 0;
        uint32_t bit_e = (idx == end_idx) ? ((end_bit - 1) % 64) : 63;

        /* Formulate a precise fast execution block bit-mask for the span range */
        uint64_t mask = (~0ULL >> (63 - (bit_e - bit_s))) << bit_s;
        uint64_t current_val = bitmap[idx];

        if ((current_val & mask) != 0) {
            has_old_bits = true;
        }
        if ((current_val & mask) != mask) {
            has_new_bits = true;
        }
    }

    /* Evaluate network tracking state based on bit intersection */
    if (unlikely(has_old_bits)) {
        /* Condition A: Perfect overlapping match -> Promiscuous mode skb_clone mirror */
        if (!has_new_bits) {
            if (is_clone) *is_clone = true;
            return false; 
        }
        /* Condition B: Partial intersection -> Asymmetric overlap attack vector detected */
        return true; 
    }

    /* Happy Path: Commit non-allocating bitmask write states directly to the slot registry */
    for (uint32_t idx = start_idx; idx <= end_idx; idx++) {
        uint32_t bit_s = (idx == start_idx) ? (start_bit % 64) : 0;
        uint32_t bit_e = (idx == end_idx) ? ((end_bit - 1) % 64) : 63;
        uint64_t mask = (~0ULL >> (63 - (bit_e - bit_s))) << bit_s;
        
        bitmap[idx] |= mask;
    }

    return false;
}

/* Helper to check if all bits up to total_len are set */
static inline bool is_bitmap_complete(uint64_t *bitmap, uint32_t total_len) {
    uint32_t total_bits = (total_len + FRAG_UNIT - 1) / FRAG_UNIT;
    uint32_t full_bytes = total_bits / 64;
    uint8_t remaining_bits = total_bits % 64;
    
    for (uint32_t i = 0; i < full_bytes; i++) {
        if (bitmap[i] != 0xFFFFFFFFFFFFFFFFULL) return false;
    }
    
    if (remaining_bits > 0) {
        uint64_t mask = (1ULL << remaining_bits) - 1;
        if ((bitmap[full_bytes] & mask) != mask) return false;
    }
    return true;
}

/**
 * Performs stateful lockless reassembly of fragmented IP packets.
 * @data:   Pointer to the start of the raw Ethernet frame buffer.
 * @len:    Total length of the received link-layer frame.
 * @info:   Output structure populated with payload pointers upon complete reassembly.
 *
 * Return:  1  = Assembly complete; payload ready for next-stage processing.
 * 0  = Fragment processed successfully, awaiting outstanding sequences.
 * -1  = Error encountered (OOB, overlap anomaly, or structural breach).
 */
int xdp_do_reasm(const uint8_t *data, size_t len, pkt_info_t *info) {
    (void)len;

    const uint64_t now = get_now_ms();
    const struct iphdr *ip = (const struct iphdr *)(data + ETH_HLEN);
    
    const uint16_t f_off_raw = ntohs(ip->frag_off);
    const uint32_t offset = (f_off_raw & IP_OFFSET_MASK) << 3; /* Multiplied by 8 */
    const bool mf = !!(f_off_raw & IP_MF_FLAG);
    
    const uint32_t ip_hdr_len = ip->ihl << 2; /* Multiplied by 4 */
    const uint32_t p_len = ntohs(ip->tot_len) - ip_hdr_len;

    /* Out-of-bounds sanity constraint to block memory layout manipulation vulnerabilities */
    if (unlikely(offset + p_len > MAX_IP_PKT_SIZE)) {
        __atomic_fetch_add(&global_stats.reasm_oob_errors, 1, __ATOMIC_RELAXED);
        return -1;
    }

    /* Retrieve or pre-emptively acquire a concurrent slot hash bucket reference */
    reasm_slot_t *slot = xdp_get_reasm_slot(ip);
    if (unlikely(!slot)) {
        return -1; 
    }

    /* Track boundary fragment sequences and cache structural metadata */
    if (offset == 0) {
        slot->header_received = true;
    }
    if (!mf) {
        slot->last_frag_received = true;
        slot->expected_total_len = offset + p_len;
    }

    /* Process fragment span bitmask array mapping and detect layout overlap anomalies */
    bool is_clone  = false;
    bool __overlap = set_bitmap_range(slot->bitmap, offset, p_len, &is_clone);
    
    if (unlikely(__overlap)) {
        __atomic_fetch_add(&global_stats.reasm_overlap_drops, 1, __ATOMIC_RELAXED);
        LOG_WARN_RATELIMITED(5, 1, "[SECURITY] Overlapping fragment detected! ID:%u, Off:%u", 
                             ntohs(ip->id), offset);
        
        /* Force-deactivate contaminated slot architecture to prevent Teardrop style state exhaustion */
        __atomic_store_n(&slot->is_active, false, __ATOMIC_RELEASE);
        return -1;
    }

    /* Intercept promiscuous mode skb_clone mirror twins without repeating payload copies */
    if (unlikely(is_clone)) {
        /* Short-circuit evaluation: Only verify bitmask completeness if boundary flags match */
        if (slot->header_received && slot->last_frag_received) {
            if (is_bitmap_complete(slot->bitmap, slot->expected_total_len)) {
                goto package_complete;
            }
        }
        return 0; 
    }

    /* Commit clean, non-overlapping fragment segments to sequential staging buffer memory */
    if (likely(slot->buffer && slot->buffer->data)) {
        memcpy(slot->buffer->data + offset, (const uint8_t *)ip + ip_hdr_len, p_len);
    }

    /* Update cache coherence tracking state timestamp */
    __atomic_store_n(&slot->last_seen, now, __ATOMIC_RELEASE);

    /* Verify if all sequence ranges have closed the allocation window successfully */
    if (slot->header_received && slot->last_frag_received) {
        if (is_bitmap_complete(slot->bitmap, slot->expected_total_len)) {
            
package_complete:
            __atomic_fetch_add(&global_stats.reasm_completed, 1, __ATOMIC_RELAXED);

            /* Bind the contiguous linear packet storage buffer to the exit protocol parser */
            info->payload     = slot->buffer->data;
            info->payload_len = slot->expected_total_len;
            
            /* Clear connection tuple fingerprints without releasing slot activation token.
             * This provides a temporal structural shield against trailing duplicate bursts. */
            slot->ip_id              = 0; 
            slot->src_ip             = 0;
            slot->header_received    = false;
            slot->last_frag_received = false;
            slot->expected_total_len = 0;
            
            memset((void *)slot->bitmap, 0, sizeof(uint64_t) * BITMAP_U64_COUNT);
            
            /* Synchronize state barrier modifications before returning slot control safely */
            __atomic_store_n(&slot->last_seen, now, __ATOMIC_RELEASE);

            /* Update framework management plane interface statistics counter telemetry */
            cmd_reass_stats_add(
                global_stats.reasm_completed, 
                global_stats.reasm_timeout_counts,                      
                global_stats.reasm_oob_errors,
                global_stats.reasm_overlap_drops
            );
            return 1; 
        }
    }

    /**
     * Industrial Policy: Increment the reassembly stats counter for successful completions.
     * This allows operators to monitor the frequency of fragment reassembly, which can be
     * an indicator of certain types of network activity or attacks.
     */
    cmd_reass_stats_add(
        global_stats.reasm_completed, 
        global_stats.reasm_timeout_counts,                      
        global_stats.reasm_oob_errors,
        global_stats.reasm_overlap_drops
    );

    return 0; 
}

int xdp_pkt_parse_all(const uint8_t *data, size_t len, pkt_info_t *info) {
    /* --- 0. Initial Boundary Check --- */
    if (unlikely(!data || !info || len < ETH_HLEN + sizeof(struct iphdr))) {
        return PARSE_ERR_L3_SHORT;
    }

    memset(info, 0, sizeof(pkt_info_t));
    const uint8_t *data_end = data + len;

    /* --- 1. Layer 2 (Ethernet) Parsing --- */
    struct ethhdr *eth = (struct ethhdr *)data;

    memcpy(info->eth.src, eth->h_source, 6);
    memcpy(info->eth.dst, eth->h_dest, 6);
    info->eth.proto = ntohs(eth->h_proto);

    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return PARSE_ERR_L2_TYPE;
    }

    /* --- 2. Layer 3 (IPv4) Parsing --- */
    struct iphdr *ip = (struct iphdr *)(data + ETH_HLEN);
    uint32_t ip_hdr_len = ip->ihl * 4;
    
    /* Strict IHL and buffer boundary validation */
    if (unlikely(ip->ihl < 5 || (uint8_t *)ip + ip_hdr_len > data_end)) {
        return PARSE_ERR_L3_SHORT;
    }

    info->ip.src_ip   = ip->saddr;
    info->ip.dst_ip   = ip->daddr;
    info->ip.proto    = ip->protocol;
    info->ip.id       = ntohs(ip->id);
    uint16_t f_off_raw = ntohs(ip->frag_off);
    
    /* Check for More Fragments (MF) bit or non-zero Fragment Offset */
    info->ip.is_fragment = !!(f_off_raw & (IP_MF_FLAG | IP_OFFSET_MASK));

    const uint8_t *l4_ptr = NULL;
    size_t l4_len = 0;

    /* --- 3. Fragmentation Branch --- */
    if (info->ip.is_fragment) {
        int res = xdp_do_reasm(data, len, info);
        if (res != 1) {
            return (res == 0) ? PARSE_FRAG_IN_PROG : PARSE_ERR_REASM;
        }
        /* info->payload/len are already set by xdp_do_reasm to point to slot buffer */
        l4_ptr = info->payload;
        l4_len = info->payload_len;
    } else {
        /* Standard Packet: Use IP Total Length for precise payload calculation */
        uint32_t ip_tot_len = ntohs(ip->tot_len);
        if (unlikely(ip_tot_len < ip_hdr_len || (uint8_t *)ip + ip_tot_len > data_end)) {
            return PARSE_ERR_L3_SHORT;
        }
        l4_ptr = (uint8_t *)ip + ip_hdr_len;
        l4_len = ip_tot_len - ip_hdr_len;
    }

    /* --- 4. Layer 4 (Transport) Unified Parsing --- */
    if (info->ip.proto == IPPROTO_UDP) {
        if (unlikely(l4_len < sizeof(struct udphdr))) return PARSE_ERR_L4_TRUNC;
        
        struct udphdr *udp = (struct udphdr *)l4_ptr;
        info->l4.src_port = ntohs(udp->source);
        info->l4.dst_port = ntohs(udp->dest);
        
        /* Payload starts after the 8-byte UDP header */
        info->payload     = (uint8_t *)udp + sizeof(struct udphdr);
        info->payload_len = l4_len - sizeof(struct udphdr);
    } 
    else if (info->ip.proto == IPPROTO_TCP) {
        if (unlikely(l4_len < sizeof(struct tcphdr))) return PARSE_ERR_L4_TRUNC;
        
        struct tcphdr *tcp = (struct tcphdr *)l4_ptr;
        uint32_t tcp_hdr_len = tcp->doff * 4;
        
        /* Validate TCP Data Offset (Header Length) */
        if (unlikely(tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > l4_len)) {
            return PARSE_ERR_L4_TRUNC;
        }

        info->l4.src_port = ntohs(tcp->source);
        info->l4.dst_port = ntohs(tcp->dest);
        
        /* Payload starts after variable TCP header length */
        info->payload     = (uint8_t *)tcp + tcp_hdr_len;
        info->payload_len = l4_len - tcp_hdr_len;
    } 
    else {
        /* Generic Protocol Support */
        info->payload     = l4_ptr;
        info->payload_len = l4_len;
    }

    return PARSE_OK; 
}

/* @brief Serialize pkt_info_t into a pure, native L2 ethernet frame.
 * @param pkt     Source parsed packet structure (read-only).
 * @param buf     Output buffer to hold the raw ethernet frame bytes.
 * @param max_len Capacity of the output buffer.
 * @return Total size of the native ethernet frame, or -1 on error.
 */
static ssize_t xdp_pkt_to_buf(const pkt_info_t *pkt, uint8_t *buf, size_t max_len) {
    size_t l4_len, tot_len;
    uint8_t *p;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    if (!pkt || !buf) return -1;

    /* Calculate inner layer 4 payload size (UDP vs TCP/Others) */
    l4_len = (pkt->ip.proto == IPPROTO_UDP) ? (8U + pkt->payload_len) : (20U + pkt->payload_len);
    
    /* Total size = Eth Header(14B) + IP Header(20B) + L4 Header & Payload */
    tot_len = 14U + 20U + l4_len;

    /* Safety boundary check */
    if (tot_len > max_len) return -1;

    p = buf;

    /* [Step 1] Reconstruct Layer 2: Ethernet Header */
    eth = (struct ethhdr *)p;
    memcpy(eth->h_source, pkt->eth.src, 6);
    memcpy(eth->h_dest, pkt->eth.dst, 6);
    eth->h_proto = htons(pkt->eth.proto);
    p += 14;

    /* [Step 2] Reconstruct Layer 3: IPv4 Header (Force Clear Slicing Flags) */
    ip = (struct iphdr *)p;
    ip->version = 4;
    ip->ihl = 5; /* Standard 20 bytes */
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)(20U + l4_len));
    ip->id = pkt->ip.id;
    
    /* Crucial: Wipe out fragment flags since this is now a fully reassembled single big packet */
    ip->frag_off = 0; 
    
    ip->ttl = pkt->ip.ttl;
    ip->protocol = pkt->ip.proto;
    ip->saddr = pkt->ip.src_ip;
    ip->daddr = pkt->ip.dst_ip;
    
    /* Recalculate pure L3 IP checksum */
    ip->check = 0;
    ip->check = ip_calculate_checksum((const uint16_t *)ip, 20);
    p += 20;

    /* [Step 3] Reconstruct Layer 4: Transport Header (UDP Branch) */
    if (pkt->ip.proto == IPPROTO_UDP) {
        udp = (struct udphdr *)p;
        udp->source = htons(pkt->l4.src_port);
        udp->dest = htons(pkt->l4.dst_port);
        udp->len = htons((uint16_t)(8U + pkt->payload_len));
        udp->check = 0; /* Clear L4 checksum for high-speed pass-through */
        p += 8;
    }

    /* [Step 4] Append raw application payload bytes */
    if (pkt->payload_len > 0 && pkt->payload) {
        memcpy(p, pkt->payload, pkt->payload_len);
    }

    /* Returns the absolute raw size of this structured Ethernet Frame */
    return (ssize_t)tot_len;
}

/**
 * @brief  Parses the inner encapsulated UDP destination port from a tunnel payload.
 * This function performs deep packet inspection (DPI) on the encapsulated traffic.
 * It strictly validates the IPv4 header and dynamically calculates offsets to 
 * handle variable IP options, ensuring memory safety against malformed packets.
 *
 * @param  payload      Pointer to the start of the tunnel payload (Auth Header).
 * @param  payload_len  Total size of the payload provided by the ring buffer.
 * @return uint16_t     Inner UDP destination port in Host Byte Order, or 0 if invalid.
 */
static inline uint16_t xdp_get_inner_dport(const uint8_t *payload, size_t payload_len) {
    /* 1. Initial boundary check: Must accommodate Auth(16) + Eth(14) + Min IPv4(20) */
    if (unlikely(payload_len < (HDR_SIZE + 14 + sizeof(struct iphdr)))) {
        return 0;
    }

    /* Jump to the start of the inner IP header */
    const uint8_t *ip_ptr = payload + HDR_SIZE + 14;

    /* 2. Protocol Validation: Verify IPv4 version and UDP protocol */
    // ip_ptr[0]: High 4 bits = Version, Low 4 bits = IHL (Internet Header Length)
    uint8_t ver_ihl = ip_ptr[0];
    if (unlikely((ver_ihl >> 4) != 4)) {
        return 0; // Not an IPv4 packet
    }
    
    // Check Protocol field (offset 9 in IPv4 header)
    if (unlikely(ip_ptr[9] != IPPROTO_UDP)) {
        return 0; // Not a UDP packet
    }

    /* 3. Calculate dynamic IP Header Length (IHL) 
     * IHL represents the number of 32-bit words. Multiply by 4 to get bytes. 
     */
    size_t ip_hl = (ver_ihl & 0x0F) * 4;
    
    /* 4. Secondary boundary check: Ensure buffer accommodates the UDP header (8 bytes) */
    // Offset = Auth + Ethernet + Variable IP Header Length
    size_t udp_offset = HDR_SIZE + 14 + ip_hl;
    if (unlikely(payload_len < (udp_offset + sizeof(struct udphdr)))) {
        return 0; // Malformed packet or truncated UDP header
    }

    /* 5. Extract Destination Port
     * UDP header structure: Source Port (2B), Destination Port (2B).
     * We use memcpy to prevent Unaligned Access exceptions on strict architectures.
     */
    uint16_t dport;
    memcpy(&dport, payload + udp_offset + 2, sizeof(uint16_t));
    
    /* Convert from Network Byte Order (Big-Endian) to Host Byte Order */
    return ntohs(dport);
}


static inline void xdp_decapsulated_packet(struct redgwserver *server_ctx, pkt_info_t *info, 
                                               const uint8_t *packet_data, size_t packet_len, 
                                               uint32_t ifindex) 
{
    if ((int)ifindex == server_ctx->dev1_index) {
        if (info->payload && info->payload_len >= (HDR_SIZE + 14)) {
            uint8_t *inner_base = (uint8_t *)info->payload;
            const struct ethhdr *inner_eth = (const struct ethhdr *)((const uint8_t *)info->payload + HDR_SIZE);
            uint16_t inner_eth_type = ntohs(inner_eth->h_proto);
            
            switch (inner_eth_type) {
                case PKT_TYPE_ENG: {
                    uint16_t inner_dport = xdp_get_inner_dport(inner_base, info->payload_len);
                    if (likely(pkt_is_engine_port(inner_dport))) {
                        log_info("BLACK --> RED : (%s) | ethtype: 0x%04X | inner_dport: %u | Length: %zu", 
                                 server_ctx->dev1, inner_eth_type, inner_dport, packet_len);
                        gw_send_to_client(packet_data, packet_len);
                    }
                    break;
                }
                case PKT_TYPE_PROBE:
                case PKT_TYPE_CTRL:
                    log_info("BLACK --> RED : (%s) | ethtype: 0x%04X | Length: %zu", server_ctx->dev1, inner_eth_type, packet_len);
                    gw_send_to_client(packet_data, packet_len);
                    break;
                default:
                    break;
            }
        }
    }
    
    if ((int)ifindex == server_ctx->dev2_index) {
        switch (info->l4.src_port) {
            case PKT_OPE_SRC_PORT:
            case PKT_CTRL_SRC_PORT:
            case PKT_ADD_PORT:
                if (likely(info->payload_len > 0)) {
                    log_info("RED --> BLACK : (%s) | ethtype: 0x%04X | src_port: %u | Length: %zu", 
                        server_ctx->dev2, info->eth.proto, info->l4.src_port, packet_len);
                    gw_send_to_core(packet_data, packet_len);
                }
                break;
            default:
                break;
        }
    }
}

int xdp_handle_ringbuf(void *ctx, const uint8_t *data, size_t data_sz, uint32_t ifindex) {
    if (unlikely(!data || data_sz == 0)) return 0;

    if (cmd_ispcap_enabled()) {
        pcap_mod_inject(data, data_sz);
    }

    gw_scope_begin();

    int ret;
    pkt_info_t info = {0};
    uint8_t *data_ptr = NULL;

    if (unlikely((ret = xdp_pkt_parse_all(data, data_sz, &info)) != 0)) {
        if (unlikely(ret == PARSE_ERR_REASM))
            log_error("xdp_pkt_parse_all error code: %d", ret);
        goto _out_cleanup;
    }

    if (info.ip.is_fragment) {
        size_t plen = HDR_SIZE + 42U + info.payload_len;
        uint8_t *reasm_buf = gw_alloc(plen);
        if (unlikely(!reasm_buf)) {
            log_error("OOM inside omni thread pool!");
            goto _out_cleanup;
        }

        data_ptr = reasm_buf + HDR_SIZE;
        ssize_t rc = xdp_pkt_to_buf(&info, data_ptr, plen - HDR_SIZE);
        if (unlikely(rc < 0)) {
            log_error("xdp_pkt_to_buf() failed return : %d", rc);
            goto _out_cleanup;
        }

        xdp_decapsulated_packet(ctx, &info, data_ptr, (size_t)rc, ifindex);
    } else {
        uint8_t *safe_buf = gw_alloc(data_sz + HDR_SIZE);
        if (unlikely(!safe_buf)) {
            log_error("OOM inside omni thread pool for fast-path packet!");
            goto _out_cleanup;
        }

        data_ptr = safe_buf + HDR_SIZE;
        memcpy(data_ptr, data, data_sz);
        xdp_decapsulated_packet(ctx, &info, data_ptr, data_sz, ifindex);
    }

_out_cleanup:
    gw_scope_exit();
    return 0;
}

/**
 * @brief Initializes the IP reassembly subsystem and binds metadata to buffers.
 * * This function performs a "Cold/Hot" memory split optimization:
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
void xdp_reasm_init(void) {
    /* Clear all metadata to ensure is_active starts as false and last_seen is 0 */
    memset(reasm_table, 0, sizeof(reasm_table));

    /* Establish the static link between Hot Metadata and Cold Buffers */
    for (int i = 0; i < MAX_REASM_SLOTS; i++) {
        reasm_table[i].buffer = &data_pool[i];
    }

    log_info("[REASM] Slots: %d, Metadata Size: %zu bytes, Buffer Pool: %zu MB", 
             MAX_REASM_SLOTS, sizeof(reasm_slot_t), 
             (sizeof(reasm_buf_t) * MAX_REASM_SLOTS) / 1024 / 1024);
}

void xdp_reasm_show_stats(void) {
    /* * Using __sync_val_compare_and_swap(ptr, 0, 0) is a common trick 
     * to perform an atomic load if you don't have C11 atomic_load.
     */
    uint64_t completed = __sync_val_compare_and_swap(&global_stats.reasm_completed, 0, 0);
    uint64_t overlap   = __sync_val_compare_and_swap(&global_stats.reasm_overlap_drops, 0, 0);
    uint64_t timeout   = __sync_val_compare_and_swap(&global_stats.reasm_timeout_counts, 0, 0);
    uint64_t oob       = __sync_val_compare_and_swap(&global_stats.reasm_oob_errors, 0, 0);

    log_info("--- IP Reassembly Statistics ---");
    log_info("  Completed:       %lu", completed);
    log_info("  Overlap Drops:   %lu (Security Alert!)", overlap);
    log_info("  Timeout Drops:   %lu", timeout);
    log_info("  OOB Errors:      %lu", oob);
    log_info("---------------------------------");
}

void xdp_pkt_dump_log(const pkt_info_t *info) {
    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &info->ip.src_ip, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &info->ip.dst_ip, d_ip, sizeof(d_ip));

    printf("[PKT] %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x | ",
           info->eth.src[0], info->eth.src[1], info->eth.src[2],
           info->eth.src[3], info->eth.src[4], info->eth.src[5],
           info->eth.dst[0], info->eth.dst[1], info->eth.dst[2],
           info->eth.dst[3], info->eth.dst[4], info->eth.dst[5]);

    printf("IPv4: %s:%u -> %s:%u [Proto:%d] [Len:%zu]\n",
           s_ip, info->l4.src_port, d_ip, info->l4.dst_port,
           info->ip.proto, info->payload_len);
}