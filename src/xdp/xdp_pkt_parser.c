/*
 * Packet Parser Implementation
 * Copyright (c) 2026, Red LRM.
 * Author: [yanruibing]
 */
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdatomic.h>
#include "util.h"
#include "gap.h"
#include "log.h"
// #include "xdp_receiver.h"
#include "xdp_pkt_parser.h"
#include "gcprobe.h"
#include "pkteng.h"
#include "cmdengine.h"

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

typedef bool (*xdp_eng_handler_t)(const pkt_info_t *info);
typedef struct {
    uint16_t port;
    xdp_eng_handler_t handler;
} xdp_port_handler_map_t;

static const xdp_port_handler_map_t xdp_eng_port_maps[] = {
    {PKT_OPE_SRC_PORT, pkt_reverse_ope_to_red},
    {PKT_CTRL_SRC_PORT, pkt_reverse_ctrl_to_red},
    {PKT_ADD_PORT, pkt_reverse_raise_to_red},
};
#define ENG_MAP_SIZE (sizeof(xdp_eng_port_maps) / sizeof(xdp_eng_port_maps[0]))

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
static reasm_slot_t* xdp_get_reasm_slot(struct iphdr *ip) {
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
 * @brief Checks and sets bits in the bitmap, detecting overlaps.
 * @return true if an overlap is detected, false otherwise.
 */
static inline bool set_bitmap_range(uint64_t *bitmap, uint32_t offset, uint32_t len) {
    uint32_t start_bit = offset / FRAG_UNIT;
    uint32_t num_bits = (len + FRAG_UNIT - 1) / FRAG_UNIT;
    bool overlap = false;

    for (uint32_t i = 0; i < num_bits; i++) {
        uint32_t bit = start_bit + i;
        uint32_t byte_idx = bit / 64;
        uint64_t bit_mask = (1ULL << (bit % 64));

        /* Detect if this block has already been filled */
        if (bitmap[byte_idx] & bit_mask) {
            overlap = true;
        }
        /* Mark the block as received */
        bitmap[byte_idx] |= bit_mask;
    }
    return overlap;
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
 * @brief Performs IPv4 fragment reassembly using a bitmap to track data continuity.
 * This function processes an individual IP fragment, copies it into a 
 * reassembly buffer, and marks the corresponding bits in a bitmap. 
 * Once the bitmap is fully filled (from Offset 0 to Expected Total Length), 
 * the datagram is considered complete.
 *
 * @param data Pointer to the raw packet (Ethernet header start).
 * @param len  Total length of the received frame.
 * @param info Pointer to the packet info structure to be populated upon success.
 * @return int 1 if reassembly is complete; 0 if still in progress; -1 on error.
 */
static int xdp_do_reasm(const uint8_t *data, size_t len, pkt_info_t *info) {
    (void)len;

    struct iphdr *ip = (struct iphdr *)(data + ETH_HLEN);
    uint32_t ip_hdr_len = ip->ihl * 4;
    uint16_t frag_off_raw = ntohs(ip->frag_off);
    
    uint32_t offset = (frag_off_raw & IP_OFFSET_MASK) * FRAG_UNIT;
    uint32_t p_len = ntohs(ip->tot_len) - ip_hdr_len;
    bool mf = !!(frag_off_raw & IP_MF_FLAG);

    reasm_slot_t *slot = xdp_get_reasm_slot(ip);
    if (!slot) return -1;

    /* Boundary Check: Prevent buffer overflow */
    if (unlikely(offset + p_len > MAX_IP_PKT_SIZE)) {
        __sync_fetch_and_add(&global_stats.reasm_oob_errors, 1);
        slot->is_active = false;
        return -1;
    }

    /* 2. Overlap Detection: Use our safe bitmap function */
    /* We check BEFORE we write to the buffer to maintain integrity */
    if (unlikely(set_bitmap_range(slot->bitmap, offset, p_len))) {
        /* * Industrial Policy: Log the overlap attempt and drop the fragment.
         * This prevents 'TearDrop' style attacks where fragments overlap to
         * bypass security filters or crash the stack.
         */
        LOG_WARN_RATELIMITED(5, 1, "[SECURITY] Overlapping fragment detected! ID:%u, Off:%u", 
                             ntohs(ip->id), offset);
        __sync_fetch_and_add(&global_stats.reasm_overlap_drops, 1);
        /* Optional: We can choose to invalidate the entire slot to be safe */
        slot->is_active = false; 
        return -1; 
    }

    /* Copy fragment data and update bitmap */
    memcpy(slot->buffer->data + offset, (uint8_t *)ip + ip_hdr_len, p_len);
    
    if (offset == 0) slot->header_received = true;
    if (!mf) {
        slot->last_frag_received = true;
        slot->expected_total_len = offset + p_len;
    }

    /* Check completion */
    if (slot->header_received && slot->last_frag_received) {
        if (is_bitmap_complete(slot->bitmap, slot->expected_total_len)) {
            __sync_fetch_and_add(&global_stats.reasm_completed, 1);

            info->payload = slot->buffer->data;
            info->payload_len = slot->expected_total_len;
            slot->is_active = false; 

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
            return 1; /* Success */
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
    return 0; /* Still in progress */
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

typedef void (*pkt_handler_t)(void *ctx, pkt_info_t *info);
static void handle_probe_packet(void *ctx, pkt_info_t *info) {
    struct sockaddr_in peer = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = info->ip.src_ip,
        .sin_port = htons(info->l4.src_port),
        .sin_zero = {0}
    };
    gc_probe_proc_enqueue((gc_probe_processor_t*)ctx, (uint8_t *)info->payload, info->payload_len, &peer);
}

/**
 * @brief  Parses the inner encapsulated UDP destination port from a tunnel payload.
 * * This function performs deep packet inspection (DPI) on the encapsulated traffic.
 * It strictly validates the IPv4 header and dynamically calculates offsets to 
 * handle variable IP options, ensuring memory safety against malformed packets.
 *
 * @param  payload      Pointer to the start of the tunnel payload (Auth Header).
 * @param  payload_len  Total size of the payload provided by the ring buffer.
 * @return uint16_t     Inner UDP destination port in Host Byte Order, or 0 if invalid.
 */
static inline uint16_t xdp_get_inner_dport(const uint8_t *payload, size_t payload_len) {
    /* 1. Initial boundary check: Must accommodate Auth(16) + Eth(14) + Min IPv4(20) */
    if (unlikely(payload_len < (GAP_AUTH_LEN + 14 + sizeof(struct iphdr)))) {
        return 0;
    }

    /* Jump to the start of the inner IP header */
    const uint8_t *ip_ptr = payload + GAP_AUTH_LEN + 14;

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
    size_t udp_offset = GAP_AUTH_LEN + 14 + ip_hl;
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

/**
 * @brief Industrial-grade Ring Buffer packet dispatcher.
 * Handles mixed traffic: Tunnel data, Probe discovery, and Raw terminal traffic.
 */
int xdp_handle_ringbuf(void *ctx, const uint8_t *data, size_t data_sz) {
    if (unlikely(!data || data_sz == 0)) return 0;

    pkt_info_t info = {0};
    int ret;
    /* 1. Basic parsing of the outer L2/L3/L4 headers */
    if (unlikely((ret = xdp_pkt_parse_all(data, data_sz, &info)) != 0)) {
        if (unlikely(ret == PARSE_ERR_REASM))
            log_error("xdp_pkt_parse_all error code: %d", ret);
        return 0;
    }

    if (cmd_islogpkt_enabled()) {
        xdp_pkt_dump_log(&info);
    }
    /**
     * 2. Identification of Tunneled/Special Packets
     * Even if the port is not 52719, if the length satisfies the encapsulation 
     * (Auth Header + Inner Ethernet), we inspect the content.
     */
    if (info.payload && info.payload_len >= (GAP_AUTH_LEN + 14)) {
        
        uint8_t *inner_base = (uint8_t *)info.payload;
        /* Locate the EtherType in the encapsulated Ethernet header (offset 12) */
        // uint16_t inner_eth_type = ntohs(*(uint16_t *)(inner_base + GAP_AUTH_LEN + 12));
        uint16_t inner_eth_type;
        memcpy(&inner_eth_type, inner_base + GAP_AUTH_LEN + 12, sizeof(uint16_t));
        inner_eth_type = ntohs(inner_eth_type);

        switch (inner_eth_type) {
            case PKT_TYPE_ENG:
                uint16_t inner_dport = xdp_get_inner_dport(inner_base, info.payload_len);
                int port_found = 0;

                for (size_t i = 0; i < ENG_MAP_SIZE; i++) {
                    if (xdp_eng_port_maps[i].port == inner_dport) {
                        /* Ensure handler exists before calling */
                        if (xdp_eng_port_maps[i].handler) {
                            xdp_eng_port_maps[i].handler(&info);
                        }
                        port_found = 1;
                        break; /* Find first match and exit loop */
                    }
                }

                /* If no registered handler is found for the extracted port */
                if (unlikely(!port_found)) {
                    /* Log a warning with rate-limiting to prevent log flooding.
                     * Interval: 5 seconds, Max logs per interval: 3. */
                    LOG_WARN_RATELIMITED(5, 3, 
                        "PKT_TYPE_ENG: No handler for inner port %u", inner_dport);
                }
                return 0;
            case PKT_TYPE_PROBE:
                /**
                 * Discovery/Heartbeat packets. 
                 * These are processed regardless of whether the port is 52719.
                 */
                handle_probe_packet(ctx, &info);
                return 0;
            case PKT_TYPE_CTRL:
                /* Control plane signaling */
                pkt_reverse_ctrl54_to_red(&info);
                return 0;
            default:
                /* If the payload is large but EtherType doesn't match our protocol,
                 * it's likely just a large raw packet (e.g., MTU-sized UDP).
                 * Fall through to pkt_send_to_black.
                 */
                break;
        }
    }

    /**
     * 3. Forward Path (Red -> Black)
     * Default action: Any packet that is not identified as a tunnel/probe
     * is treated as raw traffic from a terminal and sent for encapsulation.
     */
    switch (info.l4.src_port) {
        case PKT_OPE_SRC_PORT:
            if (likely(info.payload_len > 0)) {
                pkt_send_ope_to_black(&info);
            }
            break;
        case PKT_CTRL_SRC_PORT:
            if (likely(info.payload_len > 0)) {
                pkt_send_ctrl_to_black(&info);
            }
            break;
        case PKT_ADD_PORT:
            if (likely(info.payload_len > 0)) {
                pkt_send_raise_to_black(&info);
            }
            break;
        default:
            /* For all other ports, we assume it's terminal-originated traffic. */
            if (likely(info.payload_len > 0)) {
                pkt_send_ctrl54_to_black(&info);
            }
            break;
    }
    
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

    log_info("[REASM] Fragment reassembly engine initialized.");
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