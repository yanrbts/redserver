/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>   // struct ethhdr
#include <arpa/inet.h>       // inet_addr
#include <stdbool.h>
#include <stdlib.h>

#include "util.h"
#include "log.h"
#include "gap.h"
#include "udp.h"
#include "pkteng.h"

#define VPORT_START 10000
#define VPORT_END   60000

static session_manager_t *smgr = NULL;
static auth_t *at = NULL;
static gc_probe_processor_t *gprobe = NULL;
static udp_conn_t *udp_conn = NULL;
static raw_sock_t *rawsock_conn = NULL;
static uint16_t dstport = 0;
static uint32_t local_ip = 0;
static uint8_t  local_mac[6] = {0};

/**
 * @brief Thread-safe allocation of a unique Virtual Port (vPort) for session tracking.
 *
 * In a high-performance network gateway, multiple internal clients may communicate 
 * with the same external destination. Since the physical tunnel port (52719) is 
 * static, this function provides a unique 16-bit identifier (vPort) to be 
 * embedded within the tunnel protocol.
 *
 * This Virtual Port serves as a unique session key, allowing the gateway to 
 * correctly demultiplex returning traffic and route it back to the original 
 * Red Zone source.
 *
 * @note Design Pattern: Thread-Local Rolling Counter.
 * @details 
 * - **Thread Safety**: Uses `_Thread_local` (C11) to eliminate lock contention 
 * between CPU cores. Each XDP processing thread maintains its own independent 
 * counter, ensuring zero-overhead allocation in multi-core environments.
 * - **Collision Avoidance**: Uses a circular range (VPORT_START to VPORT_END). 
 * The 50,000-port range is sufficient to prevent ID wraparound collisions 
 * for most short-lived session scenarios.
 *
 * @return uint16_t  A unique virtual port number within the specified range.
 */
static uint16_t session_vport_allocate(void) {
    /* Static thread-local counter. 
     * Persists for the lifetime of the thread and is initialized only once.
     */
    static _Thread_local uint16_t next_vport = VPORT_START;

    /* Assign current value and increment the internal counter */
    uint16_t current_vport = next_vport++;

    /* Range Boundary Enforcement:
     * Check if the counter has exceeded the defined maximum (VPORT_END).
     * 'unlikely' is used as a compiler hint for branch prediction optimization,
     * as the reset condition occurs only once every 50,000 calls.
     */
    if (unlikely(next_vport > VPORT_END)) {
        next_vport = VPORT_START;
    }

    return current_vport;
}

/**
 * @brief Updates the session management table with a new context.
 * This function constructs a session key using the provided RCP ID and 
 * Virtual Port, then associates it with the packet's source metadata 
 * (IP, Port, and MAC). This is typically used to track requests so that 
 * responses from the Black Zone can be routed back to the correct Red Zone client.
 *
 * @param smgr     Pointer to the session manager instance.
 * @param info     Pointer to the packet information structure.
 * @param rcp_id   The Remote Control Protocol ID (use 0 for control packets).
 * @param v_port   The Virtual Port used as a unique session identifier.
 * @return int     Returns 0 on success, or a negative value on failure.
 */
static inline int session_mgr_update_by_pkt(const pkt_info_t *info, 
                                            uint8_t rcp_id, 
                                            uint16_t v_port) 
{
    if (unlikely(!smgr || !info)) {
        return -1;
    }

    /* 1. Initialize and construct the unique Session Key */
    session_key_t key;
    memset(&key, 0, sizeof(session_key_t));
    key.v_port = v_port;
    key.rcp_id = rcp_id;

    /* 2. Map the original network context (Red Zone source) */
    session_context_t s_ctx;
    memset(&s_ctx, 0, sizeof(session_context_t));
    s_ctx.src_ip   = info->ip.src_ip;
    s_ctx.src_port = info->l4.src_port;
    s_ctx.dst_ip   = info->ip.dst_ip;
    s_ctx.dst_port = info->l4.dst_port;
    memcpy(s_ctx.src_mac, info->eth.src, 6);

    /* 3. Commit the entry to the session manager */
    session_mgr_update(smgr, &key, &s_ctx);

    return 0;
}

/**
 * @brief Enqueues external data (Red Zone) to be encapsulated and sent to Black Zone.
 * @param info Parsed info of the original packet.
 * @return true if successfully enqueued.
 */
bool pkt_send_ope_to_black(const pkt_info_t *info) {
    /* Safety Check: Fast fail */
    if (unlikely(!info || !at || !gprobe || !udp_conn || local_ip == 0)) {
        return false;
    }

    tunnel_payload_t **packets = NULL;
    size_t num_packets = 0;
    uint32_t auth = 0;
    uint32_t dst_ip = 0;
    // uint16_t v_port;
    char ip_str[16] = {0};
    char ip_dst[16] = {0};
    uint8_t dst_mac[6] = {0};

    tunnel_inner_payload_t *inner = gap_get_inner(info->payload, info->payload_len);
    if (!inner) {
        log_error("Failed to parse inner header from incoming packet");
        return false;
    }

    if (unlikely(!gc_probe_get_ip_by_type(gprobe, GC_MGR_BLACK, &dst_ip))) {
        log_error("CTRL Failed to get destination IP for Black Zone");
        return false;
    }
    ip_ntop(dst_ip, ip_dst, sizeof(ip_dst));

    if (unlikely(!gc_probe_get_mac_by_type(gprobe, GC_MGR_BLACK, dst_mac))) {
        log_error("CTRL Failed to get destination MAC for Black Zone");
        return false;
    }
    
    /* 1. Allocate a unique Session ID (Virtual Port) */
    // v_port = session_vport_allocate();
    if (unlikely(session_mgr_update_by_pkt(info, inner->rcpId, PKT_OPE_SRC_PORT) != 0)) {
        log_error("OPE Failed to update session manager");
        return false;
    }

    auth = auth_get_static_value();
    int ret = gap_build_tunneled_packets_ex(
        info->payload, info->payload_len,
        local_mac, dst_mac,                             // mac
        local_ip, info->ip.dst_ip,                      // ip
        PKT_OPE_SRC_PORT, PKT_OPE_DST_PORT,
        auth,
        &packets, &num_packets          
    );

    if (unlikely(ret != 0 || packets == NULL || num_packets == 0)) {
        return false;
    }

    ret = gap_send_tunneled_to_target(
        ip_dst,
        dstport,
        packets,
        num_packets,
        udp_conn
    );

    if (unlikely(ret != 0)) {
        log_error("Failed to send tunneled packets to Switch");
    } else {
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info("OPE SRC(%s) -> DST(%s): Sent %zu tunneled packets", ip_str, ip_dst, num_packets);
    }

    gap_free_tunneled_packets(packets, num_packets);

    return (ret == 0);
}

/**
 * @brief Decapsulates Black Zone return data and routes it back to the Red Zone.
 * This function handles tunnel decapsulation, performs a session lookup
 * to identify the original Red Zone source, and forwards the raw data
 * to the initial requester.
 * @param info Pointer to the packet received from the tunnel.
 * @return true if the packet was successfully matched and routed.
 * @return false if no session was found or decapsulation failed.
 */
bool pkt_reverse_ope_to_red(const pkt_info_t *info) {
    if (unlikely(!info || !smgr || !udp_conn)) return false;

    char ip_str[16] = {0};
    char ip_dst_str[16] = {0};
    uint16_t v_port;
    unsigned char *payload_data;
    size_t payload_len;
    session_context_t orig;

    /* 1. Decapsulation */
    if (unlikely(gap_unpack_packets((unsigned char *)info->payload, 
                                   info->payload_len, &v_port, 
                                   &payload_data, &payload_len) != 0)) {
        return false;
    }

    tunnel_inner_payload_t *inner = gap_get_inner(payload_data, payload_len);
    if (!inner) {
        log_error("Failed to parse inner header from tunneled packet");
        return false;
    }

    /* 2. Fragment Reassembly Logic 
     * We pass the fragment to our reassembly engine. 
     * It returns a non-NULL pointer ONLY when the last fragment arrives.
     */
    size_t complete_len = 0;
    uint8_t *complete_pkt_raw = gap_assemble_tunnel_payload(inner, &complete_len);

    if (complete_pkt_raw == NULL) {
        /* Packet is incomplete, waiting for more fragments. 
         * Return true because the fragment was successfully handled/buffered. */
        return true; 
    }

    /* 4. Process the Fully Assembled Packet */
    /* Now we have the complete 'tunnel_inner_payload_t' structure in contiguous memory */
    tunnel_inner_payload_t *assembled_inner = (tunnel_inner_payload_t *)complete_pkt_raw;

    /* 3. Reverse Session Lookup */
    session_key_t reverse_key;
    memset(&reverse_key, 0, sizeof(session_key_t));
    reverse_key.v_port = v_port;
    reverse_key.rcp_id = assembled_inner->rcpId;

    if (unlikely(!session_mgr_lookup(smgr, &reverse_key, &orig))) {
        /* Frequent in edge cases, log at warn/debug level */
        log_warn("Reverse lookup failed for %u:%hu:%u %s:%s", 
            info->ip.src_ip, v_port, reverse_key.rcp_id, assembled_inner->url, assembled_inner->method);
        gap_assemble_free_packet(complete_pkt_raw);
        return false;
    }

    /* 3. Raw Return to Source */
    ip_ntop(orig.src_ip, ip_dst_str, sizeof(ip_dst_str));
    // ssize_t sent = udp_send_raw(udp_conn, ip_dst_str, orig.src_port, complete_pkt_raw, complete_len);

    ssize_t sent = raw_send_udp_frag(
        rawsock_conn,
        local_mac, orig.src_mac,
        orig.dst_ip, orig.src_ip,
        htons(orig.dst_port), htons(orig.src_port),
        complete_pkt_raw, complete_len
    );

    if (likely(sent >= 0)) {
        // ip_ntop(orig.src_ip, ip_dst_str, sizeof(ip_dst_str));
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info("OPE SRC(%s) -> DST(%s): Sent %zu ", ip_str, ip_dst_str, complete_len);
    }

    gap_assemble_free_packet(complete_pkt_raw);

    return (sent >= 0);
}

bool pkt_send_ctrl_to_black(const pkt_info_t *info) {
    if (unlikely(!info || !gprobe || !udp_conn || local_ip == 0)) {
        return false;
    }

    tunnel_payload_t *packet = NULL;
    size_t packet_len = 0;
    uint32_t auth = 0;
    uint32_t dst_ip = 0;
    char ip_str[16] = {0};
    char ip_dst[16] = {0};
    uint8_t dst_mac[6] = {0};

    if (unlikely(!gc_probe_get_ip_by_type(gprobe, GC_MGR_BLACK, &dst_ip))) {
        log_error("CTRL Failed to get destination IP for Black Zone");
        return false;
    }
    ip_ntop(dst_ip, ip_dst, sizeof(ip_dst));

    if (unlikely(!gc_probe_get_mac_by_type(gprobe, GC_MGR_BLACK, dst_mac))) {
        log_error("CTRL Failed to get destination MAC for Black Zone");
        return false;
    }

    /* Control packets can use a reserved RCP ID, e.g., 0 or 255, 
     * to differentiate from regular OPE packets. Here we use 0. */
    if (unlikely(session_mgr_update_by_pkt(info, 0, PKT_CTRL_SRC_PORT) != 0)) {
        log_error("CTRL Failed to update session manager");
        return false;
    }
    
    auth = auth_get_static_value();
    packet = gap_build_control_packet(
        info->payload, info->payload_len,
        local_mac, dst_mac,                             // mac
        local_ip, info->ip.dst_ip,                      // ip
        PKT_CTRL_SRC_PORT, PKT_CTRL_DST_PORT,
        auth,
        &packet_len          
    );

    if (unlikely(packet == NULL || packet_len == 0)) {
        return false;
    }

    ssize_t sent_bytes = udp_send_raw(udp_conn, ip_dst, dstport, 
                                        packet, packet_len);

    if (unlikely(sent_bytes < 0)) {
        log_error("Send failed for control packet: %s", strerror(errno));
        return false;
    } else {
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info("CTRL SRC(%s) -> DST(%s): Sent 1 tunneled packets", ip_str, ip_dst);
    }

    gap_free_single_payload(packet);

    return true;
}

bool pkt_reverse_ctrl_to_red(const pkt_info_t *info) {
    if (unlikely(!info)) return false;

    char ip_str[16] = {0};
    char ip_dst_str[16] = {0};
    uint16_t v_port;
    unsigned char *payload_data;
    size_t payload_len;
    session_context_t orig;

    tunnel_payload_t *tunnel_pkt = (tunnel_payload_t *)info->payload;
    if (unlikely(tunnel_pkt->ip_header[9] != 17)) { // UDP protocol check
        log_warn("Received non-UDP control packet, ignoring");
        return false;
    }

    /* 1. Decapsulation */
    if (unlikely(gap_unpack_packets((unsigned char *)info->payload, 
                                   info->payload_len, &v_port, 
                                   &payload_data, &payload_len) != 0)) {
        return false;
    }

    /* 2. Reverse Session Lookup */
    session_key_t reverse_key;
    memset(&reverse_key, 0, sizeof(session_key_t));
    reverse_key.v_port = v_port;
    reverse_key.rcp_id = 0; // Control packets use reserved RCP ID 0

    if (unlikely(!session_mgr_lookup(smgr, &reverse_key, &orig))) {
        /* Frequent in edge cases, log at warn/debug level */
        log_warn("Reverse lookup failed for %u:%hu", info->ip.src_ip, v_port);
        return false;
    }

    /* 3. Raw Return to Source */
    ip_ntop(orig.src_ip, ip_dst_str, sizeof(ip_dst_str));
    ssize_t sent = udp_send_raw(udp_conn, ip_dst_str, orig.src_port, payload_data, payload_len);
    
    if (likely(sent >= 0)) {
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info(">>> REVERSE SRC(%s) -> DST(%s): Sent %zu ", ip_str, ip_dst_str, payload_len);
        return true;
    }

    return false;
}

bool pkt_send_ctrl54_to_black(const pkt_info_t *info) {
    if (unlikely(!info || !gprobe || !udp_conn || local_ip == 0)) {
        return false;
    }

    tunnel_payload_t *packet = NULL;
    size_t packet_len = 0;
    uint32_t auth = 0;
    uint32_t dst_ip = 0;
    char ip_str[16] = {0};
    char ip_dst[16] = {0};
    uint8_t dst_mac[6] = {0};

    if (unlikely(!gc_probe_get_ip_by_type(gprobe, GC_MGR_BLACK, &dst_ip))) {
        log_error("CTRL54 Failed to get destination IP for Black Zone");
        return false;
    }
    ip_ntop(dst_ip, ip_dst, sizeof(ip_dst));

    if (unlikely(!gc_probe_get_mac_by_type(gprobe, GC_MGR_BLACK, dst_mac))) {
        log_error("CTRL54 Failed to get destination MAC for Black Zone");
        return false;
    }

    /**
     * Security Check: Ensure the destination MAC is not the same as the source MAC of the incoming packet.
     * This prevents potential reflection attacks where an attacker might try to send a raise message
     * that appears to originate from the Black Zone but is actually crafted by an external attacker.
     */
    if (unlikely(memcmp(info->eth.src, dst_mac, 6) == 0)) {
        log_warn("CTRL54 Destination IP mismatch: expected %s, got %s", ip_dst, ip_str);
        return false;
    }

    /* Control packets can use a reserved RCP ID, e.g., 0 or 255, 
     * to differentiate from regular OPE packets. Here we use 0. */
    if (unlikely(session_mgr_update_by_pkt(info, 0, info->l4.src_port) != 0)) {
        log_error("CTRL54 Failed to update session manager");
        return false;
    }
    
    auth = auth_get_static_value();
    packet = gap_build_ctrl54_packet(
        info->payload, info->payload_len,
        local_mac, dst_mac,                             // mac
        info->ip.src_ip, info->ip.dst_ip,               // ip
        info->l4.src_port, info->l4.dst_port,           // port
        auth,
        &packet_len          
    );

    if (unlikely(packet == NULL || packet_len == 0)) {
        return false;
    }

    ssize_t sent_bytes = udp_send_raw(udp_conn, ip_dst, dstport, 
                                        packet, packet_len);

    if (unlikely(sent_bytes < 0)) {
        log_error("CTRL54 Send failed for control packet: %s", strerror(errno));
        return false;
    } else {
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info("CTRL54 SRC(%s) -> DST(%s): Sent 1 tunneled packets", ip_str, ip_dst);
    }

    gap_free_single_payload(packet);

    return true;
}

bool pkt_reverse_ctrl54_to_red(const pkt_info_t *info) {
    return pkt_reverse_ctrl_to_red(info);
}

bool pkt_send_raise_to_black(const pkt_info_t *info) {
    if (unlikely(!info || !gprobe || !udp_conn || local_ip == 0)) {
        return false;
    }

    tunnel_payload_t *packet = NULL;
    size_t packet_len = 0;
    uint32_t auth = 0;
    uint32_t dst_ip = 0;
    char ip_str[16] = {0};
    char ip_dst[16] = {0};
    uint8_t dst_mac[6] = {0};

    if (unlikely(!gc_probe_get_ip_by_type(gprobe, GC_MGR_BLACK, &dst_ip))) {
        log_error("RAISE Failed to get destination IP for Black Zone");
        return false;
    }
    ip_ntop(dst_ip, ip_dst, sizeof(ip_dst));

    if (unlikely(!gc_probe_get_mac_by_type(gprobe, GC_MGR_BLACK, dst_mac))) {
        log_error("RAISE Failed to get destination MAC for Black Zone");
        return false;
    }

    /* Control packets can use a reserved RCP ID, e.g., 0 or 255, 
     * to differentiate from regular OPE packets. Here we use 0. */
    if (unlikely(session_mgr_update_by_pkt(info, 0, PKT_ADD_PORT) != 0)) {
        log_error("RAISE Failed to update session manager");
        return false;
    }
    
    auth = auth_get_static_value();
    packet = gap_build_control_packet(
        info->payload, info->payload_len,
        local_mac, dst_mac,                             // mac
        local_ip, info->ip.dst_ip,                      // ip
        PKT_ADD_PORT, PKT_ADD_PORT,                     // port
        auth,
        &packet_len          
    );

    if (unlikely(packet == NULL || packet_len == 0)) {
        return false;
    }

    ssize_t sent_bytes = udp_send_raw(udp_conn, ip_dst, dstport, 
                                        packet, packet_len);

    if (unlikely(sent_bytes < 0)) {
        log_error("RAISE Send failed for control packet: %s", strerror(errno));
        return false;
    } else {
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info("RAISE SRC(%s) -> DST(%s): Sent 1 tunneled packets", ip_str, ip_dst);
    }

    gap_free_single_payload(packet);

    return true;
}

bool pkt_reverse_raise_to_red(const pkt_info_t *info) {
    if (unlikely(!info)) return false;

    char ip_str[16] = {0};
    char ip_dst_str[16] = {0};
    uint16_t v_port;
    unsigned char *payload_data;
    size_t payload_len;
    session_context_t orig;

    tunnel_payload_t *tunnel_pkt = (tunnel_payload_t *)info->payload;
    if (unlikely(tunnel_pkt->ip_header[9] != 17)) { // UDP protocol check
        log_warn("RAISE Received non-UDP control packet, ignoring");
        return false;
    }

    /* 1. Decapsulation */
    if (unlikely(gap_unpack_packets((unsigned char *)info->payload, 
                                   info->payload_len, &v_port, 
                                   &payload_data, &payload_len) != 0)) {
        return false;
    }

    /* 2. Reverse Session Lookup */
    session_key_t reverse_key;
    memset(&reverse_key, 0, sizeof(session_key_t));
    reverse_key.v_port = v_port;
    reverse_key.rcp_id = 0; // Control packets use reserved RCP ID 0

    if (unlikely(!session_mgr_lookup(smgr, &reverse_key, &orig))) {
        /* Frequent in edge cases, log at warn/debug level */
        log_warn("Reverse lookup failed for %u:%hu", info->ip.src_ip, v_port);
        return false;
    }

    /* 3. Raw Return to Source */
    ip_ntop(orig.src_ip, ip_dst_str, sizeof(ip_dst_str));
    ssize_t sent = udp_send_raw(udp_conn, ip_dst_str, orig.src_port, payload_data, payload_len);
    
    if (likely(sent >= 0)) {
        ip_ntop(info->ip.src_ip, ip_str, sizeof(ip_str));
        log_info(">>> REVERSE SRC(%s) -> DST(%s): Sent %zu ", ip_str, ip_dst_str, payload_len);
        return true;
    }

    return false;
}

/**
 * @brief Configures the packet engine with persistent system objects.
 */
void pkt_set_object(
    session_manager_t *const sm,       
    auth_t *const auth,                
    gc_probe_processor_t *const gp,    
    udp_conn_t *const conn, 
    raw_sock_t *const rawsock,           
    const uint16_t port,                
    const uint32_t localip,
    const uint8_t *const localmac 
) {
    if (unlikely(!sm || !auth || !gp || !conn || localip==0 || !localmac)) {
        log_fatal("Invalid object injection in pkt_set_object");
        return;
    }
    
    smgr = sm;
    at = auth;
    gprobe = gp;
    udp_conn = conn;
    dstport = port;
    local_ip = localip;
    memcpy(local_mac, localmac, 6);
    rawsock_conn = rawsock;
}