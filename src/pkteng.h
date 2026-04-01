/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 * * Description: Header for the high-performance packet engine.
 * This module handles bidirectional traffic between Red and Black zones,
 * including session management and tunnel encapsulation/decapsulation.
 */

#ifndef __PKTENG_H__
#define __PKTENG_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "xdp_pkt_parser.h"
#include "auth.h"
#include "session_manager.h"
#include "gcprobe.h"
#include "udp.h"

/* Tunnel Engine Specific Ports - Defined as Unsigned */
enum pkt_port_enum {
    PKT_OPE_SRC_PORT = 58888U,
    PKT_OPE_DST_PORT = 59999U,
    PKT_CTRL_SRC_PORT = 60002U,
    PKT_CTRL_DST_PORT = 50002U,
    PKT_ADD_PORT = 6013U,
};

/**
 * @brief Encapsulates and forwards Red Zone data to the Black Zone.
 * This function parses the incoming packet, updates the session manager,
 * wraps the payload into a tunnel format, and transmits it via UDP to 
 * the Black Zone management node.
 * @param info Pointer to the parsed packet metadata (IP, Port, Payload).
 * @return true if the packet was successfully processed and sent.
 * @return false if encapsulation failed or network resources were unavailable.
 */
bool pkt_send_ope_to_black(const pkt_info_t *info);

/**
 * @brief Decapsulates Black Zone return data and routes it back to the Red Zone.
 * This function handles tunnel decapsulation, performs a session lookup
 * to identify the original Red Zone source, and forwards the raw data
 * to the initial requester.
 * @param info Pointer to the packet received from the tunnel.
 * @return true if the packet was successfully matched and routed.
 * @return false if no session was found or decapsulation failed.
 */
bool pkt_reverse_ope_to_red(const pkt_info_t *info);

/**
 * @brief Handles control packets received from the Black Zone.
 * This function processes management/control messages, such as session updates
 * or configuration commands, and applies necessary changes to the system state.
 * @param info Pointer to the parsed control packet information.
 * @return true if the control message was successfully processed.
 * @return false if the message was malformed or contained invalid commands.
 */
bool pkt_send_ctrl_to_black(const pkt_info_t *info);

/**
 * @brief Handles control packets received from the Black Zone.
 * This function processes management/control messages, such as session updates
 * or configuration commands, and applies necessary changes to the system state.
 * @param info Pointer to the parsed control packet information.
 * @return true if the control message was successfully processed.
 * @return false if the message was malformed or contained invalid commands.
 */
bool pkt_reverse_ctrl_to_red(const pkt_info_t *info);

/**
 * @brief Handles raise messages received from the Black Zone.
 * This function processes critical alerts or state changes that need to be
 * escalated to the Red Zone for immediate attention.
 * @param info Pointer to the parsed raise message information.
 * @return true if the raise message was successfully processed.
 * @return false if the message was malformed or contained invalid commands.
 */
bool pkt_send_raise_to_black(const pkt_info_t *info);

/**
 * @brief Handles control packets received from the Black Zone.
 * This function processes management/raise messages, such as session updates
 * or configuration commands, and applies necessary changes to the system state.
 * @param info Pointer to the parsed control packet information.
 * @return true if the control message was successfully processed.
 * @return false if the message was malformed or contained invalid commands.
 */
bool pkt_reverse_raise_to_red(const pkt_info_t *info);

/**
 * @brief Handles a specific type of control packet (CTRL54) received from the Black Zone.
 * This function processes CTRL54 messages, which may represent a particular class of control
 * commands or alerts, and applies necessary changes to the system state.
 * @param info Pointer to the parsed CTRL54 packet information.
 * @return true if the CTRL54 message was successfully processed.
 * @return false if the message was malformed or contained invalid commands.
 */
bool pkt_send_ctrl54_to_black(const pkt_info_t *info);

/**
 * @brief Handles a specific type of control packet (CTRL54) received from the Black Zone.
 * This function processes CTRL54 messages, which may represent a particular class of control
 * commands or alerts, and applies necessary changes to the system state.
 * @param info Pointer to the parsed CTRL54 packet information.
 * @return true if the CTRL54 message was successfully processed.
 * @return false if the message was malformed or contained invalid commands.
 */
bool pkt_reverse_ctrl54_to_red(const pkt_info_t *info);

/**
 * @brief Configures the packet engine with persistent system objects.
 * @param sm       Pointer to the session manager (Thread-safe instance).
 * @param auth     Pointer to the authentication service.
 * @param gp       Pointer to the GC probe processor.
 * @param conn     Pointer to the shared UDP connection handle.
 * @param port     Destination tunnel port.
 * @param localip  Static local IP for encapsulation.
 * @param localmac Pointer to the 6-byte source MAC address.
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
);

#endif /* __PKTENG_H__ */