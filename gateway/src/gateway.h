/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef __GATEWAY_H__
#define __GATEWAY_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Marks the entry point of a network event processing cycle.
 * Saves the current memory arena cursor state to lock a roll-back snapshot.
 */
void gw_scope_begin(void);

/**
 * @brief Marks the exit point of a network event processing cycle.
 * O(1) instantly rolls back the allocation cursor to free all memory used in this scope.
 */
void gw_scope_exit(void);

/**
 * @brief Allocates a strictly isolated, 16-byte hardware-aligned memory block.
 * @param[in] required_len Absolute buffer size needed for the packet frame.
 * @return Safe aligned pointer to destination storage, or NULL if out of bounds (OOM).
 */
uint8_t *gw_alloc(size_t required_len);

/**
 * High-performance Packet Fusion Matrix
 * Assembles the user custom header and embeds the raw captured XDP frames.
 * @param dst_buf       Output vector memory boundary (Must hold payload_len + HDR_SIZE)
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
                uint32_t auth_token);

/**
 * @brief Zero-Copy High-Performance Packet Unpacking Engine.
 *
 * Validates wire integrity, executes metadata parsing, and returns a zero-copy
 * memory reference pointing directly into the original packet's payload offset.
 *
 * @param dst_buf     [Output] Pointer to store the zero-copy reference to the payload slice.
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
                    uint32_t *auth_out);

/**
 * @brief Encapsulates an outbound terminal packet and dispatches it to the Core.
 *
 * This function handles the forward data path (Red -> Black). It runs an in-place 
 * zero-copy optimization by assuming the provided payload pointer has sufficient 
 * encapsulation headroom preceding it.
 *
 * @param[in] data Pointer to the start of the active payload data stream.
 * The buffer must have at least `HDR_SIZE` bytes of 
 * writable headroom memory allocated directly before this address 
 * (i.e., data - HDR_SIZE) to inject the gateway matrix header without 
 * causing a heap memory copy or memory corruption.
 * @param[in] len  Absolute size of the active payload in bytes.
 * @return Number of total bytes transmitted (including encapsulation header) on success, 
 * or -1 if validation fails or socket transmission errors occur.
 */
ssize_t gw_send_to_core(const uint8_t *data, size_t len);

/**
 * @brief Decapsulates an incoming tunnel packet and delivers it to the destination Client.
 *
 * This function handles the reverse data path (Black -> Red). It validates the custom 
 * encapsulation layers (such as gateway matrix headers, security tokens, and CRCs), 
 * strips them off, and injects the raw decapsulated Layer-2/Layer-3 frame out through 
 * the client-facing interface.
 *
 * @param[in] data Pointer to the origin of the encapsulated packet stream.
 * @param[in] len  Total size of the encapsulated packet buffer in bytes.
 * @return Number of bytes successfully injected to the client interface on success, 
 * or -1 if the packet fails integrity/CRC verification or delivery drops.
 */
ssize_t gw_send_to_client(const uint8_t *data, size_t len);

#endif /* __ASSEMBLE_H__ */