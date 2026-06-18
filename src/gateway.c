/**
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hdr.h"
#include "log.h"

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
                uint32_t auth_token)
{
    if (!dst_buf || !src_payload || payload_len == 0) {
        log_error("Invalid memory pointer reference or zero-length payload detected");
        return 0;
    }

    // 1. Calculate the final total payload mass boundary
    size_t total_packet_len = HDR_SIZE + payload_len;
    if (total_packet_len > BUFFER_SIZE) {
        log_error("Assembled data packet length [%zu] blows past max BUFFER_SIZE boundary", total_packet_len);
        return 0;
    }

    // 2. Linear Memory Shift: Pre-load the captured network payload into the data section (behind header)
    // We execute this first so that the header memory segment remains pristine for your builder
    memcpy(dst_buf + HDR_SIZE, src_payload, payload_len);

    // 3. Execution of your precise Custom Header Construction Engine
    // Note: Since your crc32_manual reads 'total_len' directly from raw_hdr, 
    // it will now flawlessly compute the CRC across the newly copied data segment downstream!
    hdr_build(dst_buf, type, (uint32_t)total_packet_len, auth_token);

    return total_packet_len;
}

/**
 * Unpack packet, verify CRC, and strip the 12-byte header.
 *
 * @param dst        Output buffer to store recovered payload
 * @param max_dst_len Maximum capacity of the destination buffer
 * @param pkt        Pointer to the raw incoming packet (Header + Payload)
 * @param pkt_len    Total length of the incoming packet
 * @param type_out   Parsed message type (host order)
 * @param auth_out   Parsed auth value (host order)
 * @return Recovered payload length, 0 on failure.
 */
size_t gw_unpack(unsigned char *dst,
                  size_t max_dst_len,
                  const unsigned char *pkt,
                  ssize_t pkt_len,
                  uint16_t *type_out,
                  uint32_t *auth_out)
{
    if (!dst || !pkt || pkt_len < HDR_SIZE) {
        log_error("Invalid argument or length shorter than HDR_SIZE");
        return 0;
    }

    // 1. Verify CRC integrity
    if (!hdr_verify_crc(pkt, pkt_len)) {
        log_error("Packet CRC verification failed");
        return 0;
    }

    // 2. Parse metadata fields
    uint16_t parsed_len = 0;
    uint32_t parsed_crc = 0;
    if (hdr_parse(pkt, type_out, &parsed_len, auth_out, &parsed_crc) != 0) {
        log_error("Failed to parse packet header");
        return 0;
    }

    // 3. Length cross-check
    if ((ssize_t)parsed_len != pkt_len) {
        log_error("Length mismatch: header=%u, wire=%zd", parsed_len, pkt_len);
        return 0;
    }

    // 4. Strip header and extract payload
    size_t payload_len = (size_t)pkt_len - HDR_SIZE;
    if (payload_len > max_dst_len) {
        log_error("Destination buffer overflow prevented, needs %zu bytes", payload_len);
        return 0;
    }

    if (payload_len > 0) {
        memcpy(dst, pkt + HDR_SIZE, payload_len);
    }

    return payload_len;
}