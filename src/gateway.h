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
                  uint32_t *auth_out);

#endif /* __ASSEMBLE_H__ */