/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __HDR_H__
#define __HDR_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define AUTH_REQ            0x6000
#define AUTH_REP            0x6001
#define AUTH_DATA           0x6789
#define HDR_SIZE            12
#define AUTH_DATA_LENGTH    1514
#define AUTH_PAYLOAD_SIZE   (AUTH_DATA_LENGTH - HDR_SIZE)
#define BUFFER_SIZE         (HDR_SIZE + AUTH_PAYLOAD_SIZE)

/* HDR Structure (Byte Arrays - Manual Big-Endian)
 * Total size: exactly 12 bytes */
typedef struct {
    uint8_t type[2];    // Type16: [0]=high byte, [1]=low byte
    uint8_t len[2];     // Len16:  [0]=high byte, [1]=low byte
    uint8_t auth[4];    // Auth32: big-endian (auth[0] = highest byte)
    uint8_t crc[4];     // CRC32:  big-endian (crc[0] = highest byte)
} __attribute__((packed)) hdr_t;

/**
 * Build header using byte arrays (manual big-endian)
 * @param raw_hdr    Output buffer (must be HDR_SIZE bytes)
 * @param type       Message type (host order)
 * @param total_len  Total packet length (host order)
 * @param auth       Auth value (host order)
 * @param crc        CRC value (host order)
 */
void hdr_build(unsigned char *raw_hdr,
                    uint16_t type,
                    uint32_t total_len,
                    uint32_t auth);


/**
 * Parse header from raw bytes (manual big-endian to host order)
 * @param raw_hdr    Input header buffer (HDR_SIZE bytes)
 * @param type_out   Parsed type (host order)
 * @param len_out    Parsed total length (host order)
 * @param auth_out   Parsed auth value (host order)
 * @param crc_out    Parsed crc value (host order)
 * @return 0 on success, -1 on failure
 */
int hdr_parse(const unsigned char *raw_hdr,
                     uint16_t *type_out,
                     uint16_t *len_out,
                     uint32_t *auth_out,
                     uint32_t *crc_out);

/**
 * Verify CRC32 of header (first 8 bytes)
 * @param raw_hdr Header buffer (HDR_SIZE bytes)
 * @return 1 if CRC matches, 0 otherwise
 */
int hdr_verify_crc(const unsigned char *raw_hdr, ssize_t raw_len);

#endif