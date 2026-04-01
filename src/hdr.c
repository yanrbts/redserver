/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <string.h>
#include "hdr.h"
#include "log.h"
#include "crc32.h"

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
                      uint32_t auth) {
    if (total_len > 0xFFFF) {
        log_error("total_len exceeds uint16_t range: %u", total_len);
        return;
    }

    hdr_t *h = (hdr_t *)raw_hdr;

    // Type16 big-endian
    h->type[0] = (type >> 8) & 0xFF;   // high byte
    h->type[1] = type & 0xFF;          // low byte

    // Len16 big-endian
    h->len[0] = (total_len >> 8) & 0xFF;
    h->len[1] = total_len & 0xFF;

    // Auth32 big-endian
    h->auth[0] = (auth >> 24) & 0xFF;
    h->auth[1] = (auth >> 16) & 0xFF;
    h->auth[2] = (auth >> 8)  & 0xFF;
    h->auth[3] = auth & 0xFF;

    // CRC32 big-endian (first set to 0 for calculation)
    memset(h->crc, 0, 4);

    // Calculate CRC32 on first 8 bytes
    uint32_t calc_crc = crc32_manual(raw_hdr, total_len) & 0xFFFFFFFF;

    // Fill CRC big-endian
    h->crc[0] = (calc_crc >> 24) & 0xFF;
    h->crc[1] = (calc_crc >> 16) & 0xFF;
    h->crc[2] = (calc_crc >> 8)  & 0xFF;
    h->crc[3] = calc_crc & 0xFF;
}

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
                     uint32_t *crc_out) {
    if (!raw_hdr) return -1;

    const hdr_t *h = (const hdr_t *)raw_hdr;

    *type_out = (h->type[0] << 8) | h->type[1];
    *len_out  = (h->len[0] << 8)  | h->len[1];
    *auth_out = (h->auth[0] << 24) | (h->auth[1] << 16) | (h->auth[2] << 8) | h->auth[3];
    *crc_out  = (h->crc[0] << 24)  | (h->crc[1] << 16)  | (h->crc[2] << 8)  | h->crc[3];

    return 0;
}

/**
 * Verify CRC32 of header (first 8 bytes)
 * @param raw_hdr Header buffer (HDR_SIZE bytes)
 * @return 1 if CRC matches, 0 otherwise
 */
int hdr_verify_crc(const unsigned char *raw_hdr, ssize_t raw_len) {
    if (!raw_hdr || raw_len < HDR_SIZE) {
        return 0;
    }

    unsigned char temp[BUFFER_SIZE];
    if ((size_t)raw_len > sizeof(temp)) {
        log_error("Packet too large for buffer");
        return 0;
    }
    memcpy(temp, raw_hdr, raw_len);
    memset(temp + 8, 0, 4);

    uint32_t calc_crc = crc32_manual(temp, raw_len);

    const hdr_t *h = (const hdr_t *)raw_hdr;
    uint32_t stored_crc = (h->crc[0] << 24) | (h->crc[1] << 16) | (h->crc[2] << 8) | h->crc[3];

    int match = (calc_crc == stored_crc);
    if (!match) {
        log_debug("CRC mismatch: calc=0x%08x, stored=0x%08x", calc_crc, stored_crc);
    }

    return match;
}