/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __CRC32_H__
#define __CRC32_H__

#include <stdint.h>
#include <stddef.h>
/**
 * Calculate CRC32 (IEEE 802.3) for a buffer
 * @param buf   Data buffer
 * @param len   Length of data
 * @return 32-bit CRC value
 */
uint32_t crc32_manual(const unsigned char *buf, size_t len);

#endif