/*
 * Copyright (c) 2025-2025, yanruibinghxu@gmail.com All rights reserved.
 * Copyright (c) lxc Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __RINGBUF_H__
#define __RINGBUF_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>

/**
 * ringbuf - Implements a simple and efficient memory mapped ringbuffer.
 * - The "addr" field of struct lxc_ringbuf is considered immutable. Instead the
 *   read and write offsets r_off and w_off are used to calculate the current
 *   read and write addresses. There should never be a need to use any of those
 *   fields directly. Instead use the appropriate helpers below.
 * - Callers are expected to synchronize read and write accesses to the
 *   ringbuffer.
 */
struct ringbuf {
	char *addr; /* start address of the ringbuffer */
	uint64_t size; /* total size of the ringbuffer in bytes */
	uint64_t r_off; /* read offset */
	uint64_t w_off; /* write offset */
};

/**
 * lxc_ringbuf_create - Initialize a new ringbuffer.
 *
 * @param[in] size	Size of the new ringbuffer as a power of 2.
 */
int ringbuf_create(struct ringbuf *buf, size_t size);
void ringbuf_move_read_addr(struct ringbuf *buf, size_t len);
int ringbuf_write(struct ringbuf *buf, const char *msg, size_t len);
int ringbuf_read(struct ringbuf *buf, char *out, size_t *len);

static inline void ringbuf_release(struct ringbuf *buf) {
    if (buf->size)
        munmap(buf->addr, buf->size * 2);
}

static inline void ringbuf_clear(struct ringbuf *buf) {
    buf->r_off = 0;
    buf->w_off = 0;
}

static inline uint64_t ringbuf_used(struct ringbuf *buf) {
    return buf->w_off - buf->r_off;
}

static inline uint64_t ringbuf_free(struct ringbuf *buf) {
	return buf->size - ringbuf_used(buf);
}

static inline char *ringbuf_get_read_addr(struct ringbuf *buf) {
	return buf->addr + buf->r_off;
}

static inline char *ringbuf_get_write_addr(struct ringbuf *buf) {
	return buf->addr + buf->w_off;
}

static inline void ringbuf_move_write_addr(struct ringbuf *buf, size_t len) {
	buf->w_off += len;
}

#endif