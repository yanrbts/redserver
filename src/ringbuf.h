/*
 * Copyright (c) 2025-2026, yanruibinghxu@gmail.com All rights reserved.
 * Copyright (c) lxc Ltd. All rights reserved.
 * Optimized for High-Throughput Stream Overwrite Mode.
 */

#ifndef __RINGBUF_H__
#define __RINGBUF_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>

/**
 * @struct ringbuf_hdr_t
 * @brief Self-contained transactional header embedded directly inside the memory stream.
 */
typedef struct {
    uint32_t pkt_len;          /* Pure data payload length in bytes */
    uint32_t version_seq;      /* Transaction snapshot tracking token (lower 32-bits of tail) */
    uint8_t  payload[];        /* Flexible array member pointing to continuous serialized data */
} __attribute__((packed)) ringbuf_hdr_t;

/**
 * @struct ringbuf
 * @brief Thread-safe Multi-Consumer Mirror Ring Buffer using virtual memory wrapping.
 */
typedef struct ringbuf {
    uint8_t *addr;            /* Base address of the double-mapped contiguous virtual memory space */
    uint64_t size;            /* Physical size of a single buffer window (must be page-aligned) */
    volatile uint64_t head;   /* Shared monotonic virtual read offset across multiple consumers */
    volatile uint64_t tail;   /* Monotonic virtual write offset managed by a single producer */
} ringbuf_t;

/**
 * @brief Allocates and initializes the virtual mirror mapping ring buffer architecture.
 * @param buf Pointer to the ring buffer structural tracking backbone.
 * @param size Physical allocation size (bytes). Must be an exact multiple of the system page size.
 * @return 0 on success, or a negative standard error code (e.g., -EINVAL, -ENOMEM).
 */
int ringbuf_create(ringbuf_t *buf, size_t size);

/**
 * @brief Safe teardown and dissociation of the underlying virtual memory segments.
 * @param buf Pointer to the active ring buffer context.
 */
void ringbuf_release(ringbuf_t *buf);

/**
 * @brief Unconditional mandatory overwrite streaming injection (Single-Producer safe).
 * 
 * Never blocks or rejects inputs. Automatically purges stale frames by pushing the 
 * global head forward if the incoming ingestion payload risks a window overflow.
 * 
 * @param buf Pointer to the active ring buffer context.
 * @param raw_hdr Optional peripheral metadata header (e.g., struct pcap_pkthdr). Pass NULL if unused.
 * @param raw_hdr_len Length of the optional metadata header segment. Pass 0 if unused.
 * @param data Core raw buffer network packet frames / payload segment.
 * @param data_len Length of the core raw payload segment.
 * @return 0 on successful commitment, negative error code on structural parameters constraint violation.
 */
int ringbuf_write(ringbuf_t *buf, 
                  const void *raw_hdr, size_t raw_hdr_len,
                  const void *data, size_t data_len);

/**
 * @brief Concurrent thread-safe data frame extraction (Multi-Consumer safe).
 * 
 * Leverages Compare-And-Swap (CAS) optimistic locking to arbitrate zero-copy index indices.
 * Executes dual-stage transactional validation to intercept and drop frames torn by write overruns.
 * 
 * @param buf Pointer to the active ring buffer context.
 * @param out_hdr_buf Target memory segment to hold the retrieved metadata header (Optional, can be NULL).
 * @param hdr_len Expected allocation constraint size of the targeted metadata header.
 * @param out_data_buf Target user-space destination buffer where payload will be deep-copied.
 * @param max_data_len Maximum allocation ceiling boundary size of out_data_buf container.
 * @param out_actual_data_len Output variable returning the exact volume of extracted payload bytes.
 * @return 0 on success, -1 if queue starved (empty), -2 on concurrency collision / transaction tearing (retry).
 */
int ringbuf_read(ringbuf_t *buf,
                 void *out_hdr_buf, size_t hdr_len,
                 void *out_data_buf, size_t max_data_len,
                 uint32_t *out_actual_data_len);

#endif /* __RINGBUF_H__ */