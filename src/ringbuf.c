#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "util.h"
#include "ringbuf.h"

/**
 * @brief Safely determines system architecture memory page boundary requirements.
 */
static inline uint64_t _get_sys_pagesize(void) {
    long pgsz = sysconf(_SC_PAGESIZE);
    return (pgsz <= 0) ? 4096 : (uint64_t)pgsz;
}

int ringbuf_create(ringbuf_t *buf, size_t size) {
    if (unlikely(!buf)) return -EINVAL;

    buf->size = size;
    buf->head = 0;
    buf->tail = 0;

    /* Verify strict page alignment configuration compliance */
    if (unlikely(buf->size % _get_sys_pagesize())) {
        fprintf(stderr, "ringbuf: size must be a multiple of the page size(%lu)\n", _get_sys_pagesize());
        return -EINVAL;
    }

    /* Step 1: Reserve an unbacked contiguous virtual memory area twice the single size capacity */
    buf->addr = (uint8_t *)mmap(NULL, buf->size * 2, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (unlikely(buf->addr == MAP_FAILED)) {
        return -ENOMEM;
    }

    /* Step 2: Provision highly-optimized anonymous volatile backplane RAM storage */
    int memfd = memfd_create(".ringbuf_shm", MFD_CLOEXEC);
    if (unlikely(memfd < 0)) {
        /* Fallback mechanism: Degrade to a hidden unlinked standard temporary disk asset if memfd_create is missing */
        char template[] = "/tmp/.ringbuf_XXXXXX";
        mode_t msk = umask(0022);
        memfd = mkstemp(template);
        umask(msk);
        if (likely(memfd >= 0)) {
            fcntl(memfd, F_SETFD, FD_CLOEXEC);
            unlink(template); /* Unlink immediately for auto-cleanup closure guarantees on teardown */
        }
    }

    if (unlikely(memfd < 0)) {
        munmap(buf->addr, buf->size * 2);
        return -EIO;
    }

    if (unlikely(ftruncate(memfd, buf->size) < 0)) {
        close(memfd);
        munmap(buf->addr, buf->size * 2);
        return -EIO;
    }

    /* Step 3: Core Mirror Mechanism - Double map the same physical file into adjacent memory bounds */
    /* Map the first half segment: [0 to size-1] */
    uint8_t *tmp1 = (uint8_t *)mmap(buf->addr, buf->size, PROT_READ | PROT_WRITE, 
                                    MAP_FIXED | MAP_SHARED, memfd, 0);
    /* Map the mirror second half segment: [size to 2*size-1] mirroring offset 0 of the exact same descriptor */
    uint8_t *tmp2 = (uint8_t *)mmap(buf->addr + buf->size, buf->size, PROT_READ | PROT_WRITE, 
                                    MAP_FIXED | MAP_SHARED, memfd, 0);

    /* Reference count is now held directly by active virtual memory mappings; descriptor can be safely closed */
    close(memfd); 

    if (unlikely(tmp1 == MAP_FAILED || tmp2 == MAP_FAILED || tmp1 != buf->addr || tmp2 != (buf->addr + buf->size))) {
        munmap(buf->addr, buf->size * 2);
        return -EFAULT;
    }

    return 0;
}

void ringbuf_release(ringbuf_t *buf) {
    if (likely(buf && buf->size)) {
        munmap(buf->addr, buf->size * 2);
        buf->addr = NULL;
        buf->size = 0;
    }
}

int ringbuf_write(ringbuf_t *buf, 
                  const void *raw_hdr, size_t raw_hdr_len,
                  const void *data, size_t data_len) {
    if (unlikely(!buf || !buf->addr || !data || !data_len)) return -EINVAL;

    size_t payload_total_len = raw_hdr_len + data_len;
    size_t total_write_size = sizeof(ringbuf_hdr_t) + payload_total_len;

    /* Structural Guard: A single transaction packet size must never scale beyond physical capacity limits */
    if (unlikely(total_write_size > buf->size)) return -EFBIG;

    uint64_t current_tail = buf->tail;
    uint64_t current_head = __atomic_load_n(&buf->head, __ATOMIC_ACQUIRE);

    /* 
     * Mandatory Overwrite Paradigm:
     * If the incoming write block exceeds remaining free window volume, the single producer
     * unconditionally shifts the global head pointer forward to purge the oldest unread frames.
     */
    while (unlikely((current_tail + total_write_size - current_head) > buf->size)) {
        /* Advance head by optimized 64-byte chunks to instantly open sufficient write room */
        if (__atomic_compare_exchange_n(&buf->head, &current_head, current_head + 64, 
                                        true, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            current_head += 64;
        } else {
            /* CAS fallback: Reload index since concurrent consumer operations advanced the head */
            current_head = __atomic_load_n(&buf->head, __ATOMIC_ACQUIRE);
        }
    }

    /* Translate the virtual global offset into raw physical target index via single modulus mapping */
    uint8_t *w_ptr = buf->addr + (current_tail % buf->size);
    ringbuf_hdr_t *hdr = (ringbuf_hdr_t *)w_ptr;

    /* Transaction Phase 1: Invalidate version token to immediately block consumers from parsing garbage mid-write */
    __atomic_store_n(&hdr->version_seq, (uint32_t)(current_tail + 1), __ATOMIC_RELEASE);

    /* 
     * Double-Mapping Advantage:
     * Even if (w_ptr + total_write_size) overshoots the physical boundary, MMU page translation 
     * automatically routes memory wraps to virtual address block 2. We can perform a continuous linear copy.
     */
    hdr->pkt_len = (uint32_t)payload_total_len;
    
    if (raw_hdr && raw_hdr_len > 0) {
        memcpy(hdr->payload, raw_hdr, raw_hdr_len);
    }
    memcpy(hdr->payload + raw_hdr_len, data, data_len);

    /* Transaction Phase 2: Commit and publish valid immutable transaction generation identity token */
    __atomic_store_n(&hdr->version_seq, (uint32_t)current_tail, __ATOMIC_RELEASE);

    /* Increment and publish global monotonic virtual write offset tracker */
    buf->tail = current_tail + total_write_size;

    return 0;
}

int ringbuf_read(ringbuf_t *buf,
                 void *out_hdr_buf, size_t hdr_len,
                 void *out_data_buf, size_t max_data_len,
                 uint32_t *out_actual_data_len) {
    if (unlikely(!buf || !buf->addr || !out_data_buf || !out_actual_data_len)) return -EINVAL;

    uint64_t current_head;

    while (1) {
        current_head = __atomic_load_n(&buf->head, __ATOMIC_ACQUIRE);
        uint64_t current_tail = __atomic_load_n(&buf->tail, __ATOMIC_ACQUIRE);

        /* Queue Status Assessment: Check if stream tracks are starved of unconsumed data frames */
        if (current_head >= current_tail) {
            return -1; 
        }

        /* Calculate direct continuous reference location omitting boundary wrapping logic */
        uint8_t *r_ptr = buf->addr + (current_head % buf->size);
        ringbuf_hdr_t *hdr = (ringbuf_hdr_t *)r_ptr;

        /* 
         * Transaction Validation Alpha:
         * Verify token version snapshot integrity. If mismatch is detected, an aggressive high-throughput
         * producer has already run over this position. Discard current state loop iteration.
         */
        if (__atomic_load_n(&hdr->version_seq, __ATOMIC_ACQUIRE) != (uint32_t)current_head) {
            /* Help advance the fouled head to a safe offset alignment and skip cycle */
            __atomic_compare_exchange_n(&buf->head, &current_head, current_head + 8, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
            return -2;
        }

        uint32_t total_payload_len = hdr->pkt_len;
        size_t total_read_size = sizeof(ringbuf_hdr_t) + total_payload_len;

        /* Enforce internal bounds checks to prevent downstream buffer memory clipping overruns */
        size_t actual_pure_data_len = (total_payload_len > hdr_len) ? (total_payload_len - hdr_len) : 0;
        if (unlikely(actual_pure_data_len > max_data_len)) {
            actual_pure_data_len = max_data_len;
        }

        /* Execute deep copy isolation extraction into consumer private thread storage stack workspace */
        if (out_hdr_buf && hdr_len > 0) {
            memcpy(out_hdr_buf, hdr->payload, hdr_len);
        }
        memcpy(out_data_buf, hdr->payload + hdr_len, actual_pure_data_len);
        *out_actual_data_len = (uint32_t)actual_pure_data_len;

        /* 
         * Transaction Validation Beta:
         * Double-verify token states. Ensures the data plane payload was not overwritten or torn 
         * by the producer during the execution of the deep copy memcpy operation.
         */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (unlikely(__atomic_load_n(&hdr->version_seq, __ATOMIC_ACQUIRE) != (uint32_t)current_head)) {
            /* Memory tearing detected due to race condition overwrite. Abort current transaction frame. */
            return -2;
        }

        /* 
         * Optimistic Concurrency Race (CAS):
         * Atomically attempt to claim ownership of this frame against all other concurrent consumer threads.
         */
        if (likely(__atomic_compare_exchange_n(&buf->head, &current_head, current_head + total_read_size, 
                                               false, __ATOMIC_RELEASE, __ATOMIC_RELAXED))) {
            /* CAS success: Node processing ownership validated, exit routing safely */
            return 0;
        }
        
        /* CAS failed: Another sibling thread snatched this packet first. Loop and parse next index. */
    }
}