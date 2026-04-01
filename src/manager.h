#ifndef __MANAGER_H__
#define __MANAGER_H__

#include <stddef.h>
#include "mempool.h"
#include "ringbuf.h"

typedef struct manager{
    mem_pool_t *pool;
    struct ringbuf rb;
} gap_pkt_mgr_t;

gap_pkt_mgr_t* gap_pkt_mgr_create(size_t rb_size, size_t pool_size);
void* gap_pkt_mgr_reserve(gap_pkt_mgr_t *mgr, size_t len);
void gap_pkt_mgr_commit(gap_pkt_mgr_t *mgr, size_t len);
void gap_pkt_mgr_destroy(gap_pkt_mgr_t *mgr);

#endif