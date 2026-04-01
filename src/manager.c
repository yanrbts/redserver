#include <stdlib.h>
#include <string.h>
#include "manager.h"

gap_pkt_mgr_t* gap_pkt_mgr_create(size_t rb_size, size_t pool_size) {
    // 使用内存池分配管理器自身
    mem_pool_t *pool = mem_create_pool(pool_size);
    if (!pool) return NULL;

    gap_pkt_mgr_t *mgr = mem_palloc(pool, sizeof(gap_pkt_mgr_t));
    mgr->pool = pool;

    if (ringbuf_create(&mgr->rb, rb_size) != 0) {
        mem_destroy_pool(pool);
        return NULL;
    }
    return mgr;
}

void* gap_pkt_mgr_reserve(gap_pkt_mgr_t *mgr, size_t len) {
    if (ringbuf_free(&mgr->rb) < len) return NULL;
    // 直接返回镜像内存的写地址
    return ringbuf_get_write_addr(&mgr->rb);
}

void gap_pkt_mgr_commit(gap_pkt_mgr_t *mgr, size_t len) {
    ringbuf_move_write_addr(&mgr->rb, len);
}

void gap_pkt_mgr_destroy(gap_pkt_mgr_t *mgr) {
    ringbuf_release(&mgr->rb);
    mem_destroy_pool(mgr->pool);
}
