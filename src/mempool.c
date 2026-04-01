/*
 * Copyright (c) 2024-2024, yanruibinghxu@gmail.com All rights reserved.
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
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
#include <stdlib.h>
#include <string.h>
#include "mempool.h"
#include "zmalloc.h"

#define mem_malloc zmalloc
#define mem_realloc zrealloc
#define mem_free zfree

static inline void *mem_palloc_small(mem_pool_t *pool, size_t size, uintptr_t align);
static void *mem_palloc_large(mem_pool_t *pool, size_t size);
static void *mem_palloc_block(mem_pool_t *pool, size_t size);

static void *mem_memalign(size_t alignment, size_t size) {
    void *p;
    int err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        p = NULL;
    }

    return p;
}

mem_pool_t *mem_create_pool(size_t size) {
    mem_pool_t   *p;

    p = mem_memalign(MEM_POOL_ALIGNMENT, size);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char*)p + sizeof(mem_pool_t);
    p->d.end = (u_char*)p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(mem_pool_t);
    p->max = (size < MEM_MAX_ALLOC_FROM_POOL) ? size : MEM_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->large = NULL;
    p->cleanup = NULL;

    return p;
}

void mem_destroy_pool(mem_pool_t *pool) {
    mem_pool_t          *p, *n;
    mem_pool_large_t    *l;
    mem_pool_cleanup_t  *c;

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            c->handler(c->data);
        }
    }

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        free(p);

        if (n == NULL) {
            break;
        }
    }
}

void mem_reset_pool(mem_pool_t *pool) {
    mem_pool_t        *p;
    mem_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            free(l->alloc);
        }
    }

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *)p + sizeof(mem_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->large = NULL;
}

void *mem_palloc(mem_pool_t *pool, size_t size) {
    if (size <= pool->max) {
        return mem_palloc_small(pool, size, 1);
    }

    return mem_palloc_large(pool, size);
}

void *mem_pnalloc(mem_pool_t *pool, size_t size) {
    if (size <= pool->max) {
        return mem_palloc_small(pool, size, 0);
    }

    return mem_palloc_large(pool, size);
}

static inline void *
mem_palloc_small(mem_pool_t *pool, size_t size, uintptr_t align) {
    u_char      *m;
    mem_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = mem_align_ptr(m, MEM_ALIGNMENT);
        }

        if ((size_t)(p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return mem_palloc_block(pool, size);
}

static void *
mem_palloc_block(mem_pool_t *pool, size_t size) {
    u_char      *m;
    size_t       psize;
    mem_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *)pool);

    m = mem_memalign(MEM_POOL_ALIGNMENT, psize);
    if (m == NULL) {
        return NULL;
    }

    new = (mem_pool_t*)m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(mem_pool_data_t);
    m = mem_align_ptr(m, MEM_ALIGNMENT);
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}

static void *
mem_palloc_large(mem_pool_t *pool, size_t size) {
    void              *p;
    uintptr_t          n;
    mem_pool_large_t  *large;

    p = mem_malloc(size);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    large = mem_palloc_small(pool, sizeof(mem_pool_large_t), 1);
    if (large == NULL) {
        mem_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

void *mem_pmemalign(mem_pool_t *pool, size_t size, size_t alignment) {
    void              *p;
    mem_pool_large_t  *large;

    p = mem_memalign(alignment, size);
    if (p == NULL) {
        return NULL;
    }

    large = mem_palloc_small(pool, sizeof(mem_pool_large_t), 1);
    if (large == NULL) {
        free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}

void *mem_pcalloc(mem_pool_t *pool, size_t size) {
    void *p;

    p = mem_palloc(pool, size);
    if (p) {
        memset(p, 0, size);
    }

    return p;
}

int mem_pfree(mem_pool_t *pool, void *p) {
    mem_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            free(l->alloc);
            l->alloc = NULL;
            
            return 0;
        }
    }
    return -1;
}

mem_pool_cleanup_t *mem_pool_cleanup_add(mem_pool_t *p, size_t size) {
    mem_pool_cleanup_t  *c;

    c = mem_palloc(p, sizeof(mem_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = mem_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }
    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    return c;
}

void mem_pool_run_cleanup_file(mem_pool_t *p, int fd) {
    mem_pool_cleanup_t       *c;
    mem_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == mem_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}

void mem_pool_cleanup_file(void *data) {
    mem_pool_cleanup_file_t  *c = data;

    close(c->fd);
}

void mem_pool_delete_file(void *data) {
    mem_pool_cleanup_file_t  *c = data;

    unlink(c->name);
    close(c->fd);
}