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
#ifndef __MEMPOOL_H__
#define __MEMPOOL_H__

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef MEM_ALIGNMENT
#define MEM_ALIGNMENT       sizeof(unsigned long)    /* platform word */
#endif
#define mem_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define mem_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))
/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define MEM_MAX_ALLOC_FROM_POOL  (getpagesize() - 1)
#define MEM_DEFAULT_POOL_SIZE    (16 * 1024)
#define MEM_POOL_ALIGNMENT       16
#define MEM_MIN_POOL_SIZE                                                     \
    mem_align((sizeof(mem_pool_t) + 2 * sizeof(mem_pool_large_t)),            \
              MEM_POOL_ALIGNMENT)

typedef void (*mem_pool_cleanup_pt)(void *data);

typedef struct mem_pool_cleanup_s  mem_pool_cleanup_t;
typedef struct mem_pool_s          mem_pool_t;
typedef struct mem_pool_large_s    mem_pool_large_t;

struct mem_pool_cleanup_s {
    mem_pool_cleanup_pt   handler;
    void                 *data;
    mem_pool_cleanup_t   *next;
};

struct mem_pool_large_s {
    mem_pool_large_t     *next;
    void                 *alloc;
};

typedef struct {
    u_char              *last;
    u_char              *end;
    mem_pool_t          *next;
    uintptr_t           failed; 
} mem_pool_data_t;

struct mem_pool_s {
    mem_pool_data_t      d;
    size_t               max;
    mem_pool_t          *current;
    mem_pool_large_t    *large;
    mem_pool_cleanup_t  *cleanup;
};

typedef struct {
    int              fd;
    u_char          *name;
} mem_pool_cleanup_file_t;

mem_pool_t *mem_create_pool(size_t size);
void mem_destroy_pool(mem_pool_t *pool);
void mem_reset_pool(mem_pool_t *pool);

void *mem_palloc(mem_pool_t *pool, size_t size);
void *mem_pnalloc(mem_pool_t *pool, size_t size);
void *mem_pcalloc(mem_pool_t *pool, size_t size);
void *mem_pmemalign(mem_pool_t *pool, size_t size, size_t alignment);
int mem_pfree(mem_pool_t *pool, void *p);

mem_pool_cleanup_t *mem_pool_cleanup_add(mem_pool_t *p, size_t size);
void mem_pool_run_cleanup_file(mem_pool_t *p, int fd);
void mem_pool_cleanup_file(void *data);
void mem_pool_delete_file(void *data);

#endif