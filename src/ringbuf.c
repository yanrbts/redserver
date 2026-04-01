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
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ringbuf.h>

#define call_cleaner(cleaner) \
	__attribute__((__cleanup__(cleaner##_function))) __attribute__((unused))

#define close_prot_errno_disarm(fd) \
	if (fd >= 0) {                  \
		int _e_ = errno;            \
		close(fd);                  \
		errno = _e_;                \
		fd = -EBADF;                \
	}

static inline void close_prot_errno_disarm_function(int *fd) {
    close_prot_errno_disarm(*fd);
}

#define __do_close call_cleaner(close_prot_errno_disarm)

#define move_fd(fd)                         \
	({                                  \
		int __internal_fd__ = (fd); \
		(fd) = -EBADF;              \
		__internal_fd__;            \
	})

static inline uint64_t _getpagesize(void) {
	int64_t pgsz;

	pgsz = sysconf(_SC_PAGESIZE);
	if (pgsz <= 0)
		pgsz = 1 << 12;

	return pgsz;
}

static inline int set_cloexec(int fd) {
	return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int make_tmpfile(char *template, bool rm) {
    __do_close int fd = -EBADF;
    int ret;
    mode_t msk;

    msk = umask(0022);
    fd = mkstemp(template);
    umask(msk);
    if (fd < 0)
        return -1;
    
    if (set_cloexec(fd))
        return -1;
    
    if (!rm)
        return move_fd(fd);
    
    ret = unlink(template);
	if (ret < 0)
		return -1;

	return move_fd(fd);
}

int ringbuf_create(struct ringbuf *buf, size_t size) {
    __do_close int memfd = -EBADF;
    char *tmp;
    int ret;

    buf->size = size;
    buf->w_off = 0;
    buf->r_off = 0;

    /* verify that we are at least given the multiple of a page size */
    if (buf->size % _getpagesize()){
        fprintf(stderr, "ringbuf: size must be a multiple of the page size(%lu)\n", _getpagesize());
        return -EINVAL;
    }
    
    buf->addr = mmap(NULL, buf->size * 2, PROT_NONE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buf->addr == MAP_FAILED)
		return -EINVAL;
    
    /* memfd_create()  creates an anonymous file and returns a file descriptor that refers to it.  
     * The file behaves
     * like a regular file, and so can be modified, truncated, memory-mapped, and so on.  
     * However, unlike a regular file,  it  lives in RAM and has a volatile backing storage.  
     * Once all references to the file are dropped, it is automatically released.  
     * Anonymous memory is used for all backing pages of the  file.   Therefore,  files
     * created  by memfd_create() have the same semantics as other anonymous memory 
     * allocations such as those allocated using mmap(2) with the MAP_ANONYMOUS flag.*/
    memfd = memfd_create(".ringbuf", MFD_CLOEXEC);
    if (memfd < 0) {
        char template[] = "/tmp/.ringbuf_XXXXXX";

        if (errno != ENOSYS)
            goto on_error;
        
        memfd = make_tmpfile(template, true);
    }

    if (memfd < 0)
        goto on_error;
    
    ret = ftruncate(memfd, buf->size);
    if (ret < 0)
        goto on_error;
    
    tmp = mmap(buf->addr, buf->size, PROT_READ | PROT_WRITE,
		   MAP_FIXED | MAP_SHARED, memfd, 0);
	if (tmp == MAP_FAILED || tmp != buf->addr)
		goto on_error;

	tmp = mmap(buf->addr + buf->size, buf->size, PROT_READ | PROT_WRITE,
		   MAP_FIXED | MAP_SHARED, memfd, 0);
	if (tmp == MAP_FAILED || tmp != (buf->addr + buf->size))
		goto on_error;

	return 0;

on_error:
	ringbuf_release(buf);
	return -1;
}

void ringbuf_move_read_addr(struct ringbuf *buf, size_t len) {
    buf->r_off += len;

    if (buf->r_off < buf->size)
        return;
    
    /* wrap around */
	buf->r_off -= buf->size;
	buf->w_off -= buf->size;
}

int ringbuf_write(struct ringbuf *buf, const char *msg, size_t len) {
    char *w_addr;
    uint64_t free;

    /* consistency check: a write should never exceed the ringbuffer's total size */
	if (len > buf->size)
		return -EFBIG;
    
    free = ringbuf_free(buf);

    /* not enough space left so advance read address */
	if (len > free)
        ringbuf_move_read_addr(buf, len);
    
    w_addr = ringbuf_get_write_addr(buf);
    memcpy(w_addr, msg, len);

    ringbuf_move_write_addr(buf, len);

    return 0;
}

int ringbuf_read(struct ringbuf *buf, char *out, size_t *len) {
    uint64_t used;

	/* there's nothing to read */
	if (buf->r_off == buf->w_off)
		return -ENODATA;

	/* read maximum amount available */
	used = ringbuf_used(buf);
	if (used < *len)
		*len = used;

	/* copy data to reader but don't advance addr */
	memcpy(out, ringbuf_get_read_addr(buf), *len);
	out[*len - 1] = '\0';

	return 0;
}