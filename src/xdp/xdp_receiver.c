/*
 * XDP Ring Buffer User-space Implementation
 * Copyright (c) 2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "xdp_receiver.h"
#include "xdp_pkt_parser.h"
#include "gap.h"
#include "log.h"

/**
 * @struct xdp_internal_ctx
 * @brief Private context structure to maintain state without global variables.
 */
struct xdp_internal_ctx {
    struct bpf_object   *obj;       /* Libbpf object handle */
    struct ring_buffer  *rb;        /* Libbpf ring buffer manager */
    int                  ifindex;   /* Network interface index */
    xdp_packet_cb        user_cb;   /* User-defined packet processor */
    void                *user_ctx;  /* User-defined context for callback */
    volatile bool        running;   /* Thread-safe loop control flag */
    bool                 verbose;   /* Toggle for debug logging */
};

/**
 * @brief Internal proxy callback for the libbpf ring buffer.
 * Translates raw ring buffer samples into packet events.
 */
static int handle_ringbuf_sample(void *ctx, void *data, size_t data_sz) {
    struct xdp_internal_ctx *ictx = ctx;
    struct packet_event *e = data;

    /* KEY POINT: Validate memory bounds before accessing the packet data */
    if (data_sz < sizeof(uint32_t) || e->pkt_len > data_sz - sizeof(uint32_t)) {
        if (ictx->verbose) {
            log_error("Corrupted ringbuf sample received\n");
        }
        return 0;
    }

    /* Execute user callback if provided; otherwise, use default parser */
    if (ictx->user_cb) {
        return ictx->user_cb(ictx->user_ctx, e->data, e->pkt_len);
    } else {
        pkt_info_t info = {0};
        if (xdp_pkt_parse_all(e->data, e->pkt_len, &info) == 0) {
            xdp_pkt_dump_log(&info);
        }
    }
    return 0;
}

void* xdp_receiver_init(const xdp_receiver_config_t *cfg, xdp_packet_cb cb) {
    if (!cfg || !cfg->bpf_obj_path || !cfg->ifname) return NULL;

    struct xdp_internal_ctx *ictx = calloc(1, sizeof(struct xdp_internal_ctx));
    if (!ictx) return NULL;

    ictx->user_cb  = cb;
    ictx->user_ctx = cfg->user_ctx;
    ictx->verbose  = cfg->verbose;
    ictx->running  = false;

    /* Convert interface name to index (e.g., "eth0" -> 2) */
    ictx->ifindex = if_nametoindex(cfg->ifname);
    if (ictx->ifindex == 0) goto cleanup;

    /* KEY POINT: Open and load the BPF object file */
    ictx->obj = bpf_object__open_file(cfg->bpf_obj_path, NULL);
    if (!ictx->obj || bpf_object__load(ictx->obj)) {
        log_error("Failed to load BPF object: %s", cfg->bpf_obj_path);
        goto cleanup;
    }

    /* Locate the ringbuf map by name defined in the C code */
    int map_fd = bpf_object__find_map_fd_by_name(ictx->obj, "pkt_ringbuf");
    if (map_fd < 0) goto cleanup;

    /* Initialize the ring buffer manager with the internal context as user data */
    ictx->rb = ring_buffer__new(map_fd, handle_ringbuf_sample, ictx, NULL);
    if (!ictx->rb) goto cleanup;

    /* KEY POINT: Attach the XDP program to the network interface.
       Using XDP_FLAGS_SKB_MODE for generic compatibility; use 0 for native driver support. */
    struct bpf_program *prog = bpf_object__find_program_by_name(ictx->obj, "xdp_packet_capture");
    if (!prog || bpf_xdp_attach(ictx->ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL) < 0) {
        log_error("Failed to attach XDP program");
        goto cleanup;
    }

    return ictx;

cleanup:
    if (ictx->rb) ring_buffer__free(ictx->rb);
    if (ictx->obj) bpf_object__close(ictx->obj);
    free(ictx);
    return NULL;
}

int xdp_receiver_start(void *ctx) {
    struct xdp_internal_ctx *ictx = ctx;
    if (!ictx) return -EINVAL;

    ictx->running = true;
    if (ictx->verbose) {
        log_info("Starting XDP receiver loop on ifindex %d...", ictx->ifindex);
    }

    /* KEY POINT: Main execution loop using non-blocking poll with 100ms timeout */
    while (ictx->running) {
        int ret = ring_buffer__poll(ictx->rb, 100);
        if (ret < 0 && ret != -EINTR) {
            log_error("Ring buffer polling error: %d\n", ret);
            return ret;
        }
    }

    return 0;
}

void xdp_receiver_exit(void *ctx) {
    struct xdp_internal_ctx *ictx = ctx;
    if (ictx) {
        /* KEY POINT: Thread-safe flag modification to break the while-loop in start() */
        ictx->running = false;
    }
}

void xdp_receiver_stop(void **ctx_ptr) {
    if (!ctx_ptr || !*ctx_ptr) return;
    struct xdp_internal_ctx *ictx = *ctx_ptr;

    /* Set running to false just in case exit() wasn't called */
    ictx->running = false;

    /* KEY POINT: Orderly resource cleanup to prevent kernel resource leaks */
    if (ictx->rb) {
        ring_buffer__free(ictx->rb);
    }

    /* Detach the XDP program from the interface before closing the object */
    if (ictx->ifindex > 0) {
        bpf_xdp_detach(ictx->ifindex, XDP_FLAGS_SKB_MODE, NULL);
    }

    if (ictx->obj) {
        bpf_object__close(ictx->obj);
    }

    free(ictx);
    *ctx_ptr = NULL; /* Prevent dangling pointers in the caller */
    
    log_info("XDP receiver resource cleanup complete");
}