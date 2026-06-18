/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pcap/pcap.h>

#include "util.h"
#include "log.h"
#include "pktpcap.h"

#define PCAP_BUFFER_SIZE (16 * 1024 * 1024) /* 16MB ring buffer size for high-throughput capture */
/**
 * @brief Reference-counted container wrapping the standard BPF filter structure.
 * Provides lock-free memory tracking capabilities across multi-threaded operations.
 */
typedef struct {
    struct bpf_program fp; /**< Underlying compiled pcap filter structural bytecode */
    int ref_count;         /**< Atomic execution reference count counter */
} safe_filter_t;

/**
 * @brief Unified global engine context encapsulation tracking static state.
 */
typedef struct {
    pcap_t *pcap;
    char file_path[256];   /**< Persistent storage path for the output .pcap file */
    pcap_dumper_t *dumper;
    safe_filter_t *filter; /**< Atomic pointer targeting the active dynamic filter container */
} pktpcap_t;

static pktpcap_t g_ctx = { .pcap = NULL, .file_path = {0}, .dumper = NULL, .filter = NULL };

/**
 * @brief Initializes the pcap capturing module, configures interface properties,
 * and opens the unified storage stream dumper.
 * 
 * @param ifname Network interface name to capture from (e.g., "eth0").
 * @param file   Target file path where captured frames will be recorded.
 * @return int   0 on success, -1 on failure.
 */
int pcap_mod_init(const char *ifname, const char *file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (unlikely(!ifname || !file)) return -1;

    strncpy(g_ctx.file_path, file, sizeof(g_ctx.file_path) - 1);
    g_ctx.file_path[sizeof(g_ctx.file_path) - 1] = '\0';

    /* Create the live capture handler to intercept traffic */
    g_ctx.pcap = pcap_create(ifname, errbuf);
    if (unlikely(!g_ctx.pcap)) {
        log_error("Failed to create pcap handler: %s", errbuf);
        return -1;
    }
    
    /* Configure advanced industrial-grade capturing ring-buffer parameters */
    pcap_set_snaplen(g_ctx.pcap, 65535);
    // pcap_set_promisc(g_ctx.pcap, 1);
    pcap_set_timeout(g_ctx.pcap, 100);                  /* 100ms timeout for packet buffering */
    pcap_set_buffer_size(g_ctx.pcap, PCAP_BUFFER_SIZE); /* 16MB ring buffer allocated in kernel */

    /* Activate the packet capture handle */
    if (pcap_activate(g_ctx.pcap) < 0) {
        pcap_close(g_ctx.pcap);
        g_ctx.pcap = NULL;
        return -1;
    }

    /* Dynamically evaluate and log the absolute Data Link Type assigned by the kernel */
    int actual_dlt = pcap_datalink(g_ctx.pcap);
    log_info("Actual pcap live datalink type is: %d (%s)", actual_dlt, pcap_datalink_val_to_name(actual_dlt));

    /**
     * Bind dual-directional sniffing constraints.
     * Unifies the underlying monitoring pipe to allow symmetrical processing 
     * of outbound egress frames alongside intercepted ingress XDP shadow copies.
     */
    pcap_setdirection(g_ctx.pcap, PCAP_D_INOUT);

    /* Open the unified output pcap storage file */
    g_ctx.dumper = pcap_dump_open(g_ctx.pcap, file);
    if (!g_ctx.dumper) {
        pcap_close(g_ctx.pcap);
        g_ctx.pcap = NULL;
        return -1;
    }

    /* Transition packet capture descriptor into non-blocking polling state */
    pcap_setnonblock(g_ctx.pcap, 1, errbuf);
    g_ctx.filter = NULL;
    return 0;
}

/**
 * @brief Dynamically compiles and atomically hot-swaps the underlying BPF filters
 * without interrupting active packet processing loops.
 * 
 * @param expr The high-level BPF filter string expression (e.g., "udp port 48350").
 * @return int 0 on success, -1 on compilation failure.
 */
int pcap_mod_set(const char *expr) {
    if (unlikely(!g_ctx.pcap)) return -1;

    safe_filter_t *new_filter = NULL;

    /* Step 1: Pre-compile bytecode offline to guarantee no blind-spots during swaps */
    if (expr && expr[0] != '\0' && strcmp(expr, "clear") != 0) {
        new_filter = malloc(sizeof(safe_filter_t));
        if (!new_filter) return -1;
        
        new_filter->ref_count = 1;

        /* Compiles expression directly aligned against active handle constraints */
        if (pcap_compile(g_ctx.pcap, &new_filter->fp, expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            log_error("BPF Compile failed for '%s': %s", expr, pcap_geterr(g_ctx.pcap));
            free(new_filter);
            return -1;
        }
    }

    /* Step 2: Atomic Exchange. Instantly switches runtime filters without locking barriers */
    safe_filter_t *old_filter = __atomic_exchange_n(&g_ctx.filter, new_filter, __ATOMIC_SEQ_CST);

    /* Step 3: Synchronize filter rules to kernel network stack to assist polling loops */
    if (g_ctx.pcap) {
        if (new_filter) {
            pcap_setfilter(g_ctx.pcap, &new_filter->fp);
        } else {
            pcap_setfilter(g_ctx.pcap, NULL);
        }
    }

    /* Step 4: Safely evaluate and clean up the evicted old filter container */
    if (old_filter) {
        if (__atomic_sub_fetch(&old_filter->ref_count, 1, __ATOMIC_SEQ_CST) == 0) {
            pcap_freecode(&old_filter->fp);
            free(old_filter);
        }
    }

    return 0;
}

/**
 * @brief Injects an externally intercepted frame buffer (e.g., from an XDP program)
 * manually evaluated against active user-space filters into storage.
 * 
 * @param data Byte pointer targeting raw Ethernet frame payload memory.
 * @param size Linear size constraint of the buffered frame.
 */
void pcap_mod_inject(const uint8_t *data, size_t size) {
    if (unlikely(!g_ctx.dumper || !data || size == 0)) return;

    safe_filter_t *local_filter = NULL;

    /* Lock-Free Lease Shield: Safely lease a reference to the active filter runtime */
    while (1) {
        local_filter = __atomic_load_n(&g_ctx.filter, __ATOMIC_ACQUIRE);
        if (!local_filter) break;

        /* Increment the thread usage tracking claim counter atomically */
        __atomic_fetch_add(&local_filter->ref_count, 1, __ATOMIC_SEQ_CST);

        /* Double-Check Barrier: Ensure the leased filter wasn't swapped out mid-increment */
        if (likely(local_filter == __atomic_load_n(&g_ctx.filter, __ATOMIC_ACQUIRE))) {
            break; /* Reference locked securely; safe to proceed to execution */
        }

        /* Race detected: Revert the mistakenly incremented token and evaluate self-destruction */
        if (__atomic_sub_fetch(&local_filter->ref_count, 1, __ATOMIC_SEQ_CST) == 0) {
            pcap_freecode(&local_filter->fp);
            free(local_filter);
        }
    }

    /* Construct standard metadata headers for the storage pcap dumper */
    struct pcap_pkthdr hdr;
    gettimeofday(&hdr.ts, NULL);
    hdr.caplen = (bpf_u_int32)size;
    hdr.len    = (bpf_u_int32)size;

    int match = 1;

    if (local_filter) {
        /* Bytecode evaluation is safe from crashes; memory is guaranteed stable by ref_count */
        match = pcap_offline_filter(&local_filter->fp, &hdr, data);

        /* Return the filter lease token */
        if (__atomic_sub_fetch(&local_filter->ref_count, 1, __ATOMIC_SEQ_CST) == 0) {
            /* Handled final cleanups if the filter was swapped out during evaluation */
            pcap_freecode(&local_filter->fp);
            free(local_filter);
        }
    }

    if (match == 0) {
        return; /* Frame rejected by the dynamic matching rule criteria */
    }

    /* Commit the authenticated frame snapshot down into the underlying file stream */
    pcap_dump((u_char *)g_ctx.dumper, &hdr, data);
    pcap_dump_flush(g_ctx.dumper);
}

/**
 * @brief Standard packet dispatch sink callback. Natively routes captured 
 *        live frames verified by the kernel BPF directly to disk.
 */
static void packet_handler(u_char *user, const struct pcap_pkthdr *head, const u_char *bytes) {
    pcap_dumper_t *dumper = (pcap_dumper_t *)user;
    if (likely(dumper)) {
        pcap_dump((u_char *)dumper, head, bytes);
        pcap_dump_flush(dumper);
    }
}

/**
 * @brief Non-blocking poller invoked within execution loops to harvest 
 * and flush buffered live-capture wire frames from the network interface.
 * @return int Total processed packet execution count, or -1 on runtime errors.
 */
int pcap_mod_poll(void) {
    if (unlikely(!g_ctx.pcap || !g_ctx.dumper)) return -1;
    
    /* Fetch and flush all natively captured egress/ingress host frames via libpcap engine */
    return pcap_dispatch(g_ctx.pcap, -1, packet_handler, (u_char *)g_ctx.dumper);
}

/**
 * @brief Gracefully tears down the network capture engine, synchronization tokens,
 * and releases persistent file storage resource maps.
 */
void pcap_mod_free(void) {
    if (g_ctx.dumper) {
        /* Flushes buffered operational page caches cleanly down to physical disk storage */
        pcap_dump_close(g_ctx.dumper);
        g_ctx.dumper = NULL;
    }

    /* Safely clear and evict the active global filter registration tracking */
    safe_filter_t *fp = __atomic_exchange_n(&g_ctx.filter, NULL, __ATOMIC_SEQ_CST);
    if (fp) {
        if (__atomic_sub_fetch(&fp->ref_count, 1, __ATOMIC_SEQ_CST) == 0) {
            pcap_freecode(&fp->fp);
            free(fp);
        }
    }

    if (g_ctx.pcap) {
        pcap_close(g_ctx.pcap);
        g_ctx.pcap = NULL;
    }
}