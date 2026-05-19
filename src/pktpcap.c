/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <threads.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#include "util.h"
#include "log.h"
#include "pktpcap.h"

/* ANSI Industrial Color and Terminal Effect Escape Sequences */
#define COLOR_RESET   "\033[0m"
#define COLOR_TIME    "\033[34m"     /* Blue: Timestamps */
#define COLOR_MAC     "\033[90m"     /* Dark Gray: Data Link Layer Topology */
#define COLOR_TCP     "\033[1;32m"   /* Bold Green: TCP Protocol */
#define COLOR_UDP     "\033[1;36m"   /* Bold Cyan: UDP Protocol */
#define COLOR_ICMP    "\033[1;33m"   /* Bold Yellow: ICMP Protocol */
#define COLOR_OTHER   "\033[1;35m"   /* Bold Magenta: L2 Layer or Other L3 Protocols */
#define COLOR_HEX_A   "\033[33m"     /* Yellow: Hex Address Offsets */
#define COLOR_HEX_D   "\033[37m"     /* Light Gray: Raw Hex Data */
#define COLOR_HEX_C   "\033[32m"     /* Green: Sanitized ASCII Characters */

#define PCAP_RING_BUFFER_SIZE (32 * 1024 * 1024) /* 32MB ring buffer to absorb packet bursts without kernel drops */

/**
 * @struct pcap_backend_ctx
 * @brief Internal engine configuration state container.
 */
struct pcap_backend_ctx {
    pcap_t *handle;               /**< Underlying libpcap device stream handle */
    pcap_dumper_t *dumper;        /**< Kernel-to-disk persistent pcap dumper pointer */
    struct bpf_program fp;        /**< Compiled active Berkeley Packet Filter bytecode */
    int has_filter;               /**< State flag tracking active kernel compilation layout */
    atomic_uint_least8_t output_mode;          /**< Bitmask snapshot defining frame distribution targets */
    char ifname[64];                           /**< Cached interface string required for relative subnet lookups */
    
    /* Thread Management Additions */
    pthread_t worker_tid;         /**< Internally managed POSIX background worker thread ID */
    volatile int is_running;      /**< State tracking variable to validate active execution states */
    pcap_handler user_callback;   /**< Cached copy of custom user processing callback */
    u_char *user_callback_data;   /**< Cached copy of custom user pointer context */
    
    pthread_mutex_t filter_mutex; /**< Structural mutex protecting hot-swapping bytecode parameters */
};

static pcap_backend_t *g_pcap = NULL; /* Global pointer to the active engine instance for signal handlers and global access */

/**
 * @brief Renders raw binary payload data into an atomic thread-local memory stream.
 *        Guarantees a perfectly closed right-hand vertical border card layout.
 * 
 * @param stream Target thread-local virtual memory FILE stream.
 * @param payload Pointer to the start of the Layer-4 payload.
 * @param payload_len Total length of the remaining captured payload.
 */
static void pcap_internal_render_hex(FILE *stream, const u_char *payload, uint32_t payload_len) {
    /* Defensive Guard: Handle empty or severely truncated packets gracefully */
    if (!payload || payload_len == 0) {
        fprintf(stream, COLOR_MAC "  │     └── " COLOR_HEX_D "[No usable layer-4 payload or truncated]" COLOR_RESET "\n\n");
        return;
    }

    /* Production Safeguard: Throttle real-time console tracing size to absorb high-traffic bursts without hanging I/O */
    uint32_t max_dump = (payload_len > 64) ? 64 : payload_len;
    
    /* Emit the payload sub-tree root banner */
    fprintf(stream, COLOR_MAC "  │\n  ├───" COLOR_HEX_A " PAYLOAD DATA PREVIEW (%u/%u bytes) " COLOR_MAC "─" COLOR_RESET "\n", 
            max_dump, payload_len);

    char ascii_buf[17];
    uint32_t i;

    for (i = 0; i < max_dump; i++) {
        /* Inject gutter lines and memory offset headers every 16 byte boundary alignment */
        if (i % 16 == 0) {
            fprintf(stream, COLOR_MAC "  │   " COLOR_HEX_A "%04x: " COLOR_RESET, i);
        }

        /* Serialize the raw hexadecimal string representations */
        fprintf(stream, COLOR_HEX_D "%02x " COLOR_RESET, payload[i]);
        
        /* Inject an extra space delimiter every 8 bytes to speed up manual triage and audit scanning */
        if ((i + 1) % 8 == 0 && (i + 1) % 16 != 0) {
            fprintf(stream, " ");
        }

        /* Terminal Security Sanitization: Mask control bytes to neutralize escape code attacks */
        ascii_buf[i % 16] = (payload[i] >= 32 && payload[i] <= 126) ? (char)payload[i] : '.';

        /* Terminate and flush the current aligned ASCII translation row */
        if ((i + 1) % 16 == 0) {
            ascii_buf[16] = '\0';
            fprintf(stream, COLOR_MAC "│ " COLOR_HEX_C "%s" COLOR_RESET "\n", ascii_buf);
        }
    }

    /* Process unaligned trailing fragment blocks with precise space padding calculations */
    uint32_t rem = i % 16;
    if (rem != 0) {
        uint32_t written_spaces = (rem * 3);
        if (rem > 8) {
            written_spaces += 1; /* Compensate for the extra mid-row spacing offset */
        }
        
        /* A standard fully populated 16-hex section consumes exactly 49 character slots */
        uint32_t missing_spaces = 49 - written_spaces;
        for (uint32_t s = 0; s < missing_spaces; s++) {
            fprintf(stream, " ");
        }
        
        ascii_buf[rem] = '\0';
        /* Enforce a rigid left-aligned 16-character map container before discarding the row */
        fprintf(stream, COLOR_MAC "│ " COLOR_HEX_C "%-16s" COLOR_RESET "\n", ascii_buf);
    }

    /* Print a truncation hint if additional application data was squashed */
    if (payload_len > max_dump) {
        fprintf(stream, COLOR_MAC "  │   ... (%u more payload bytes compressed) ..." COLOR_RESET "\n", payload_len - max_dump);
    }
    
    fprintf(stream, "\n");
}

static void pcap_show_info(const struct pcap_pkthdr *header, const u_char *packet) {
    /* Packet Integrity Defenses: Discard corrupted runt frames smaller than an Ethernet baseline */
    if (header->caplen < sizeof(struct ethhdr)) return;

    /* 
    * ATOMIC MULTI-THREADED LOG BUFFERING LOGIC:
    * Instantiates an elastic virtual memory stream anchored into the thread's execution stack frame.
    * All discrete component serialization occurs within isolated buffers, allowing instantaneous 
    * out-of-order execution across CPU cores. The final atomic 'puts' flush completely circumvents
    * multi-threaded string interleaving without invoking locking penalties.
    */
    char *log_buffer = NULL;
    size_t log_size = 0;
    FILE *mem_stream = open_memstream(&log_buffer, &log_size);
    if (!mem_stream) return; 

    struct ethhdr *eth = (struct ethhdr *)packet;
    
    /* Transform raw ingest microsecond timestamps into localized ISO-8601 frames */
    char time_str[32];
    struct tm ltime;
    localtime_r(&header->ts.tv_sec, &ltime); 
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &ltime);

    /* Extract Layer-2 Hardware MAC Addresses */
    char src_mac[18], dst_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                eth->h_source[0], eth->h_source[1], eth->h_source[2],
                eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    /* Core L3 Slicing: Inspect and map IPv4 packet wrappers */
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        uint32_t min_ip_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (header->caplen >= min_ip_offset) {
            struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
            
            /* Dynamic Header Offset Evaluation: Read the 'ihl' field to account for optional fields */
            uint32_t ip_hl = ip->ihl * 4;
            if (ip_hl < sizeof(struct iphdr) || header->caplen < sizeof(struct ethhdr) + ip_hl) {
                fclose(mem_stream);
                free(log_buffer);
                return; /* Deflect intentionally fuzzed/malformed fragment drop evasion vectors */
            }

            /* Fast translation of network-ordered binary addresses to alphanumeric strings */
            char ip_src_str[INET_ADDRSTRLEN];
            char ip_dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->saddr, ip_src_str, sizeof(ip_src_str));
            inet_ntop(AF_INET, &ip->daddr, ip_dst_str, sizeof(ip_dst_str));

            uint32_t l4_offset = sizeof(struct ethhdr) + ip_hl;
            const u_char *payload_ptr = NULL;
            int32_t payload_len = 0;
            uint16_t src_port = 0, dst_port = 0;
            
            const char *proto_color = COLOR_OTHER;
            char proto_str[8] = "IP";

            /* Core L4 Demuxing: TCP vs UDP vs ICMP Parsing loops */
            if (ip->protocol == IPPROTO_TCP) {
                proto_color = COLOR_TCP;
                strcpy(proto_str, "TCP ");
                if (header->caplen >= l4_offset + sizeof(struct tcphdr)) {
                    struct tcphdr *tcp = (struct tcphdr *)(packet + l4_offset);
                    src_port = ntohs(tcp->source);
                    dst_port = ntohs(tcp->dest);
                    
                    /* Dynamically adjust the TCP payload window offset by tracking variable options fields */
                    uint32_t tcp_hl = tcp->doff * 4;
                    if (tcp_hl >= sizeof(struct tcphdr) && header->caplen >= l4_offset + tcp_hl) {
                        payload_ptr = packet + l4_offset + tcp_hl;
                        payload_len = (int32_t)header->caplen - (l4_offset + tcp_hl);
                    }
                }
            } 
            else if (ip->protocol == IPPROTO_UDP) {
                proto_color = COLOR_UDP;
                strcpy(proto_str, "UDP ");
                if (header->caplen >= l4_offset + sizeof(struct udphdr)) {
                    struct udphdr *udp = (struct udphdr *)(packet + l4_offset);
                    src_port = ntohs(udp->source);
                    dst_port = ntohs(udp->dest);
                    
                    payload_ptr = packet + l4_offset + sizeof(struct udphdr);
                    payload_len = (int32_t)header->caplen - (l4_offset + sizeof(struct udphdr));
                }
            }
            else if (ip->protocol == IPPROTO_ICMP) {
                proto_color = COLOR_ICMP;
                strcpy(proto_str, "ICMP");
                payload_ptr = packet + l4_offset;
                payload_len = (int32_t)header->caplen - l4_offset;
            }

            /* Block mathematical integer underflows caused by fuzzed capture frames */
            if (payload_len < 0) payload_len = 0;

            /* Section 1: Output the stream-lined telemetry banner */
            fprintf(mem_stream, COLOR_TIME " %s.%06ld " COLOR_RESET "%s[%s]" COLOR_RESET " ────────────────────────────────────\n", 
                    time_str, header->ts.tv_usec, proto_color, proto_str);
            
            /* Section 2: Emit the Network Layer Socket Tuple (L3/L4 Topology) */
            if (src_port > 0 || dst_port > 0) {
                fprintf(mem_stream, COLOR_MAC "  ├── " COLOR_TCP "NETWORK:" COLOR_RESET " %s:%d → %s:%d\n", ip_src_str, src_port, ip_dst_str, dst_port);
            } else {
                fprintf(mem_stream, COLOR_MAC "  ├── " COLOR_TCP "NETWORK:" COLOR_RESET " %s → %s\n", ip_src_str, ip_dst_str);
            }
            
            /* Section 3: Emit Data Link Hardware Topology and Capture Statistics (L2 Topology) */
            fprintf(mem_stream, COLOR_MAC "  ├── " COLOR_MAC "LINK   :" COLOR_RESET " %s → %s  " COLOR_MAC "[Wire: %uB | Cap: %uB]\n", 
                    src_mac, dst_mac, header->len, header->caplen);

            /* Section 4: Render Application Payload Trees */
            pcap_internal_render_hex(mem_stream, payload_ptr, (uint32_t)payload_len);
        }
    } else {
        /* Fallback Pipeline: Track alternative non-IP profiles (e.g., ARP, VLAN tagging, LLDP) */
        fprintf(mem_stream, COLOR_TIME " %s.%06ld " COLOR_RESET COLOR_OTHER "[L2-OTHER: 0x%04x]" COLOR_RESET " ────────────────────────────────────\n", 
                time_str, header->ts.tv_usec, ntohs(eth->h_proto));
        fprintf(mem_stream, COLOR_MAC "  └── " COLOR_MAC "LINK   :" COLOR_RESET " %s → %s  " COLOR_MAC "[Cap: %uB]\n\n", 
                src_mac, dst_mac, header->caplen);
    }

    /* Commit and Flush Step: Close memory streams and execute atomic stdout logging delivery */
    fclose(mem_stream);
    if (log_buffer) {
        puts(log_buffer);
        free(log_buffer); /* Reclaim heap blocks to prevent long-term memory allocation fragmentation */
    }
}

/**
 * @brief Gateway core telemetry callback router invoked on every captured frame event.
 */
static void pcap_default_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_backend_t *ctx = (pcap_backend_t *)user;
    if (!ctx || !packet) return;

    uint8_t current_mode = atomic_load_explicit(&ctx->output_mode, memory_order_acquire);
    /* Data Plane Path: Zero-copy high-efficiency raw packet serialization to local storage */
    if ((current_mode & PCAP_OUT_FILE) && ctx->dumper) {
        pcap_dump((u_char *)ctx->dumper, header, packet);

        static __thread uint32_t pkt_counter = 0;
        if (unlikely((++pkt_counter & 15) == 0)) {
            pcap_dump_flush(ctx->dumper);
        }
    }

    if (ctx->user_callback) {
        ctx->user_callback(ctx->user_callback_data, header, packet);
    }
    /* Control Plane Path: Live diagnostic logging and console streaming */
    if (current_mode & PCAP_OUT_CONSOLE) {
        pcap_show_info(header, packet);
    }
}

/**
 * @brief Private internal blocking execution loop wrapper.
 *        Maps fatal driver/interface runtime disconnects directly to signature logs.
 */
static void pcap_engine_internal_loop(pcap_backend_t *ctx) {
    int ret;

    ret = pcap_loop(ctx->handle, 0, pcap_default_callback, (u_char *)ctx);
    if (ret == -1) {
        log_error("[PCAP] Low-level subsystem encountered a fatal fault: %s\n", pcap_geterr(ctx->handle));
    }
}

/**
 * @brief Static POSIX thread routine wrapper to bootstrap the private internal handler loop.
 */
static void* pcap_worker_thread_stub(void *arg) {
    pcap_backend_t *ctx = (pcap_backend_t *)arg;
    
    pcap_engine_internal_loop(ctx);
    
    /* Mark running flag down immediately upon loop 
     * rupture to synchronize cross-thread states */
    ctx->is_running = 0;
    return NULL;
}

pcap_backend_t* pcap_engine_init(const char *ifname, 
                                 const char *bpf_filter, 
                                 int promiscuous, 
                                 uint8_t output_mode,
                                 const char *save_path
                                ) {
    if (unlikely(!ifname)) return NULL;

    pcap_backend_t *ctx = calloc(1, sizeof(pcap_backend_t));
    if (unlikely(!ctx)) {
        log_error("[PCAP] Out of memory allocating backend context.");
        return NULL;
    }
    
    // ctx->output_mode = output_mode;
    atomic_init(&ctx->output_mode, output_mode);
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);

    /* Allocate structure synchronization mutex to govern hot-swap transactions */
    if (pthread_mutex_init(&ctx->filter_mutex, NULL) != 0) {
        log_error("[PCAP] Failed to initialize framework internal mutex lock.");
        free(ctx);
        return NULL;
    }

    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
    /* Initialize unactivated session wrapper context */
    ctx->handle = pcap_create(ifname, pcap_errbuf);
    if (unlikely(!ctx->handle)) {
        log_error("[PCAP] Failed to create pcap handle: %s", pcap_errbuf);
        pthread_mutex_destroy(&ctx->filter_mutex);
        free(ctx);
        return NULL;
    }

    pcap_set_buffer_size(ctx->handle, PCAP_RING_BUFFER_SIZE);   /* 32MB ring buffer to absorb packet bursts without kernel drops */
    pcap_set_snaplen(ctx->handle, 65535);                       /* Set snaplen to max MTU boundary to capture complete Jumbo frames */
    pcap_set_promisc(ctx->handle, promiscuous);                 /* Toggle hardware promiscuous packet ingestion matrix */
    pcap_set_timeout(ctx->handle, 100);                         /* 100ms batching flush timeout reduces CPU context-switch interrupts */

    /* Commit parameters and activate interface session handle */
    int status = pcap_activate(ctx->handle);
    if (unlikely(status < 0)) {
        log_error("[PCAP] Activation failed: %s", pcap_geterr(ctx->handle));
        goto err;
    }

    /* Initialize persistent disk dumper stream when FILE mask routing is enabled */
    if ((output_mode & PCAP_OUT_FILE) && save_path) {
        ctx->dumper = pcap_dump_open(ctx->handle, save_path);
        if (!ctx->dumper) {
            log_error("[PCAP] Failed to open dump file: %s", pcap_geterr(ctx->handle));
            goto err;
        }
    }

    /* Apply initial filter rules via optimized thread-safe injector */
    if (bpf_filter && strlen(bpf_filter) > 0) {
        if (pcap_engine_update_filter(ctx, bpf_filter) < 0) {
            goto err;
        }
    }

    ctx->is_running = 0;
    g_pcap = ctx;
    return ctx;

err:
    if (ctx) {
        if (ctx->dumper) pcap_dump_close(ctx->dumper);
        if (ctx->handle) pcap_close(ctx->handle);
        pthread_mutex_destroy(&ctx->filter_mutex);
        free(ctx);
    }
    return NULL;
}

int pcap_engine_start(pcap_backend_t *ctx, pcap_handler callback, u_char *user_data) {
    if (unlikely(!ctx || !ctx->handle)) return -1;

    pthread_mutex_lock(&ctx->filter_mutex);
    
    /* Guard against duplicate execution tracking threads */
    if (unlikely(ctx->is_running)) {
        pthread_mutex_unlock(&ctx->filter_mutex);
        return 0; 
    }

    /* Cache callback configuration metrics safely before starting the thread entry wrapper */
    ctx->user_callback = callback;
    ctx->user_callback_data = user_data;
    ctx->is_running = 1;

    /* Spawn the dedicated asynchronous network-ingestion data plane thread */
    if (pthread_create(&ctx->worker_tid, NULL, pcap_worker_thread_stub, ctx) != 0) {
        ctx->is_running = 0;
        ctx->user_callback = NULL;
        ctx->user_callback_data = NULL;
        pthread_mutex_unlock(&ctx->filter_mutex);
        return -2;
    }

    pthread_mutex_unlock(&ctx->filter_mutex);
    return 0;
}

int pcap_engine_stop(pcap_backend_t *ctx) {
    if (unlikely(!ctx || !ctx->handle)) return -1;

    pthread_mutex_lock(&ctx->filter_mutex);
    if (unlikely(!ctx->is_running)) {
        pthread_mutex_unlock(&ctx->filter_mutex);
        return -1;
    }

    /* Mark intent flag down and force execution break on the low-level handle */
    ctx->is_running = 0;
    pcap_breakloop(ctx->handle);
    pthread_mutex_unlock(&ctx->filter_mutex);

    /* Synchronously wait for the data plane thread to terminate cleanly */
    pthread_join(ctx->worker_tid, NULL);
    
    ctx->user_callback = NULL;
    ctx->user_callback_data = NULL;
    return 0;
}

int pcap_engine_update_filter(pcap_backend_t *ctx, const char *new_bpf_filter) {
    if (unlikely(!ctx || !ctx->handle)) return -1;

    bpf_u_int32 net, mask;
    struct bpf_program new_fp;
    int has_new_filter = 0;
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};

    /* Phase 1: Subnet evaluation (Executed out of lock bounds to limit critical path exposure) */
    if (pcap_lookupnet(ctx->ifname, &net, &mask, pcap_errbuf) < 0) {
        net = PCAP_NETMASK_UNKNOWN;
    }

    /* Phase 2: Compile BPF rules out-of-lock. Syntactical errors intercept here without blocking consumer threads */
    if (new_bpf_filter && strlen(new_bpf_filter) > 0) {
        if (pcap_compile(ctx->handle, &new_fp, new_bpf_filter, 1, net) < 0) {
            log_error("[PCAP] Dynamic BPF Compile error: %s", pcap_geterr(ctx->handle));
            return -2;
        }
        has_new_filter = 1;
    }

    /* Phase 3: Enter micro-critical section to modify active bytecode registers safely */
    pthread_mutex_lock(&ctx->filter_mutex);

    if (has_new_filter) {
        /* Swap configuration inside active system kernel atomically */
        if (pcap_setfilter(ctx->handle, &new_fp) < 0) {
            log_error("[PCAP] Dynamic BPF Injection error: %s", pcap_geterr(ctx->handle));
            pcap_freecode(&new_fp);
            pthread_mutex_unlock(&ctx->filter_mutex);
            return -3;
        }

        /* Free user-space heap allocation allocated by historical compiled bytecode rules */
        if (ctx->has_filter) {
            pcap_freecode(&ctx->fp);
        }

        /* Update context descriptors */
        ctx->fp = new_fp;
        ctx->has_filter = 1;
        log_info("[PCAP] Filter successfully hot-swapped to: \"%s\"", new_bpf_filter);

    } else {
        /* Stripping active filters. Disconnect network layer dependencies prior to structural free */
        if (ctx->has_filter) {
            pcap_setfilter(ctx->handle, NULL); 
            pcap_freecode(&ctx->fp);
            ctx->has_filter = 0;
            log_info("[PCAP] Filter dynamically cleared. Capturing ALL network traffic.");
        }
    }

    pthread_mutex_unlock(&ctx->filter_mutex);
    return 0;
}

int pcap_engine_set_filter(const char *new_bpf_filter) {
    if (unlikely(!g_pcap)) return -1;
    return pcap_engine_update_filter(g_pcap, new_bpf_filter);
}

void pcap_engine_destroy(pcap_backend_t *ctx) {
    if (unlikely(!ctx)) return;
    
    /* Stop internal thread gracefully if still up and processing */
    if (ctx->is_running) {
        pcap_engine_stop(ctx);
    }
    
    pthread_mutex_lock(&ctx->filter_mutex);
    if (ctx->has_filter) {
        pcap_freecode(&ctx->fp);
    }
    
    /* Order of Operations Protection: File streams must flush and unbind before master handles 
       close out completely to guarantee file integrity and prevent trailing frame truncation. */
    if (ctx->dumper) {
        pcap_dump_flush(ctx->dumper); 
        pcap_dump_close(ctx->dumper);
    }
    
    if (ctx->handle) {
        pcap_close(ctx->handle);
    }

    pthread_mutex_unlock(&ctx->filter_mutex);
    
    pthread_mutex_destroy(&ctx->filter_mutex);
    free(ctx);
}

/**
 * @brief Dynamically hot-swaps the packet distribution target bitmask in a lock-free, thread-safe manner.
 * 
 * This method directly updates the active output routing state using atomic stores, bypassing
 * the heavy structural filter_mutex to prevent critical-path data plane stalls.
 * 
 * @param mode  New bitmask combination topology (e.g., PCAP_OUT_FILE | PCAP_OUT_MEMORY).
 * @return int  0 upon successful injection, or -1 if the backend context is invalid.
 */
int pcap_engine_set_output_mode(uint8_t mode) {
    if (unlikely(!g_pcap)) return -1;

    if (unlikely((mode & ~PCAP_OUT_VALID_MASK) != 0)) {
        log_error("[PCAP] Rejecting illegal output mode bitmask injection: 0x%02X", mode);
        return -2;
    }

    /* 
     * Commit the routing mask update atomically to prevent cross-core data races.
     * The 'memory_order_release' fence guarantees that all preceding control plane configuration
     * writes are synchronized and made visible to the data plane worker loop immediately.
     */
    atomic_store_explicit(&g_pcap->output_mode, mode, memory_order_release);

    if (!(mode & PCAP_OUT_FILE) && g_pcap->dumper) {
        pcap_dump_flush(g_pcap->dumper);
    }
    
    log_info("[PCAP] Output mode dynamically hot-swapped to mask: 0x%02X", mode);
    return 0;
}

// int pcap_write_node(pcap_backend_t *ctx, const pcap_packet_node_t *node) {
//     if (unlikely(!ctx || !node)) return -EINVAL;

//     /* 
//      * Optimization: Only commit active packet regions (sizeof(header) + node->len).
//      * This avoids writing unused buffer padding slots on small packets.
//      */
//     return ringbuf_write(&ctx->ring_buf, 
//                          &node->header, sizeof(struct pcap_pkthdr), 
//                          node->data, node->len);
// }

// int pcap_read_node(pcap_backend_t *ctx, pcap_packet_node_t *out_node) {
//     if (unlikely(!ctx || !out_node)) return -EINVAL;

//     uint32_t actual_payload_len = 0;

//     /* Route the metadata directly into .header and streams directly into the internal .data bounds */
//     int ret = ringbuf_read(&ctx->ring_buf,
//                            &out_node->header, sizeof(struct pcap_pkthdr),
//                            out_node->data, PCAP_MAX_PACKET_SIZE,
//                            &actual_payload_len);
//     if (likely(ret == 0)) {
//         out_node->len = actual_payload_len;
//     }
//     return ret;
// }