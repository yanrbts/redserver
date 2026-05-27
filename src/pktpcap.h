/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __PKTPCAP_H__
#define __PKTPCAP_H__

#include <stdint.h>
#include <stddef.h>
/**
 * @brief Initializes the unified hybrid pcap engine context.
 * 
 * Allocates descriptors, configures low-level ring buffers, and sets up
 * the underlying live handler bound to the specified interface.
 * 
 * @param ifname Name of the physical network interface (e.g., "eth0").
 * @param file   Destination storage path for the output .pcap file.
 * @return int   0 on successful initialization; -1 on validation or activation failures.
 */
int pcap_mod_init(const char *ifname, const char *file);

/**
 * @brief Performs a root-safe, atomic dynamic BPF filter hot-swap.
 * 
 * Compiles the new expression out-of-band and executes an atomic pointer exchange.
 * The life cycle of the replaced filter is safely tracked internally via atomic 
 * reference counting, preventing dangling pointer references in concurrent data paths.
 * 
 * @param expr Standard tcpdump/pcap style string filter expression (e.g., "tcp port 443").
 *             Passing NULL, an empty string, or "clear" safely disables filtering.
 * @return int 0 on a successful hot-swap; -1 if compilation or memory allocation fails.
 */
int pcap_mod_set(const char *expr);

/**
 * @brief Data-Plane Ingestion Interface for Ingress Frames (Lock-Free & Thread-Safe).
 * 
 * Tailored to ingest raw frames forwarded out of kernel space via eBPF/XDP 
 * Ring Buffers. Applies user-space dynamic BPF rules before committing matching frames to disk.
 * 
 * @param data Pointer to the start of the raw Ethernet packet bytes.
 * @param size Total byte length of the received frame payload.
 */
void pcap_mod_inject(const uint8_t *data, size_t size);

/**
 * @brief Data-Plane Ingestion Interface for Egress Frames (Thread-Safe).
 * 
 * Non-blocking loop iteration that drives the libpcap ring buffer to flush 
 * and capture host-generated outbound packets directly from the kernel descriptor.
 * 
 * @return int Number of processed and dumped packets on success; -1 on internal engine errors.
 */
int pcap_mod_poll(void);

/**
 * @brief Safely tears down the capture engine, unbinds structures, and flushes IO streams.
 */
void pcap_mod_free(void);

#endif /* PKTPCAP_H */