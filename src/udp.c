/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>  // For ETH_P_ALL
#include <sys/ioctl.h>      // For ioctl()
#include <linux/if_packet.h>

#include "log.h"
#include "udp.h"

#ifndef IP_OFFMASK
#define IP_OFFMASK      0x1fff
#endif

#define ETH_ALEN        6
#define IP_H_SIZE       20
#define UDP_H_SIZE      8
#define MAX_PAYLOAD     1480  /* (1500 - 20), must be multiple of 8 */
#define FRAG_UNIT       8

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
} __attribute__((packed));

/**
 * @brief Incremental 16-bit 1's complement sum accumulator.
 * @param data Pointer to the data buffer.
 * @param len Length of the data in bytes.
 * @param initial_sum Current accumulated sum (for chaining).
 * @return 32-bit intermediate sum.
 */
static inline uint32_t checksum_accumulate(const void *data, size_t len, uint32_t initial_sum) {
    const uint8_t *ptr = (const uint8_t *)data;
    uint32_t sum = initial_sum;

    /* Process 2 bytes at a time */
    while (len > 1) {
        uint16_t word;
        /* Use memcpy to prevent unaligned access exceptions on ARM/MIPS */
        sum += ((uint32_t)ptr[0] << 8) | (uint32_t)ptr[1];
        ptr += 2;
        len -= 2;
    }

    /* Handle remaining odd byte if present */
    if (len > 0) {
        /* Per RFC 1071: Odd byte is treated as the MSB of a 16-bit word (padded with 0) */
        sum += ((uint32_t)ptr[0] << 8);
    }
    return sum;
}

/**
 * @brief Finalizes the checksum by folding bits and performing bitwise NOT.
 * @param sum The 32-bit accumulated sum.
 * @return The final 16-bit checksum in network byte order.
 */
static inline uint16_t checksum_finalize(uint32_t sum) {
    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* Initializes the UDP connection handle.
 * Sets up kernel buffers and allows for high-performance packet handling.
 */
udp_conn_t* udp_init_listener(uint16_t port, int recv_buf_mb) {
    udp_conn_t *conn = (udp_conn_t *)malloc(sizeof(udp_conn_t));
    if (!conn) return NULL;

    /* Use SOCK_CLOEXEC for security in multi-process environments */
    conn->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (conn->fd < 0) {
        log_error("Socket creation failed: %s", strerror(errno));
        free(conn);
        return NULL;
    }

    /* Initialize cached timeout to -1 to force the first setsockopt call */
    conn->current_timeout = -1;

    /* Expand kernel buffers to prevent drops during 20KB+ packet bursts */
    if (recv_buf_mb > 0) {
        int bytes = recv_buf_mb * 1024 * 1024;
        if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) < 0) {
            log_error("Failed to set SO_RCVBUF: %s", strerror(errno));
        }
        setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
    }

    /* Standard production socket options for fast recovery and scaling */
    int on = 1;
    setsockopt(conn->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(conn->fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif

    /* Allow IP fragmentation to handle payloads larger than physical MTU */
    int mtu_disc = IP_PMTUDISC_DONT;
    setsockopt(conn->fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu_disc, sizeof(mtu_disc));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("UDP bind failed on port %u: %s", port, strerror(errno));
        close(conn->fd);
        free(conn);
        return NULL;
    }

    /* Retrieve actual assigned port if 0 was passed */
    if (port == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(conn->fd, (struct sockaddr *)&addr, &len) == 0) {
            conn->port = ntohs(addr.sin_port);
        } else {
            conn->port = 0;
        }
    } else {
        conn->port = port;
    }

    return conn;
}

/* Optimized raw send: Handles kernel buffer overflow and signal interruptions.
 */
ssize_t udp_send_raw(udp_conn_t *conn, const char *dst_ip, uint16_t dst_port, const void *data, size_t len) {
    if (!conn || conn->fd < 0 || !dst_ip || !data || len == 0) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dest.sin_addr) <= 0) {
        log_error("Invalid destination IP: %s", dst_ip);
        return -1;
    }

    ssize_t s;
    int retry = 0;
    while (1) {
        s = sendto(conn->fd, data, len, 0, (struct sockaddr *)&dest, sizeof(dest));
        
        if (s >= 0) return s;
        if (errno == EINTR) continue; /* Retry on signal interruption */
        /* Handle flow control: kernel buffers are temporarily full */
        if (errno == EAGAIN || errno == ENOBUFS) {
            if (++retry > 3) {
                log_error("UDP send dropped: kernel buffer full after retries");
                break;
            }
            usleep(1000); /* 1ms backoff to let kernel process fragments */
            continue;
        }
        
        log_error("UDP sendto failed: %s (target: %s:%u)", strerror(errno), dst_ip, dst_port);
        return -1;
    }
    return -1;
}

/* Optimized raw receive: Skips redundant setsockopt if timeout hasn't changed.
 */
ssize_t udp_recv_raw(udp_conn_t *conn, void *buf, size_t buf_size, struct sockaddr_in *client_addr, int timeout_ms) {
    if (!conn || conn->fd < 0 || !buf || buf_size == 0) return -1;

    /* Update kernel timeout only if it differs from the cached value */
    if (timeout_ms >= 0 && timeout_ms != conn->current_timeout) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0) {
            conn->current_timeout = timeout_ms;
        }
    }

    socklen_t addr_len = sizeof(struct sockaddr_in);
    ssize_t n;

    while (1) {
        n = recvfrom(conn->fd, buf, buf_size, 0, (struct sockaddr *)client_addr, &addr_len);
        
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* Standard timeout */
        if (errno == ECONNREFUSED) return -2; /* Destination port unreachable */

        log_error("UDP recvfrom failed: %s", strerror(errno));
        return -1;
    }
}

/* Safely closes the socket and releases memory.
 */
void udp_close(udp_conn_t *conn) {
    if (conn) {
        if (conn->fd >= 0) {
            shutdown(conn->fd, SHUT_RDWR);
            close(conn->fd);
        }
        free(conn);
    }
}

/**
 * @brief Initializes a Link-Layer Raw Socket (AF_PACKET).
 * Creates a raw socket bound to a specific network interface. This allows
 * sending and receiving packets at the Ethernet layer.
 *
 * @param if_name Name of the network interface (e.g., "eth0", "wwan0").
 * @return raw_sock_t* Pointer to the socket handle on success, NULL on failure.
 */
raw_sock_t *raw_sock_open(const char *if_name) {
    raw_sock_t *ctx = malloc(sizeof(raw_sock_t));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(raw_sock_t));

    /* 1. Create a raw socket to capture/send all Link-Layer protocols */
    ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sockfd < 0) {
        perror("socket(AF_PACKET) failed");
        goto err;
    }

    /* 2. Retrieve the interface index using IOCTL */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(ctx->sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX) failed");
        goto err;
    }

    ctx->if_index = ifr.ifr_ifindex;
    strncpy(ctx->if_name, if_name, IFNAMSIZ - 1);
    ctx->if_name[IFNAMSIZ - 1] = '\0';
    
    return ctx;
err:
    if (ctx->sockfd >= 0) close(ctx->sockfd);
    if (ctx) free(ctx);
    return NULL;
}

/**
 * @brief Generic Link-Layer Raw Data Transmission Interface.
 * Sends a raw buffer directly to the network interface. The data must
 * typically include the Ethernet header.
 *
 * @param ctx Pointer to the initialized raw_sock_t handle.
 * @param dst_mac Destination MAC address (6 bytes). If NULL, the first 6 bytes 
 * of 'data' are used as the destination address.
 * @param data Buffer containing the raw binary stream (including Ethernet header).
 * @param data_len Total length of the data to be sent.
 * @return ssize_t Number of bytes sent on success, -1 on failure.
 */
ssize_t raw_sock_send(raw_sock_t *ctx, const uint8_t *dst_mac, const void *data, size_t data_len) {
    if (!ctx || ctx->sockfd < 0 || !data || data_len == 0) {
        return -1;
    }

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    
    /* Prepare Link-Layer address structure */
    sa.sll_family   = AF_PACKET;
    sa.sll_ifindex  = ctx->if_index;
    sa.sll_halen    = ETH_ALEN;

    /* Set Destination MAC Address */
    if (dst_mac) {
        memcpy(sa.sll_addr, dst_mac, ETH_ALEN);
    } else {
        /* Default to extracting MAC from the provided Ethernet frame data */
        memcpy(sa.sll_addr, (const uint8_t *)data, ETH_ALEN);
    }

    /* Perform the raw transmission */
    ssize_t res = sendto(ctx->sockfd, data, data_len, 0,
                         (struct sockaddr *)&sa, sizeof(sa));
    
    return res;
}

/**
 * @brief Universal Layer-2 UDP Fragmentation Sender
 * @param ctx       Raw socket context/handle
 * @param src_mac   Source MAC address (6 bytes)
 * @param dst_mac   Destination MAC address (6 bytes)
 * @param src_ip    Source IP (Network Byte Order)
 * @param dst_ip    Destination IP (Network Byte Order)
 * @param src_port  Source Port (Host Byte Order)
 * @param dst_port  Destination Port (Host Byte Order)
 * @param data      Payload to send
 * @param len       Payload length
 * @return ssize_t  Total bytes sent or -1 on error
 */
ssize_t raw_send_udp_frag(raw_sock_t *ctx, 
                        const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        const uint8_t *data, size_t len) 
{
    if (!ctx || !src_mac || !dst_mac || !data || !len) return 0;

    static uint16_t g_ip_id = 0;
    uint16_t ip_id = __sync_fetch_and_add(&g_ip_id, 1); 

    size_t total_sent = 0;
    size_t offset = 0;      
    uint16_t frag_off = 0;  
    bool first = true;

    uint8_t buf[1514]; 

    while (offset < len) {
        size_t curr_len;
        bool has_more = false;

        /* Calculate fragment size */
        if (first) {
            if ((len + UDP_H_SIZE) > MAX_PAYLOAD) {
                curr_len = MAX_PAYLOAD;
                has_more = true;
            } else {
                curr_len = len + UDP_H_SIZE;
                has_more = false;
            }
        } else {
            size_t rem = len - offset;
            if (rem > MAX_PAYLOAD) {
                curr_len = MAX_PAYLOAD;
                has_more = true;
            } else {
                curr_len = rem;
                has_more = false;
            }
        }

        /* Map Headers */
        size_t pkt_len = 14 + IP_H_SIZE + curr_len;
        memset(buf, 0, 14 + IP_H_SIZE);

        struct ethhdr *eth = (struct ethhdr *)buf;
        struct iphdr  *ip  = (struct iphdr *)(buf + 14);
        uint8_t *payload   = buf + 14 + IP_H_SIZE;

        /* --- L2: Ethernet --- */
        memcpy(eth->h_dest, dst_mac, ETH_ALEN);
        memcpy(eth->h_source, src_mac, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        /* --- L3: IPv4 --- */
        ip->ihl      = 5;
        ip->version  = 4;
        ip->tot_len  = htons(IP_H_SIZE + curr_len);
        ip->id       = htons(ip_id);
        ip->ttl      = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr    = src_ip; 
        ip->daddr    = dst_ip;

        uint16_t off_field = frag_off & IP_OFFMASK;
        if (has_more) off_field |= IP_MF;
        ip->frag_off = htons(off_field);

        /* --- L4 & Payload --- */
        if (first) {
            struct udphdr *udp = (struct udphdr *)payload;
            udp->source = src_port;
            udp->dest   = dst_port;
            udp->len    = htons(UDP_H_SIZE + len); 
            udp->check  = 0; 

            size_t chunk = curr_len - UDP_H_SIZE;
            memcpy(payload + UDP_H_SIZE, data, chunk);
            offset += chunk;
            first = false;
        } else {
            memcpy(payload, data + offset, curr_len);
            offset += curr_len;
        }

        frag_off += (curr_len / FRAG_UNIT);

        /* Checksum Calculation */
        ip->check = 0;
        ip->check = checksum_finalize(checksum_accumulate(ip, IP_H_SIZE, 0));

        /* Physical Send */
        ssize_t s = raw_sock_send(ctx, dst_mac, buf, pkt_len);
        if (s <= 0) return -1;
        total_sent += s;
    }

    return total_sent;
}

/**
 * @brief Closes the Raw Socket and releases allocated resources.
 * @param ctx Pointer to the raw_sock_t handle to be closed.
 */
void raw_sock_close(raw_sock_t *ctx) {
    if (ctx) {
        if (ctx->sockfd >= 0)
            close(ctx->sockfd);
        free(ctx);
    }
}

/**
 * @brief Enable or disable broadcast capability on a UDP socket.
 * @param conn Pointer to the initialized udp_conn_t handle.
 * @param enable 1 to enable, 0 to disable.
 * @return 0 on success, -1 on failure.
 */
int udp_set_broadcast(udp_conn_t *conn, int enable) {
    if (!conn || conn->fd < 0) return -1;

    if (setsockopt(conn->fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0) {
        log_error("Failed to set SO_BROADCAST: %s", strerror(errno));
        return -1;
    }
    
    log_info("UDP broadcast %s on port %u", enable ? "enabled" : "disabled", conn->port);
    return 0;
}

/**
 * @brief Establishes a default remote address for the UDP socket.
 * * This allows the use of send() and recv() instead of sendto() and recvfrom().
 *
 * @param conn     The socket handle descriptor.
 * @param dst_ip   Destination IPv4 address in network byte order (e.g., 0xC0A80101 for 192.168.1.1).
 * @param dst_port Destination UDP port (Host Order).
 * @return 0 on success, -1 on failure.
 * @warning This modifies the socket state; use with caution in multi-destination scenarios.
 */
int udp_set_connect(udp_conn_t *conn, uint32_t dst_ip_n, uint16_t dst_port) {
    if (!conn || conn->fd < 0 || !dst_ip_n) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = dst_ip_n;

    if (connect(conn->fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        log_error("UDP connect failed to %s:%u : %s", inet_ntoa(dest.sin_addr), dst_port, strerror(errno));
        return -1;
    }
    
    return 0;
}

int udp_reset_connect(udp_conn_t *conn) {
    struct sockaddr_in unspec = { .sin_family = AF_UNSPEC };
    return connect(conn->fd, (const struct sockaddr *)&unspec, sizeof(unspec));
}