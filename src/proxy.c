/*
 * redlrm - A UDP relay/proxy for RED protocol
 * Copyright (C) 2026-2026 YRB
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "log.h"
#include "hdr.h"
#include "udp.h"
#include "redlrm.h"
#include "proxy.h"
#include "gap.h"
#include "nat.h"
#include "session_manager.h"
#include "util.h"

typedef struct {
    uint32_t ip;      // 存储网络字节序的 IP (可以直接存入 NAT 表)
    uint16_t port;    // 存储网络字节序的端口
    char ip_str[16];  // 人类可读的 IP 字符串 (方便打印日志)
} terminal_info_t;


/**
 * 封装函数：解析 client_addr
 * @param addr: udp_recv_raw 返回的地址结构体
 * @param info: 输出解析后的信息
 */
void parse_client_address(struct sockaddr_in *addr, terminal_info_t *info) {
    if (!addr || !info) return;

    // 1. 获取网络字节序原始值 (用于 NAT 表查找/插入)
    info->ip = addr->sin_addr.s_addr;
    info->port = addr->sin_port;

    // 2. 转换成人类可读字符串 (用于 printf)
    ip_ntop(addr->sin_addr.s_addr, info->ip_str, sizeof(info->ip_str));
}

void *proxy_listen_core(void *arg) {
    struct proxyinfo *pinfo = (struct proxyinfo *)arg;

    udp_conn_t *server = udp_init_listener(pinfo->port, 4);
    if (!server) return NULL;

    log_info("Listening on Core side Data: %s:%d", pinfo->host, pinfo->port);

    unsigned char buf[BUFFER_SIZE];
    struct sockaddr_in client_addr;

    while (server_running) {
        ssize_t n = udp_recv_raw(server, buf, sizeof(buf), &client_addr, 1000);

        if (n <= 0) {
            continue;
        }
        
        uint8_t dst_mac[6] = {0};
        uint32_t dst_ip = 0;
        // if (gc_mgr_get_ip_by_type(redserver.gc_mgr, GC_MGR_BLACK, &dst_ip) == 0 &&
        //     gc_mgr_get_mac_by_type(redserver.gc_mgr, GC_MGR_BLACK, dst_mac) == 0) {
            
        //     struct in_addr addr = { .s_addr = dst_ip };
        //     log_info("[Found] BLACK -> IP: %s | %02X:%02X:%02X:%02X:%02X:%02X", 
        //         inet_ntoa(addr), 
        //         dst_mac[0], dst_mac[1], dst_mac[2],
        //         dst_mac[3], dst_mac[4], dst_mac[5]);
        // } else {
        //     log_warn("[Wait] BLACK 设备尚未在线...\n");
        //     continue;
        // }

        char ip_str[16] = {0};
        char ip_dst[16] = {0};
        
        ip_ntop(redserver.localip, ip_str, sizeof(ip_str));
        ip_ntop(dst_ip, ip_dst, sizeof(ip_dst));

        uint16_t packet_type = 0;
        if (n >= 2) {
            packet_type = ntohs(*(uint16_t*)buf);
        }

        if (packet_type == AUTH_DATA 
            && client_addr.sin_addr.s_addr == dst_ip) {
            /* (Black -> Red -> Terminal) */
            uint16_t pport;
            unsigned char *json_data;
            size_t json_len;

            /* Unpack the tunnel envelope */
            if (gap_unpack_packets(buf, n, &pport, &json_data, &json_len) == 0) {
                uint32_t t_ip;
                uint16_t t_port;

                /* Find the original terminal address using the extracted Proxy Port (e.g., 58888) */
                if (nat_table_lookup(redserver.nat, pport, &t_ip, &t_port, NULL)) {
                    /* Send the original JSON payload back to the terminal */
                    char t_dst[16] = {0};
                    ip_ntop(t_ip, t_dst, sizeof(t_dst));
                    ssize_t sent_bytes = udp_send_raw(server, t_dst, ntohs(t_port), json_data, json_len);
                    
                    if (sent_bytes > 0) {
                        log_info("BLACK(%s) -> RED(%s): Restored packet to terminal %s:%d (via Proxy Port %u)", 
                                ip_dst, ip_str, t_dst, ntohs(t_port), pport);
                    }
                } else {
                    log_warn("NAT miss: No terminal found for Proxy Port %u", pport);
                }
            }

        } else {
            /* (Terminal -> Red -> Black) */
            terminal_info_t tm;
            tunnel_payload_t **packets = NULL;
            size_t num_packets = 0;
            uint32_t auth;
            
            if (auth_get(redserver.at, &auth) != 0) {
                log_error("No valid Auth available, dropping packet");
                continue;
            }

            parse_client_address(&client_addr, &tm);

            if (!nat_table_insert(redserver.nat, 58888, tm.ip, tm.port, NULL)) {
                log_error("Failed to insert ip and port to nat table.");
                continue;
            }

            int ret = gap_build_tunneled_packets(
                buf, n,
                redserver.localmac, dst_mac,                       // mac
                redserver.localip, dst_ip,                         // ip
                58888, 59999,
                // pinfo->port, pinfo->dstport,            // port
                auth,
                0,
                "GET",
                "/",
                &packets, &num_packets          
            );

            if (ret != 0 || packets == NULL || num_packets == 0) {
                // log_error("Failed to build tunneled packets from Core data");
                continue;
            }

            ret = gap_send_tunneled_to_target(
                ip_dst,
                pinfo->dstport,
                packets,
                num_packets,
                server
            );
            if (ret != 0) {
                log_error("Failed to send tunneled packets to Switch");
            } else {
                log_info("RED(%s) -> BLACK(%s): Sent %zu tunneled packets", ip_str, ip_dst, num_packets);
            }

            gap_free_tunneled_packets(packets, num_packets);
        }
    }

    udp_close(server);
    return NULL;
}

/**
 * @brief Background thread function to maintain heartbeat liveness.
 */
void *auth_heartbeat_thread(void *arg) {
    auth_monitor_t *ctx = (auth_monitor_t *)arg;
    const int interval_sec = 5;
    const int max_allowed_fails = 3;

    log_info("Heartbeat monitor thread started for %s:%u", 
             ctx->server_ip, ctx->server_port);

    while (ctx->running) {
        int result = auth_ping_probe(ctx->conn, ctx->server_ip, ctx->server_port);

        pthread_mutex_lock(&ctx->lock);
        if (result == 0) {
            if (!ctx->is_alive) log_info("Network link recovered.");
            ctx->is_alive = true;
            ctx->fail_count = 0;
        } else {
            ctx->fail_count++;
            log_warn("Heartbeat probe failed (%d/%d). Reason: %s", 
                     ctx->fail_count, max_allowed_fails, 
                     (result == -2) ? "Timeout" : "Socket Error");
            if (ctx->fail_count >= max_allowed_fails) {
                if (ctx->is_alive) log_info("Heartbeat lost!");
                ctx->is_alive = false;
            }
        }
        pthread_mutex_unlock(&ctx->lock);

        /* 响应式休眠：每 100ms 检查一次 running 状态 */
        for (int i = 0; i < interval_sec * 10 && ctx->running; i++) {
            usleep(100000);
        }
    }

    log_info("Heartbeat thread loop stopped.");
    return NULL;
}

void *auth_refresh_thread(void *arg) {
    auth_refresh_t *atf = (auth_refresh_t *)arg;

    while (server_running) {
        if (auth_refresh(atf->at, atf->auth_host, atf->auth_port) == 0) {
            log_info("Value updated by thread: 0x%08X", atf->at->auth_value);
        } else {
            log_error("Thread refresh failed, keep using old value.\n");
        }

        sleep(atf->at->auth_interval);
    }

    return NULL;
}

void *aging_thread_fn(void *arg) {
    session_manager_t *mgr = (session_manager_t *)arg;

    while (server_running) {
        session_mgr_aging(mgr);
        
        for (int i = 0; i < 20 && server_running; i++) {
            usleep(100000); // 0.1s * 20 = 2s
        }
    }
    return NULL;
}