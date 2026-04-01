// sudo tcpdump -i any -nvvX udp port 5271
// sudo tcpdump -i lo -X udp port 9999
// sudo tcpdump -i lo -w test.pcap udp port 9999
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <stddef.h>
#include <signal.h>
#include "gap.h"

/* 模拟 redserver 依赖 */
// volatile sig_atomic_t server_running = 1;
// struct server { int dummy; } redserver;

void send_raw_tunneled_packet() {
    /* 1. 构造测试数据 (3000字节可视化数据) */
    size_t json_len = 3000;
    uint8_t *json_data = malloc(json_len);
    if (!json_data) return;
    memset(json_data, 'A', json_len); 

    /* 2. 调用组装函数 */
    uint8_t dummy_mac[6] = {0};
    uint32_t auth_val = 0xDEADBEEF;
    tunnel_payload_t **packets = NULL;
    size_t num_packets = 0;

    struct in_addr src_addr, dst_addr;
    inet_pton(AF_INET, "192.168.1.100", &src_addr);
    inet_pton(AF_INET, "10.0.0.5", &dst_addr);

    // 假设内部 IP 是 10.0.0.5，目标是 192.168.1.100
    int ret = gap_build_tunneled_packets(json_data, json_len, dummy_mac, dummy_mac,
                               src_addr.s_addr, dst_addr.s_addr,
                               12345, 5271, auth_val, 0x64, "POST", "/api",
                               &packets, &num_packets);
    
    if (ret != 0 || !packets) {
        printf("Failed to build packets\n");
        free(json_data);
        return;
    }

    /* 3. 创建 Raw Socket */
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed (Must run as sudo)");
        goto cleanup;
    }

    /* 4. 开启 IP_HDRINCL 选项 */
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sockfd);
        goto cleanup;
    }

    /* 5. 准备目的地址 (用于内核路由查找) */
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.100", &dest_addr.sin_addr);

    printf("Sending %zu raw packets...\n", num_packets);

    /* 6. 发送包 */
    for (size_t i = 0; i < num_packets; i++) {
        /* * 关键点 1: 定位 InnerData
         * 由于 inner_data 是柔性数组，需强转
         */
        tunnel_inner_payload_t *inner = (tunnel_inner_payload_t *)packets[i]->inner_data;
        
        /* * 关键点 2: 发送起始位置
         * Raw Socket 发送不包含 Auth 和 Ether 层，从 ip_header 开始
         */
        uint8_t *send_ptr = packets[i]->ip_header;
        
        /* * 关键点 3: 计算发送总长度
         * 因为是 __attribute__((packed))，总长度 = IP头 + UDP头 + (InnerHeader + JSON数据)
         * 注意：ntohs(inner->dataLen) 是 JSON 数据的长度
         */
        uint16_t this_json_len = ntohs(inner->dataLen);
        
        // 使用 sizeof(tunnel_inner_payload_t) 因为它代表了除 data[] 以外的所有头部长度
        size_t send_len = GAP_IP_HDR_LEN + GAP_UDP_HDR_LEN + 
                          sizeof(tunnel_inner_payload_t) + this_json_len;

        ssize_t sent = sendto(sockfd, send_ptr, send_len, 0, 
                             (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        
        if (sent < 0) {
            printf("Fragment %zu send failed: %s (len: %zu)\n", i, strerror(errno), send_len);
        } else {
            printf("Sent Raw Fragment [%zu/%zu]: %zd bytes (JSON portion: %u)\n", 
                   i+1, num_packets, sent, this_json_len);
        }
    }

    close(sockfd);

cleanup:
    gap_free_tunneled_packets(packets, num_packets);
    free(json_data);
}

int main() {
    send_raw_tunneled_packet();
    return 0;
}