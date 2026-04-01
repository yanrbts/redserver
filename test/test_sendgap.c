#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include "gap.h"

volatile sig_atomic_t server_running = 1;
/* 解决链接时的 redserver 依赖 */
struct server {
    int dummy;
} redserver;

/**
 * 发送测试程序
 */
void test_and_send_packets() {
    printf("=== Starting Fragmentation & Send Test ===\n");

    /* * 0. 协议偏移检查 
     * 注意：由于 inner_data 是 uint8_t[]，不能直接 .dataLen
     * 我们通过计算“到 inner_data 的偏移” + “在 tunnel_inner_payload_t 内部的偏移”来打印
     */
    size_t base_off = offsetof(tunnel_payload_t, inner_data);
    printf("--- Protocol Offset Check (Logical) ---\n");
    printf("Base (InnerData start): %zu\n", base_off);
    printf("OFF_INNER_DATA_LEN: %zu\n", base_off + offsetof(tunnel_inner_payload_t, dataLen));
    printf("OFF_NUM:            %zu\n", base_off + offsetof(tunnel_inner_payload_t, num));
    printf("OFF_TOTAL:          %zu\n", base_off + offsetof(tunnel_inner_payload_t, total));
    printf("OFF_JSON_PAYLOAD:   %zu\n", base_off + offsetof(tunnel_inner_payload_t, data));
    printf("-----------------------------\n");

    /* 1. 准备 3000 字节的可视化数据 */
    size_t json_len = 3000;
    uint8_t *json_data = (uint8_t *)malloc(json_len + 1);
    if (!json_data) return;
    memset(json_data, '.', json_len);

    for (size_t i = 0; i < 60; i++) {
        char line_hdr[64];
        int header_len = snprintf(line_hdr, sizeof(line_hdr), "[Row %02zu] ", i);
        size_t row_start = i * 50; 
        if (row_start + 50 <= json_len) {
            memcpy(json_data + row_start, line_hdr, header_len);
            for (size_t j = header_len; j < 49; j++) {
                json_data[row_start + j] = 'A' + (j - header_len);
            }
            json_data[row_start + 49] = '\n';
        }
    }
    json_data[json_len] = '\0';

    /* 2. 模拟参数 */
    uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    uint32_t auth_val = 0xDEADBEEF;
    
    tunnel_payload_t **packets = NULL;
    size_t num_packets = 0;

    struct in_addr src_addr, dst_addr;
    inet_pton(AF_INET, "192.168.1.100", &src_addr);
    inet_pton(AF_INET, "10.0.0.5", &dst_addr);

    /* 3. 构造分片 */
    int ret = gap_build_tunneled_packets(
        json_data, json_len,
        dst_mac, src_mac,
        src_addr.s_addr, dst_addr.s_addr,
        12345, 5271,
        auth_val,
        0x77, "POST", "/api/data",
        &packets, &num_packets
    );

    if (ret != 0 || num_packets == 0) {
        printf("Failed to build packets.\n");
        free(json_data);
        return;
    }

    /* 4. 创建 UDP Socket (用于承载伪造包的测试发送) */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket create failed");
        goto cleanup;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(9999); 
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);

    printf("Built %zu packets. Sending to 127.0.0.1:9999...\n", num_packets);

    /* 5. 循环发送 */
    for (size_t i = 0; i < num_packets; i++) {
        /* * 关键点：强转指针以访问 tunnel_inner_payload_t 
         */
        tunnel_inner_payload_t *inner = (tunnel_inner_payload_t *)packets[i]->inner_data;
        
        /* * 关键点：使用宏计算完整包长 
         */
        uint16_t json_this_len = ntohs(inner->dataLen);
        size_t full_pkt_len = GAP_PACKET_SIZE(json_this_len);

        ssize_t sent = sendto(sockfd, packets[i], full_pkt_len, 0,
                              (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        
        if (sent < 0) {
            printf("Packet %zu send failed: %s\n", i, strerror(errno));
        } else {
            printf("Sent Fragment [%zu/%zu]: %zd bytes (Payload: %u)\n", 
                   i + 1, num_packets, sent, json_this_len);
        }
    }

    close(sockfd);

cleanup:
    gap_free_tunneled_packets(packets, num_packets);
    free(json_data);
    printf("=== Test Finished ===\n");
}

int main() {
    test_and_send_packets();
    return 0;
}