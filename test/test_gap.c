#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h> // 增加 ntohs
#include <signal.h>
#include "gap.h"

volatile sig_atomic_t server_running = 1;
struct server { int dummy; } redserver;
/* 模拟调用环境 */
void test_fragmentation_logic() {
    printf("=== Starting Fragmentation Test ===\n");

    /* 1. 准备 3000 字节的模拟 JSON 数据 */
    size_t json_len = 3000;
    uint8_t *json_data = (uint8_t *)malloc(json_len);
    for (size_t i = 0; i < json_len; i++) {
        json_data[i] = (uint8_t)('A' + (i % 26)); /* 填充 A-Z */
    }

    /* 2. 模拟伪造的参数 */
    uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src_mac[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    uint32_t auth_val = 0xDEADBEEF;
    
    tunnel_payload_t **packets = NULL;
    size_t num_packets = 0;
    struct in_addr src_addr, dst_addr;
    inet_pton(AF_INET, "192.168.1.100", &src_addr);
    inet_pton(AF_INET, "10.0.0.5", &dst_addr);

    /* 3. 调用核心接口 */
    int ret = gap_build_tunneled_packets(
        json_data, json_len,
        dst_mac, src_mac,
        src_addr.s_addr, dst_addr.s_addr,
        12345, 5271,
        auth_val,
        0x77, "POST", "/api/data",
        &packets, &num_packets
    );

    /* 4. 验证结果 */
    if (ret == 0 && packets != NULL) {
        printf("Successfully built %zu packets.\n", num_packets);

        for (size_t i = 0; i < num_packets; i++) {
            /* 关键点：由于 inner_data 是柔性数组，需要强制转换为指针 */
            tunnel_inner_payload_t *inner = (tunnel_inner_payload_t *)packets[i]->inner_data;

            uint16_t current_data_len = ntohs(inner->dataLen);
            uint16_t total_frags = ntohs(inner->total);
            uint8_t current_num = inner->num;

            printf("Fragment [%d/%d]:\n", current_num, total_frags);
            printf("  - Payload Data Length: %u bytes\n", current_data_len);
            
            /* * 关键点：计算 offset 时，要使用 sizeof(tunnel_inner_payload_t) 
             * 因为现在的 data[] 已经不占 sizeof 空间了。
             */
            size_t max_per_frag = GAP_MAX_FRAGMENT - sizeof(tunnel_inner_payload_t);
            size_t expected_offset = (current_num - 1) * max_per_frag;

            if (expected_offset < json_len) {
                /* 访问柔性数组的数据：inner->data[0] */
                printf("  - First byte: %c (Expected: %c)\n", 
                        inner->data[0], 
                        json_data[expected_offset]);
                
                // 验证数据完整性
                if (inner->data[0] != json_data[expected_offset]) {
                    printf("  [ERROR] Data mismatch at fragment %d!\n", current_num);
                }
            }
        }

        /* 5. 清理接口 */
        printf("Cleaning up memory...\n");
        gap_free_tunneled_packets(packets, num_packets);
        printf("Cleanup successful.\n");
    } else {
        printf("Failed to build tunneled packets.\n");
    }

    free(json_data);
    printf("=== Test Finished ===\n");
}

int main() {
    test_fragmentation_logic();
    return 0;
}