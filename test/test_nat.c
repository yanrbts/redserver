#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include "nat.h"

// volatile sig_atomic_t server_running = 1;
// struct server { int dummy; } redserver;

// 辅助函数：将字符串 IP 转为 uint32 (NBO)
uint32_t str_to_ip(const char* ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return addr.s_addr;
}

void print_mac(uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main() {
    printf("=== 开始 NAT 表企业级接口测试 ===\n");

    // 1. 初始化：设置超时时间为 3 秒
    nat_table_t *nat = nat_table_create(3);
    assert(nat != NULL);
    printf("[1] NAT 表初始化成功 (超时时间: 3s)\n");

    // 准备测试数据
    uint32_t ip1 = str_to_ip("192.168.1.10");
    uint16_t port1 = htons(12345);
    uint8_t mac1[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

    uint32_t ip2 = str_to_ip("192.168.1.20");
    uint16_t port2 = htons(8080);
    uint8_t mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};

    // 2. 测试插入 (模拟去程)
    printf("[2] 正在插入 2 条映射记录...\n");
    assert(nat_table_insert(nat, 60001, ip1, port1, mac1) == true);
    assert(nat_table_insert(nat, 60002, ip2, port2, mac2) == true);

    // 3. 测试查找 (模拟回程)
    printf("[3] 测试回程查找 (Proxy Port: 60001)...\n");
    uint32_t res_ip;
    uint16_t res_port;
    uint8_t res_mac[6];
    
    if (nat_table_lookup(nat, 60001, &res_ip, &res_port, res_mac)) {
        struct in_addr addr = { .s_addr = res_ip };
        printf("    查找成功! 终端: %s:%d, MAC: ", inet_ntoa(addr), ntohs(res_port));
        print_mac(res_mac);
        printf("\n");
        assert(res_ip == ip1);
    } else {
        printf("    错误: 未找到预期的 60001 记录\n");
        assert(false);
    }

    // 4. 测试活跃度更新 (LRU 逻辑)
    // 此时 60001 刚被查找，变为最新，60002 变为最旧
    printf("[4] 等待 2 秒 (未超过超时时间)...\n");
    sleep(2);
    nat_table_gc(nat); // 此时不应有任何项被清理
    assert(nat_table_lookup(nat, 60002, &res_ip, &res_port, res_mac) == true);
    printf("    2 秒后 60002 依然有效\n");

    // 5. 测试过期清理 (GC 逻辑)
    printf("[5] 继续等待 4 秒 (超过超时时间)...\n");
    sleep(4);
    
    printf("    执行 GC 清理前查找 60001...\n");
    nat_table_gc(nat); // 执行清理

    if (nat_table_lookup(nat, 60001, &res_ip, &res_port, res_mac)) {
        printf("    错误: 60001 应该已过期被清理\n");
        assert(false);
    } else {
        printf("    验证成功: 过期记录已被自动清理\n");
    }

    // 6. 测试销毁
    nat_table_destroy(nat);
    printf("[6] NAT 表销毁成功\n");

    printf("=== 所有测试用例通过! ===\n");
    return 0;
}