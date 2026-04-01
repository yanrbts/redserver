/*
 * test_gc_manager.c
 * 测试 gc_manager 多端口探测 + child ctx 创建 + connect 隔离
 * 程序会一直运行，直到用户按 Ctrl+C 才退出
 *
 * 编译命令示例：
 *   gcc -o test_gc_manager test_gc_manager.c gc_manager.c 5gc.c udp.c util.c -lpthread
 *
 * 运行： ./test_gc_manager
 * 观察日志，按 Ctrl+C 退出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#include "5gcmanager.h"
#include "5gc.h"
#include "log.h"     // 假设你有 log_info / log_error

// 如果没有 log.h，可以用这个简单实现
#ifndef log_info
#define log_info(fmt, ...)  printf("[INFO]  %s " fmt "\n", get_timestamp(), ##__VA_ARGS__)
#define log_error(fmt, ...) fprintf(stderr, "[ERROR] %s " fmt "\n", get_timestamp(), ##__VA_ARGS__)
#define log_debug(fmt, ...) printf("[DEBUG] %s " fmt "\n", get_timestamp(), ##__VA_ARGS__)
#endif

// 全局退出标志
static volatile bool g_running = true;

static const char* get_timestamp(void) {
    static char buf[32];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
    return buf;
}

// Ctrl+C 信号处理
static void sigint_handler(int sig) {
    (void)sig;
    log_info("捕获到 Ctrl+C，准备退出...");
    g_running = false;
}

static void print_mac(const char *label, uint8_t mac[6]) {
    printf("%s: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ------------------------------------------------------
// 回调函数示例
// ------------------------------------------------------
static void on_new_target(gc_manager_t *mgr, gc_resp_find_t *node, uint16_t probe_port) {
    (void)mgr;
    char ip[32];
    inet_ntop(AF_INET, &node->ipv4, ip, sizeof(ip));
    log_info("发现新目标 → %s:%u  devid=%02x:%02x:%02x:%02x:%02x:%02x",
             ip, probe_port,
             node->devid[0], node->devid[1], node->devid[2],
             node->devid[3], node->devid[4], node->devid[5]);
}

static void on_child_state_change(gc_ctx_t *child, gc_state_e new_state) {
    char ip[32];
    inet_ntop(AF_INET, &child->node.ipv4, ip, sizeof(ip));
    const char *state_str =
        (new_state == GC_STATE_DISCOVERY) ? "DISCOVERY" :
        (new_state == GC_STATE_REGISTER)  ? "REGISTER"  :
        (new_state == GC_STATE_HEARTBEAT) ? "HEARTBEAT" : "UNKNOWN";

    log_info("子连接状态变化 → %s:%u → %s (fail_count=%d)",
             ip, child->target_port, state_str, child->fail_count);
}

// ------------------------------------------------------
// 打印当前所有 child 状态（用于观察长期运行）
// ------------------------------------------------------
static void print_children_status(gc_manager_t *mgr) {
    size_t count = gc_mgr_get_child_count(mgr);
    log_info("当前 child 连接数量：%zu", count);

    for (size_t i = 0; i < count; i++) {
        gc_ctx_t *c = gc_mgr_get_child(mgr, i);
        if (c) {
            char ip[32];
            inet_ntop(AF_INET, &c->node.ipv4, ip, sizeof(ip));
            const char *state_str =
                (c->state == GC_STATE_DISCOVERY) ? "DISCOVERY" :
                (c->state == GC_STATE_REGISTER)  ? "REGISTER"  :
                (c->state == GC_STATE_HEARTBEAT) ? "HEARTBEAT" : "UNKNOWN";

            log_info("  [%zu] %s:%u  state=%s  fail=%d",
                     i, ip, c->target_port, state_str, c->fail_count);
        }
    }
    printf("----------------------------------------\n");
}

// ------------------------------------------------------
// 主函数：无限运行直到 Ctrl+C
// ------------------------------------------------------
int main(void) {
    // 注册 Ctrl+C 信号处理
    signal(SIGINT, sigint_handler);

    log_info("=== gc_manager 多端口探测测试开始（按 Ctrl+C 退出）===");

    // 准备探测端口
    gc_mgr_port_t ports_config[] = {
        {50001, GC_MGR_BLACK},   // 模拟黑区设备端口
        {50002, GC_MGR_SWITCH},  // 模拟交换机设备端口
        {50003, GC_MGR_BLACK},
        {50004, GC_MGR_SWITCH}
    };
    size_t num_ports = sizeof(ports_config) / sizeof(ports_config[0]);

    gc_manager_t *mgr = gc_mgr_create(8888, ports_config, num_ports);
    if (!mgr) {
        log_error("创建 gc_manager 失败");
        return 1;
    }

    // 设置回调
    gc_mgr_set_new_target_cb(mgr, on_new_target);
    gc_mgr_set_child_state_cb(mgr, on_child_state_change);
    gc_mgr_set_find_handler(mgr, NULL);

    // 可选：动态添加端口
    gc_mgr_add_probe_port(mgr, 50005);
    log_info("已添加额外探测端口 50005");

    // 启动 manager
    if (gc_mgr_start(mgr) != 0) {
        log_error("启动 manager 失败");
        gc_mgr_destroy(mgr);
        return 1;
    }

    log_info("manager 已启动，开始无限运行... 按 Ctrl+C 退出");

    // 无限循环，每 10 秒打印一次状态
    unsigned int tick = 0;
    while (g_running) {
        sleep(10);
        tick++;
        printf("\n[第 %u 次心跳] 当前时间: %s\n", tick, get_timestamp());
        print_children_status(mgr);

        uint8_t mac_val[6] = {0};
        uint32_t ip_val = 0;

        if (gc_mgr_get_ip_by_type(mgr, GC_MGR_BLACK, &ip_val) == 0 &&
            gc_mgr_get_mac_by_type(mgr, GC_MGR_BLACK, mac_val) == 0) {
            
            struct in_addr addr = { .s_addr = ip_val };
            printf("[Found] BLACK -> IP: %s | ", inet_ntoa(addr));
            print_mac("MAC", mac_val);
        } else {
            printf("[Wait] BLACK 设备尚未在线...\n");
        }

        // --- 测试获取 SWITCH 类型 ---
        if (gc_mgr_get_ip_by_type(mgr, GC_MGR_SWITCH, &ip_val) == 0 &&
            gc_mgr_get_mac_by_type(mgr, GC_MGR_SWITCH, mac_val) == 0) {
            
            struct in_addr addr = { .s_addr = ip_val };
            printf("[Found] SWITCH -> IP: %s | ", inet_ntoa(addr));
            print_mac("MAC", mac_val);
        } else {
            printf("[Wait] SWITCH 设备尚未在线...\n");
        }
    }

    // 清理
    log_info("正在停止 manager...");
    gc_mgr_stop(mgr);
    log_info("正在销毁 manager...");
    gc_mgr_destroy(mgr);

    log_info("程序正常退出");
    return 0;
}