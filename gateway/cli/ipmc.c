#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h> /* 用于 ntohl 转换大端序 */
#include <inttypes.h>

#include "ljb.h"
#include "log.h"

typedef enum {
    CMD_TYPE_ALL = 0,   /* 默认：原有的综合循环测试 */
    CMD_TYPE_HB,        /* 心跳 (Heartbeat) */
    CMD_TYPE_SW_VER,    /* 软件版本 (SW Version) */
    CMD_TYPE_HW_VER,    /* 硬件版本 (HW Version) */
    CMD_TYPE_SN,        /* 序列号 (SN) */
    CMD_TYPE_TIME,      /* 运行时间 (Time) */

    CMD_TYPE_RACK,      /* 机架信息 (Rack Info) */
    CMD_TYPE_UPGRADE,   /* 升级信息 (Upgrade Info) */
} test_cmd_type_t;

static volatile int g_running = 1;

static void sig_handler(int sig) {
    if (sig == SIGINT) {
        log_info("[IPMC] Terminal signal received. Exiting gracefully...");
        g_running = 0;
    }
}

static inline uint64_t bytes_to_u64_le(const uint8_t bytes[8]) {
    return ((uint64_t)bytes[0])        |
           ((uint64_t)bytes[1] <<  8)  |
           ((uint64_t)bytes[2] << 16)  |
           ((uint64_t)bytes[3] << 24)  |
           ((uint64_t)bytes[4] << 32)  |
           ((uint64_t)bytes[5] << 40)  |
           ((uint64_t)bytes[6] << 48)  |
           ((uint64_t)bytes[7] << 56);
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -f <path>   Config file path (default: ./ljb.conf)\n");
    printf("  -m <module> Module name ipmc/cpu (default: ipmc)\n");
    printf("  -c <cmd>    Command type to execute:\n");
    printf("              all     : Default mixed loop test\n");
    printf("              hb      : Send Heartbeat sync\n");
    printf("              sw      : Get SW Version sync\n");
    printf("              hw      : Get HW Version sync\n");
    printf("              sn      : Get Serial Number sync\n");
    printf("              tm      : Get Uptime/Time sync\n");
    printf("              rk      : Get Rack Info sync\n");
    printf("              up      : Get Upgrade Info sync\n");
    printf("  -n <count>  Repeat count (default: 0 = infinite loop)\n");
    printf("  -i <sec>    Interval seconds between requests (default: 1s)\n");
    printf("  -h          Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s -f /etc/ljb.conf -c hw -n 1 # Custom config file\n", prog_name);
    printf("  %s -c hw -n 1                  # Request HW version once\n", prog_name);
    printf("  %s -c sw -n 5 -i 2             # Request SW version 5 times with 2s interval\n", prog_name);
}

static void do_cmd_hb(ljb_ctx_t *ctx) {
    log_info("[IPMC] ---> Sending Heartbeat to CPU...");
    ljb_err_t err = ljb_ipmc_send_heartbeat_sync(ctx);
    if (err == LJB_OK) {
        log_info("[IPMC] Heartbeat ACK received from CPU.");
    } else {
        log_error("[IPMC] Heartbeat TIMEOUT or ERROR: %s", ljb_strerror(err));
    }
}

static void do_cmd_sw_ver(ljb_ctx_t *ctx) {
    log_info("[IPMC] ---> Requesting CPU Software Version...");
    ljb_version_t cpu_sw_ver;
    ljb_err_t err = ljb_ipmc_get_sw_version_sync(ctx, &cpu_sw_ver);
    if (err == LJB_OK) {
        log_info("[IPMC] SUCCESS: CPU SW Version: v%d.%d.%d Build %d (Date: %u)",
                 cpu_sw_ver.major, cpu_sw_ver.minor, cpu_sw_ver.revision, 
                 cpu_sw_ver.build, cpu_sw_ver.ymd);
    } else {
        log_error("[IPMC] FAILED: get_sw_version_sync %s", ljb_strerror(err));
    }
}

static void do_cmd_hw_ver(ljb_ctx_t *ctx) {
    log_info("[IPMC] ---> Requesting CPU Hardware Version...");
    ljb_version_t cpu_hw_ver;
    ljb_err_t err = ljb_ipmc_get_hw_version_sync(ctx, &cpu_hw_ver);
    if (err == LJB_OK) {
        log_info("[IPMC] SUCCESS: CPU HW Version: v%d.%d.%d Build %d (Date: %u)",
                 cpu_hw_ver.major, cpu_hw_ver.minor, cpu_hw_ver.revision, 
                 cpu_hw_ver.build, cpu_hw_ver.ymd);
    } else {
        log_error("[IPMC] FAILED: get_hw_version_sync %s", ljb_strerror(err));
    }
}

static void do_cmd_sn(ljb_ctx_t *ctx) {
    log_info("[IPMC] ---> Requesting SN...");
    uint8_t sn[8] = {0};
    ljb_err_t err = ljb_ipmc_get_sn_sync(ctx, sn);

    if (err == LJB_OK) {
        /* 1. 格式化为 16 进制字符串 */
        char sn_hex[32] = {0};
        size_t off = 0;
        for (int i = 0; i < 8; ++i) {
            off += snprintf(sn_hex + off, sizeof(sn_hex) - off, "%02X ", sn[i]);
        }

        /* 2. 格式化为 ASCII 字符串（不可打印字符替换为 '.'） */
        char sn_str[9] = {0};
        for (int i = 0; i < 8; ++i) {
            sn_str[i] = (sn[i] >= 32 && sn[i] <= 126) ? (char)sn[i] : '.';
        }

        log_info("[IPMC] SUCCESS: SN (Hex): [ %s] | SN (ASCII): \"%s\"", sn_hex, sn_str);
    } else {
        log_error("[IPMC] FAILED: get_sn_sync %s", ljb_strerror(err));
    }
}

static void do_cmd_time(ljb_ctx_t *ctx) {
    log_info("[IPMC] ---> Requesting Time/Uptime...");
    uint8_t total[8] = {0};
    uint8_t uptime[8] = {0};
    ljb_err_t err = ljb_ipmc_get_time_sync(ctx, total, uptime);
    if (err == LJB_OK) {
        uint64_t total_half_hours = bytes_to_u64_le(total);
        uint64_t uptime_sec = bytes_to_u64_le(uptime);

        log_info("[IPMC] TIME: Total Uptime: %" PRIu64 " half-hours, Current Uptime: %" PRIu64 " seconds", 
                 total_half_hours, uptime_sec);
    } else {
        log_error("[IPMC] FAILED: get_time_sync %s", ljb_strerror(err));
    }
}

static void do_cmd_rack(ljb_ctx_t *ctx) {
    log_info("[CPU] ---> Requesting Rack Info...");
    ljb_rack_t rack_info;
    ljb_err_t err = ljb_cpu_get_rack_info_sync(ctx, &rack_info);
    if (err == LJB_OK) {
        log_info("[CPU] SUCCESS: Rack ID: 0x%02X, Slot ID: 0x%02X", 
            rack_info.rack_id, 
            rack_info.slot_id
        );
    } else {
        log_error("[CPU] FAILED: ljb_cpu_get_rack_info_sync %s", ljb_strerror(err));
    }
}

static void do_cmd_upgrade(ljb_ctx_t *ctx) {
    log_info("[CPU] ---> Requesting Upgrade...");
    uint8_t upgrade = 0xFF;
    ljb_err_t err = ljb_cpu_request_upgrade_sync(ctx, &upgrade);
    if (err == LJB_OK) {
        log_info("[CPU] SUCCESS: Upgrade Grant Response Code: 0x%02X", upgrade);
    } else {
        log_error("[CPU] FAILED: ljb_cpu_request_upgrade_sync %s", ljb_strerror(err));
    }
}

int main(int argc, char *argv[]) {
    test_cmd_type_t cmd_type = CMD_TYPE_ALL;
    const char *config_file = "./ljb.conf";
    ljb_node_t module_role = NODE_IPMC;     /* 默认模块角色为 IPMC */
    int target_count = 0;                   /* 默认 0：无限循环 */
    int interval_sec = 1;                   /* 默认间隔 1 秒 */
    int opt;

    while ((opt = getopt(argc, argv, "f:m:c:n:i:h")) != -1) {
        switch (opt) {
            case 'f':
                config_file = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "ipmc") == 0) {
                    module_role = NODE_IPMC;
                } else if (strcmp(optarg, "cpu") == 0) {
                    module_role = NODE_CPU;
                } else {
                    log_error("Unknown module type: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'c':
                if (strcmp(optarg, "hb") == 0) {
                    cmd_type = CMD_TYPE_HB;
                } else if (strcmp(optarg, "sw") == 0) {
                    cmd_type = CMD_TYPE_SW_VER;
                } else if (strcmp(optarg, "hw") == 0) {
                    cmd_type = CMD_TYPE_HW_VER;
                } else if (strcmp(optarg, "sn") == 0) {
                    cmd_type = CMD_TYPE_SN;
                } else if (strcmp(optarg, "tm") == 0) {
                    cmd_type = CMD_TYPE_TIME;
                } else if (strcmp(optarg, "all") == 0) {
                    cmd_type = CMD_TYPE_ALL;
                } else if (strcmp(optarg, "rk") == 0) {
                    cmd_type = CMD_TYPE_RACK;
                } else if (strcmp(optarg, "up") == 0) {
                    cmd_type = CMD_TYPE_UPGRADE;
                } else {
                    log_error("Unknown command type: %s\n", optarg);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'n':
                target_count = atoi(optarg);
                if (target_count < 0) target_count = 0;
                break;
            case 'i':
                interval_sec = atoi(optarg);
                if (interval_sec < 1) interval_sec = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    ljb_ctx_t ctx;

    signal(SIGINT, sig_handler);

    log_info("[%s] Initializing engine...", module_role == NODE_IPMC ? "IPMC" : "CPU");
    if (ljb_init(&ctx, config_file, module_role) != LJB_OK) {
        log_error("[%s] Failed to initialize LJB engine", module_role == NODE_IPMC ? "IPMC" : "CPU");
        return 1;
    }

    sleep(1);

    log_info("[%s] Engine running (Cmd Mode: %d, Count: %d, Interval: %ds). Press Ctrl+C to stop.",
             module_role == NODE_IPMC ? "IPMC" : "CPU", cmd_type, target_count, interval_sec);

    int loop_cnt = 1;
    while (g_running) {
        if (target_count > 0 && loop_cnt > target_count) {
            log_info("[%s] Target count (%d) reached. Exiting loop.", 
                module_role == NODE_IPMC ? "IPMC" : "CPU", target_count);
            break;
        }

        if (module_role == NODE_IPMC) {
            switch (cmd_type) {
            case CMD_TYPE_HB: do_cmd_hb(&ctx); break;
            case CMD_TYPE_SW_VER: do_cmd_sw_ver(&ctx); break;
            case CMD_TYPE_HW_VER: do_cmd_hw_ver(&ctx); break;
            case CMD_TYPE_SN: do_cmd_sn(&ctx); break;
            case CMD_TYPE_TIME: do_cmd_time(&ctx); break;
            case CMD_TYPE_ALL:
            default:
                do_cmd_hb(&ctx);
                if (loop_cnt % 5 == 1) {
                    do_cmd_sw_ver(&ctx);
                    do_cmd_hw_ver(&ctx);
                }
                if (loop_cnt % 3 == 0) do_cmd_sn(&ctx);
                if (loop_cnt % 4 == 0) do_cmd_time(&ctx);
                break;
            }
        } else {
            switch (cmd_type) {
            case CMD_TYPE_RACK: do_cmd_rack(&ctx); break;
            case CMD_TYPE_UPGRADE: do_cmd_upgrade(&ctx); break;
            case CMD_TYPE_ALL:
            default:
                if (loop_cnt % 2 == 0) do_cmd_rack(&ctx);
                if (loop_cnt % 4 == 0) do_cmd_upgrade(&ctx);
                break;
            }
        }
        
        loop_cnt++;
        /* 按步长休眠，保证响应 Ctrl+C */
        for (int i = 0; i < interval_sec && g_running; ++i) {
            sleep(1);
        }
    }

    log_info("[%s] Deinitializing...", module_role == NODE_IPMC ? "IPMC" : "CPU");
    ljb_deinit(&ctx);
    return 0;
}