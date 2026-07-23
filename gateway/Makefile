# =================================================================
# Copyright (c) 2026-2026, Red LRM.
# Description: High-Performance XDP Combined Makefile with LDFLAGS
#              Intelligent Kernel Version Routing (5.x -> Perf, 6.x+ -> Ring)
# Author: [yanruibing]
# =================================================================

# 1. 基础配置
CC       := gcc
CLANG    := clang
TARGET   := bin/redgw
XDP_OBJ  := obj/xdp_kern.o

SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin
CLI_DIR  := cli

# 2. 自动化内核主版本提取与路由
KERNEL_VERSION := $(shell uname -r)
# 提取主版本号（例如 "5.4.18-xxx" -> "5", "6.1.0-xxx" -> "6"）
KERNEL_MAJOR   := $(shell uname -r | cut -d. -f1)

# 默认编译基础参数
CFLAGS   := -ggdb -O3 -DVALIDATE_UTF8 -DLOG_USE_COLOR -Wall -Wextra -pthread -Iinclude -Isrc -Isrc/ws
BPFFLAGS := -O2 -target bpf -g -Wall

# 🌟 核心修改 1：追加 -L/lib64 和 -L/usr/lib64 强行让 GCC 链接器去麒麟的 64 位库路径下搜寻 .so 文件
# 🌟 核心修改 2：追加 -Wl,-rpath 选项，把这些路径硬编码进生成的二进制文件中，这样运行时就不需要配 LD_LIBRARY_PATH 了！
LDFLAGS  := -L/lib64 -L/usr/lib64 -Wl,-rpath=/lib64:/usr/lib64 -lpthread -lbpf -lelf -lz -lm -lpcap

# 🌟 核心修改：判定只要主版本号是 5（或更低），就强行启用 USE_PERF_BUFFER 降级兼容策略
ifeq ($(KERNEL_MAJOR),5)
    $(info [SYS-DETECT] Linux Kernel $(KERNEL_VERSION) [Major: $(KERNEL_MAJOR)] -> [Enabling USE_PERF_BUFFER])
    # 双向注入用户态与内核态宏定义
    CFLAGS   += -DUSE_PERF_BUFFER
    BPFFLAGS += -DUSE_PERF_BUFFER -I/usr/include/$(shell uname -m)-linux-gnu -I/usr/local/include
else
    $(info [SYS-DETECT] Linux Kernel $(KERNEL_VERSION) [Major: $(KERNEL_MAJOR)] -> [Enabling Standard RINGBUF])
endif

# 3. 动态扫描过滤用户态源码
ALL_SRCS  := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/ws/*.c)
USER_SRCS := $(filter-out $(SRC_DIR)/xdp_kern.c, $(ALL_SRCS))
USER_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(USER_SRCS))

.PHONY: all clean directories build_cli

all: directories $(XDP_OBJ) $(TARGET) build_cli

directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/ws
	@mkdir -p $(BIN_DIR)

$(TARGET): $(USER_OBJS)
	@echo "[+] Linking User-Plane Binary: $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "[+] Compiling User-Plane Object: $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(XDP_OBJ): $(SRC_DIR)/xdp_kern.c
	@echo "[*] Compiling Adaptive XDP Kernel Bytecode: $<"
	@$(CLANG) $(BPFFLAGS) -c $< -o $@

build_cli:
	$(MAKE) -C $(CLI_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)