# =================================================================
# Copyright (c) 2026-2026, Red LRM.
# Description: High-Performance XDP Combined Makefile with LDFLAGS
# =================================================================

# 1. 编译器及工具链定义
CC       := gcc
CLANG    := clang
TARGET   := bin/redgw
XDP_OBJ  := obj/xdp_kern.o

# 2. 编译与链接选项配置
CFLAGS   := -ggdb -O3 -DLOG_USE_COLOR -Wall -Wextra -pthread -Iinclude -Isrc
BPFFLAGS := -O2 -target bpf -g -Wall

# 🌟 核心升级：引入用户态所需的全部高吞吐/内核依赖链接库
# -lpthread: 多线程支持
# -lbpf    : 用于用户态加载/管理 XDP(eBPF) 字节码
# -lelf    : libbpf 解析 ELF 格式的汇编目标文件所需
# -lz      : 压缩库，内核/libbpf 内部依赖
# -lpcap   : 高性能旁路数据包捕获捕获库
LDFLAGS  := -lpthread -lbpf -lelf -lz -lpcap

# 3. 目录与路径发现机制
SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin

CLI_DIR = cli

# 自动搜寻 src 下所有的用户态 .c 文件，排除掉 XDP 内核代码
USER_SRCS := $(filter-out $(SRC_DIR)/xdp_kern.c, $(wildcard $(SRC_DIR)/*.c))
# 将用户态源码映射到 obj 目录下的 .o 文件
USER_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(USER_SRCS))

# 4. 伪目标定义
.PHONY: all clean directories

# 默认构建流：先建目录，再编译 XDP 内核，最后编译用户态可执行程序
all: directories $(XDP_OBJ) $(TARGET) build_cli

# 5. 目录自动创建规则
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# 6. 用户态可执行文件链接规则 (🌟 关键：LDFLAGS 必须放在 $^ 后面)
$(TARGET): $(USER_OBJS)
	@echo "[+] Linking User-Plane Binary with Dependencies: $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 7. 用户态 .c 到 .o 的编译规则
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "[+] Compiling User-Plane Object: $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# 8. XDP/eBPF 内核字节码编译规则
$(XDP_OBJ): $(SRC_DIR)/xdp_kern.c
	@echo "[*] Compiling XDP Kernel Bytecode: $<"
	@$(CLANG) $(BPFFLAGS) -c $< -o $@

build_cli:
	@echo "[SUBDIR] Entering directory '$(CLI_DIR)' for build..."
	$(MAKE) -C $(CLI_DIR)

# 9. 清理规则
clean:
	@echo "[!] Cleaning Build Workspace..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)