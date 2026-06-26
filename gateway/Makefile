# =================================================================
# Copyright (c) 2026-2026, Red LRM.
# Description: High-Performance XDP Combined Makefile with LDFLAGS
#              Supports deep discovery for src/ws/ subdirectory
# =================================================================

# 1. 编译器及工具链定义
CC       := gcc
CLANG    := clang
TARGET   := bin/redgw
XDP_OBJ  := obj/xdp_kern.o

# 2. 编译与链接选项配置
CFLAGS   := -ggdb -O3 -DLOG_USE_COLOR -Wall -Wextra -pthread -Iinclude -Isrc -Isrc/ws
BPFFLAGS := -O2 -target bpf -g -Wall

# 核心升级：引入用户态所需的全部高吞吐/内核依赖链接库
LDFLAGS  := -lpthread -lbpf -lelf -lz -lm -lpcap

# 3. 目录与路径发现机制
SRC_DIR  := src
OBJ_DIR  := obj
BIN_DIR  := bin
CLI_DIR  := cli

# 🌟 核心修改 1：利用 wildcard 同时搜寻 src/ 和 src/ws/ 下的所有 .c 文件
ALL_SRCS  := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/ws/*.c)

# 🌟 核心修改 2：排除掉 XDP 内核代码，剩下的就是纯正的用户态/业务态源码
USER_SRCS := $(filter-out $(SRC_DIR)/xdp_kern.c, $(ALL_SRCS))

# 🌟 核心修改 3：将用户态源码平移映射到 obj/ 目录下（保留其原有的 ws/ 子目录结构）
USER_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(USER_SRCS))

# 4. 伪目标定义
.PHONY: all clean directories build_cli

# 默认构建流
all: directories $(XDP_OBJ) $(TARGET) build_cli

# 5. 目录自动创建规则
# 🌟 核心修改 4：创建 obj/ 的同时，必须强行把 obj/ws/ 子目录一并建好，否则生成 .o 时会报错
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/ws
	@mkdir -p $(BIN_DIR)

# 6. 用户态可执行文件链接规则
$(TARGET): $(USER_OBJS)
	@echo "[+] Linking User-Plane Binary with Dependencies: $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 7. 用户态 .c 到 .o 的编译规则 (🌟 核心修改 5：通过目录通配符，完美兼容 src/ 和 src/ws/ 里的所有规则)
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