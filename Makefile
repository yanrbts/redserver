CC       := gcc
BPF_CC   := clang
CFLAGS   := -ggdb -Wall -Wextra -O2 -DLOG_USE_COLOR -Iinclude -Isrc -Isrc/xdp
BPF_CFLAGS := -O2 -g -target bpf -Iinclude -Isrc/xdp

# 核心修改：将 XDP 库直接放入全局链接标志中，确保每个测试都能找到符号
LDFLAGS  := -lpthread -lbpf -lelf -lz

HEALTH_DIR 	 := health
SRC_DIR      := src
XDP_SRC_DIR  := src/xdp
OBJ_DIR      := obj
BIN_DIR      := bin
TEST_DIR     := test
TEST_BIN_DIR := $(BIN_DIR)/tests

TARGET       := $(BIN_DIR)/redlrm

# --- 文件分类 ---
# 内核代码：*.kern.c
BPF_KERN_SRCS := $(wildcard $(XDP_SRC_DIR)/*_kern.c)
# 用户态 XDP 代码：排除内核代码
XDP_USER_SRCS := $(filter-out $(BPF_KERN_SRCS), $(wildcard $(XDP_SRC_DIR)/*.c))
# 根目录源码
SRCS          := $(wildcard $(SRC_DIR)/*.c)

# --- 目标定义 ---
BPF_OBJS      := $(patsubst $(XDP_SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(BPF_KERN_SRCS))

# 编译出的用户态对象位置
OBJS_MAIN     := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
OBJS_XDP      := $(patsubst $(XDP_SRC_DIR)/%.c, $(OBJ_DIR)/xdp/%.o, $(XDP_USER_SRCS))

# 库对象（排除主程序入口）
EXCLUDE_MAIN  := $(OBJ_DIR)/redlrm.o $(OBJ_DIR)/proxy.o
LIB_OBJS      := $(filter-out $(EXCLUDE_MAIN), $(OBJS_MAIN)) $(OBJS_XDP)
ALL_OBJS      := $(OBJS_MAIN) $(OBJS_XDP)

# --- 编译规则 ---

all: $(BPF_OBJS) $(TARGET) tests health_subdir

# 1. 编译内核 BPF 字节码
$(BIN_DIR)/%_kern.o: $(XDP_SRC_DIR)/%_kern.c | $(BIN_DIR)
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

# 2. 链接主程序
$(TARGET): $(ALL_OBJS) | $(BIN_DIR)
	$(CC) $(ALL_OBJS) -o $@ $(LDFLAGS)

# 3. 链接测试程序
$(TEST_BIN_DIR)/%: $(TEST_DIR)/%.c $(LIB_OBJS) | $(TEST_BIN_DIR)
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# 4. 编译用户态源码 (src/*.c)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# 5. 编译 XDP 用户态源码 (src/xdp/*.c)
$(OBJ_DIR)/xdp/%.o: $(XDP_SRC_DIR)/%.c | $(OBJ_DIR)/xdp
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR) $(OBJ_DIR)/xdp $(TEST_BIN_DIR):
	mkdir -p $@

tests: $(patsubst $(TEST_DIR)/%.c, $(TEST_BIN_DIR)/%, $(wildcard $(TEST_DIR)/*.c))

health_subdir:
	$(MAKE) -C $(HEALTH_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean tests health_subdir