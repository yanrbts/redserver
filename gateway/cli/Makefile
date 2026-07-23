CC       := gcc
CFLAGS   := -Wall -Wextra -O2 -DLOG_USE_COLOR -g -I. -I../src
LDFLAGS  := -lpthread
LIBS     :=

BIN_DIR  := ../bin
TARGET   := $(BIN_DIR)/cli
TARGET_IPMC := $(BIN_DIR)/ipmc

OBJ_DIR  := ../obj/cli

SRCS     := cli.c \
            linenoise.c \
            ../src/cmd.c \
            ../src/log.c

# ipmc 对应的源文件（可根据需要添加共同依赖的 .c 文件）
SRCS_IPMC := ipmc.c \
             ../src/ljb.c \
             ../src/log.c

# 提取所有源文件的纯文件名，并将它们映射到 ../obj/cli/ 目录下
OBJS      := $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(SRCS)))
OBJS_IPMC := $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(SRCS_IPMC)))
# DEPS     := $(OBJS:.o=.d)
DEPS      := $(patsubst %.o,%.d,$(sort $(OBJS) $(OBJS_IPMC)))

.PHONY: all clean help

all: $(TARGET) $(TARGET_IPMC)

$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "[LINK] Creating executable: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS) 
	@echo "[SUCCESS] Build complete!"

$(TARGET_IPMC): $(OBJS_IPMC) | $(BIN_DIR)
	@echo "[LINK] Creating executable: $@"
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "[SUCCESS] Build complete: $@"

$(BIN_DIR):
	@echo "[DIR] Creating directory: $@"
	mkdir -p $@

# 1. 编译当前目录下的源文件 (如 cli.c, linenoise.c) 并输出至 ../obj/cli/
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# 2. 编译父级目录下的 gc 源文件 (如 ../src/gc/cmd.c, ../src/gc/logf.c) 并输出至 ../obj/cli/
$(OBJ_DIR)/%.o: ../src/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR):
	@echo "[DIR] Creating directory: $@"
	mkdir -p $@

-include $(DEPS)

clean:
	@echo "[CLEAN] Removing object files, dependencies, and target..."
	rm -rf $(OBJ_DIR) $(DEPS)
	rm -f $(TARGET) $(TARGET_IPMC)
	@rmdir $(BIN_DIR) 2>/dev/null || true
	@echo "[CLEAN] Done."

help:
	@echo "Available targets:"
	@echo "  all     : Build the '$(TARGET)' executable (default)"
	@echo "  clean   : Remove all generated binaries, objects, and dependencies"
	@echo "  help    : Display this help message"