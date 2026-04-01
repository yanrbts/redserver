#
# Copyright (c) 2026-2026, Red LRM.
# Author: [yanruibing]
#

# 1. Compiler and Flags
CC       := gcc
CFLAGS   := -Wall -Wextra -O2 -g -D_GNU_SOURCE
# Include paths: current dir and parent's include dir
CPPFLAGS := -I. -I../include
LDFLAGS  := -lpthread

# 2. Paths Configuration
# Target binary placed in the sibling 'bin' directory
TARGET_DIR := ../bin
TARGET     := $(TARGET_DIR)/redhlth

# Directory for intermediate object files
OBJ_DIR    := ./obj

# 3. Source and Object Files
# All .c files in the current 'health' directory
SRCS       := $(wildcard *.c)
OBJS       := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# 4. Default Rule
all: prepare $(TARGET)

# 5. Create necessary directories
prepare:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(TARGET_DIR)

# 6. Linking the Final Binary
$(TARGET): $(OBJS)
	@echo "  LD      $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build Successful: $(TARGET)"

# 7. Compiling Source Files
# -MMD generates .d files for header dependency tracking
$(OBJ_DIR)/%.o: %.c
	@echo "  CC      $<"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -c $< -o $@

# 8. Include Dependencies
-include $(OBJS:.o=.d)

# 9. Cleanup
clean:
	@echo "Cleaning up health objects and binary..."
	@rm -rf $(OBJ_DIR)
	@rm -f $(TARGET)

.PHONY: all prepare clean