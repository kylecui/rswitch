
# Makefile at repo root
BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

BUILD_DIR := build
BPF_DIR := bpf
USR_DIR := user

BPF_OBJ := $(BUILD_DIR)/bpf/acl_core.bpf.o
LOADER  := $(BUILD_DIR)/user/xdp-acl-loader

CFLAGS := -O2 -g -Wall -Wextra

all: $(BPF_OBJ) $(LOADER)

$(BUILD_DIR)/bpf/%.bpf.o: $(BPF_DIR)/%.bpf.c $(BPF_DIR)/include/common.h
	@mkdir -p $(BUILD_DIR)/bpf
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -I$(BPF_DIR) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@ || true

$(BUILD_DIR)/user/%: $(USR_DIR)/%.c
	@mkdir -p $(BUILD_DIR)/user
	$(CC) $(CFLAGS) -I$(BPF_DIR) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDLIBS) -lelf -lz

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
