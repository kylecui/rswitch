# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# rSwitch: Reconfigurable Switch Modular Build System

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(shell which bpftool || echo /usr/local/sbin/bpftool)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

# Paths
LIBBPF_TOP = $(abspath ../external/libbpf/src)
LIBBPF_UAPI_INCLUDES = -I$(LIBBPF_TOP)/include/uapi
LIBBPF_INCLUDES = -I/usr/local/bpf/include
LIBBPF_LIBS = -L/usr/local/bpf/lib64 -lbpf

BPF_DIR = ./bpf
CORE_DIR = $(BPF_DIR)/core
MODULES_DIR = $(BPF_DIR)/modules
INCLUDE_DIR = $(BPF_DIR)/include
USER_DIR = ./user
BUILD_DIR = ./build
OBJ_DIR = $(BUILD_DIR)/bpf

INCLUDES = $(LIBBPF_UAPI_INCLUDES) $(LIBBPF_INCLUDES) -I$(INCLUDE_DIR) -I$(CORE_DIR)

# Clang BPF system includes
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Build targets
LOADER = $(BUILD_DIR)/rswitch_loader
HOT_RELOAD = $(BUILD_DIR)/hot_reload
VOQD = $(BUILD_DIR)/rswitch-voqd
RSWITCHCTL = $(BUILD_DIR)/rswitchctl
TELEMETRY = $(BUILD_DIR)/rswitch-telemetry
EVENT_CONSUMER = $(BUILD_DIR)/rswitch-events
# AFXDP_TEST = $(BUILD_DIR)/afxdp_test  # Requires libbpf with xsk.h support
CORE_OBJS = $(patsubst $(CORE_DIR)/%.bpf.c,$(OBJ_DIR)/%.bpf.o,$(wildcard $(CORE_DIR)/*.bpf.c))
MODULE_OBJS = $(patsubst $(MODULES_DIR)/%.bpf.c,$(OBJ_DIR)/%.bpf.o,$(wildcard $(MODULES_DIR)/*.bpf.c))
ALL_BPF_OBJS = $(CORE_OBJS) $(MODULE_OBJS)

.PHONY: all clean dirs vmlinux help

all: dirs $(LOADER) $(HOT_RELOAD) $(VOQD) $(RSWITCHCTL) $(TELEMETRY) $(EVENT_CONSUMER) $(ALL_BPF_OBJS)
	@echo "✓ Build complete"
	@echo "  Loader: $(LOADER)"
	@echo "  Hot-reload: $(HOT_RELOAD)"
	@echo "  VOQd: $(VOQD)"
	@echo "  Control: $(RSWITCHCTL)"
	@echo "  Telemetry: $(TELEMETRY)"
	@echo "  Event Consumer: $(EVENT_CONSUMER)"
	@echo "  BPF objects: $(words $(ALL_BPF_OBJS)) modules"
	@echo "  Note: AF_XDP test requires libbpf ≥1.0 with xsk.h"

dirs:
	@mkdir -p $(BUILD_DIR) $(OBJ_DIR)

# Generate vmlinux.h (CO-RE support)
$(INCLUDE_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h..."
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: $(INCLUDE_DIR)/vmlinux.h

# Build BPF programs (core and modules)
$(OBJ_DIR)/%.bpf.o: $(CORE_DIR)/%.bpf.c $(INCLUDE_DIR)/vmlinux.h $(wildcard $(INCLUDE_DIR)/*.h) $(wildcard $(CORE_DIR)/*.h)
	@echo "  CC [BPF]  $@"
	@$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -DDEBUG \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $@
	@$(LLVM_STRIP) -g $@

$(OBJ_DIR)/%.bpf.o: $(MODULES_DIR)/%.bpf.c $(INCLUDE_DIR)/vmlinux.h $(wildcard $(INCLUDE_DIR)/*.h) $(wildcard $(CORE_DIR)/*.h)
	@echo "  CC [BPF]  $@"
	@echo "  CC [BPF]  $@"
	@$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -DDEBUG \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $@
	@$(LLVM_STRIP) -g $@

# Build user-space loader
$(LOADER): $(USER_DIR)/loader/rswitch_loader.c $(USER_DIR)/loader/profile_parser.c $(wildcard $(USER_DIR)/loader/*.h)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-o $@ $(USER_DIR)/loader/rswitch_loader.c $(USER_DIR)/loader/profile_parser.c \
		$(LIBBPF_LIBS) -lelf -lz

# Build hot-reload tool
$(HOT_RELOAD): $(USER_DIR)/reload/hot_reload.c $(USER_DIR)/loader/profile_parser.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/loader \
		-o $@ $(USER_DIR)/reload/hot_reload.c \
		$(LIBBPF_LIBS) -lelf -lz

# Build VOQd daemon
$(VOQD): $(USER_DIR)/voqd/voqd.c $(USER_DIR)/voqd/voq.c $(USER_DIR)/voqd/ringbuf_consumer.c $(USER_DIR)/voqd/state_ctrl.c $(USER_DIR)/voqd/nic_queue.c $(wildcard $(USER_DIR)/voqd/*.h)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/voqd \
		-o $@ $(USER_DIR)/voqd/voqd.c $(USER_DIR)/voqd/voq.c \
		$(USER_DIR)/voqd/ringbuf_consumer.c $(USER_DIR)/voqd/state_ctrl.c \
		$(USER_DIR)/voqd/nic_queue.c \
		$(LIBBPF_LIBS) -lelf -lz -lpthread

# Build rswitchctl
$(RSWITCHCTL): $(USER_DIR)/ctl/rswitchctl.c $(USER_DIR)/ctl/rswitchctl_extended.c $(USER_DIR)/ctl/rswitchctl_acl.c $(USER_DIR)/ctl/rswitchctl_mirror.c
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/ctl \
		-o $@ $(USER_DIR)/ctl/rswitchctl.c $(USER_DIR)/ctl/rswitchctl_extended.c \
		$(USER_DIR)/ctl/rswitchctl_acl.c $(USER_DIR)/ctl/rswitchctl_mirror.c \
		$(LIBBPF_LIBS) -lelf -lz

# Build telemetry exporter
$(TELEMETRY): $(USER_DIR)/telemetry/telemetry.c $(wildcard $(USER_DIR)/telemetry/*.h)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/telemetry \
		-o $@ $(USER_DIR)/telemetry/telemetry.c \
		$(LIBBPF_LIBS) -lelf -lz -lpthread

# Build event consumer daemon
$(EVENT_CONSUMER): $(USER_DIR)/events/event_consumer.c $(wildcard $(USER_DIR)/events/*.h)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/events \
		-o $@ $(USER_DIR)/events/event_consumer.c \
		$(LIBBPF_LIBS) -lelf -lz -lpthread

# Build AF_XDP test program
$(AFXDP_TEST): $(USER_DIR)/afxdp/afxdp_socket.c $(USER_DIR)/afxdp/afxdp_test.c $(wildcard $(USER_DIR)/afxdp/*.h)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/afxdp \
		-o $@ $(USER_DIR)/afxdp/afxdp_socket.c $(USER_DIR)/afxdp/afxdp_test.c \
		$(LIBBPF_LIBS) -lelf -lz

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Clean complete"

help:
	@echo "rSwitch Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build loader and all BPF modules (default)"
	@echo "  vmlinux  - Generate vmlinux.h for CO-RE"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Directory structure:"
	@echo "  $(CORE_DIR)/       - Core BPF programs (dispatcher, egress)"
	@echo "  $(MODULES_DIR)/    - Pluggable modules (vlan, acl, route, etc.)"
	@echo "  $(USER_DIR)/       - User-space programs (loader, cli)"
	@echo "  $(BUILD_DIR)/      - Build output"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build everything"
	@echo "  make vmlinux      # Generate vmlinux.h first time"
	@echo "  make clean all    # Clean rebuild"
