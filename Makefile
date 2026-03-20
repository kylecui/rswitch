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

# libxdp for AF_XDP support (xsk.h moved from libbpf to libxdp)
LIBXDP_CFLAGS = $(shell pkg-config --cflags libxdp 2>/dev/null || echo "")
LIBXDP_LIBS = $(shell pkg-config --libs libxdp 2>/dev/null || echo "-lxdp")

BPF_DIR = ./bpf
CORE_DIR = $(BPF_DIR)/core
MODULES_DIR = $(BPF_DIR)/modules
INCLUDE_DIR = $(BPF_DIR)/include
USER_DIR = ./user
COMMON_DIR = $(USER_DIR)/common
BUILD_DIR = ./build
OBJ_DIR = $(BUILD_DIR)/bpf

RS_LOG_OBJ = $(BUILD_DIR)/rs_log.o
LIFECYCLE_OBJ = $(BUILD_DIR)/lifecycle.o
REGISTRY_OBJ = $(BUILD_DIR)/registry.o
RESOURCE_LIMITS_OBJ = $(BUILD_DIR)/resource_limits.o
ROLLBACK_OBJ = $(BUILD_DIR)/rollback.o
AUDIT_OBJ = $(BUILD_DIR)/audit.o
TOPOLOGY_OBJ = $(BUILD_DIR)/topology.o
EVENT_DB_OBJ = $(BUILD_DIR)/event_db.o

INCLUDES = $(LIBBPF_UAPI_INCLUDES) $(LIBBPF_INCLUDES) -I$(INCLUDE_DIR) -I$(CORE_DIR)
USER_INCLUDES = -I$(COMMON_DIR)

# Clang BPF system includes
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Build targets
LOADER = $(BUILD_DIR)/rswitch_loader
HOT_RELOAD = $(BUILD_DIR)/hot_reload
VOQD = $(BUILD_DIR)/rswitch-voqd
STPD = $(BUILD_DIR)/rswitch-stpd
LLDPD = $(BUILD_DIR)/rswitch-lldpd
LACPD = $(BUILD_DIR)/rswitch-lacpd
RSWITCHCTL = $(BUILD_DIR)/rswitchctl
RSPORTCTL = $(BUILD_DIR)/rsportctl
RSVLANCTL = $(BUILD_DIR)/rsvlanctl
RSACLCTL = $(BUILD_DIR)/rsaclctl
RSROUTECTL = $(BUILD_DIR)/rsroutectl
RSQOSCTL = $(BUILD_DIR)/rsqosctl
RSFLOWCTL = $(BUILD_DIR)/rsflowctl
RSNATCTL = $(BUILD_DIR)/rsnatctl
RSVOQCTL = $(BUILD_DIR)/rsvoqctl
RSTUNNELCTL = $(BUILD_DIR)/rstunnelctl
TELEMETRY = $(BUILD_DIR)/rswitch-telemetry
EVENT_CONSUMER = $(BUILD_DIR)/rswitch-events
PACKET_TRACE = $(BUILD_DIR)/rs_packet_trace
SFLOW_EXPORT = $(BUILD_DIR)/rswitch-sflow
PROMETHEUS_EXPORTER = $(BUILD_DIR)/rswitch-prometheus
WATCHDOG = $(BUILD_DIR)/rswitch-watchdog
CONTROLLER = $(BUILD_DIR)/rswitch-controller
AGENT = $(BUILD_DIR)/rswitch-agent
SNMPAGENT = $(BUILD_DIR)/rswitch-snmpagent
MGMTD = $(BUILD_DIR)/rswitch-mgmtd
MONGOOSE_OBJ = $(BUILD_DIR)/mongoose.o
MGMT_IFACE_OBJ = $(BUILD_DIR)/mgmt_iface.o
WATCHDOG_OBJ = $(BUILD_DIR)/watchdog.o
# AFXDP_TEST = $(BUILD_DIR)/afxdp_test  # Requires libbpf with xsk.h support
CORE_OBJS = $(patsubst $(CORE_DIR)/%.bpf.c,$(OBJ_DIR)/%.bpf.o,$(wildcard $(CORE_DIR)/*.bpf.c))
MODULE_OBJS = $(patsubst $(MODULES_DIR)/%.bpf.c,$(OBJ_DIR)/%.bpf.o,$(wildcard $(MODULES_DIR)/*.bpf.c))
ALL_BPF_OBJS = $(CORE_OBJS) $(MODULE_OBJS)

.PHONY: all clean dirs vmlinux help test test-bpf fuzz integration-test benchmark gen-docs

all: dirs $(LOADER) $(HOT_RELOAD) $(VOQD) $(STPD) $(LLDPD) $(LACPD) $(RSWITCHCTL) $(RSPORTCTL) $(RSVLANCTL) $(RSACLCTL) $(RSROUTECTL) $(RSQOSCTL) $(RSFLOWCTL) $(RSNATCTL) $(RSVOQCTL) $(RSTUNNELCTL) $(TELEMETRY) $(EVENT_CONSUMER) $(PACKET_TRACE) $(SFLOW_EXPORT) $(PROMETHEUS_EXPORTER) $(WATCHDOG) $(CONTROLLER) $(AGENT) $(SNMPAGENT) $(MGMTD) $(ALL_BPF_OBJS)
	@echo "✓ Build complete"
	@echo "  Loader: $(LOADER)"
	@echo "  Reload: $(HOT_RELOAD)"
	@echo "  VOQd: $(VOQD)"
	@echo "  STPd: $(STPD)"
	@echo "  LLDPd: $(LLDPD)"
	@echo "  LACPd: $(LACPD)"
	@echo "  Control: $(RSWITCHCTL)"
	@echo "  PortCtl: $(RSPORTCTL)"
	@echo "  VLANCtl: $(RSVLANCTL)"
	@echo "  ACLCtl: $(RSACLCTL)"
	@echo "  RouteCtl: $(RSROUTECTL)"
	@echo "  QoSCtl: $(RSQOSCTL)"
	@echo "  FlowCtl: $(RSFLOWCTL)"
	@echo "  NATCtl: $(RSNATCTL)"
	@echo "  VOQCtl: $(RSVOQCTL)"
	@echo "  TunnelCtl: $(RSTUNNELCTL)"
	@echo "  Telemetry: $(TELEMETRY)"
	@echo "  Event Consumer: $(EVENT_CONSUMER)"
	@echo "  sFlow: $(SFLOW_EXPORT)"
	@echo "  Prometheus: $(PROMETHEUS_EXPORTER)"
	@echo "  Watchdog: $(WATCHDOG)"
	@echo "  Controller: $(CONTROLLER)"
	@echo "  Agent: $(AGENT)"
	@echo "  SNMP Agent: $(SNMPAGENT)"
	@echo "  Mgmt Daemon: $(MGMTD)"
	@echo "  BPF objects: $(words $(ALL_BPF_OBJS)) modules"
	@echo "  Note: AF_XDP requires libxdp (xsk.h moved from libbpf)"

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
	@$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -DDEBUG \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $@
	@$(LLVM_STRIP) -g $@

$(RS_LOG_OBJ): $(COMMON_DIR)/rs_log.c $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 $(USER_INCLUDES) -c $< -o $@

$(LIFECYCLE_OBJ): $(USER_DIR)/lifecycle/lifecycle.c $(USER_DIR)/lifecycle/lifecycle.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-c $< -o $@

$(REGISTRY_OBJ): $(USER_DIR)/registry/registry.c $(USER_DIR)/registry/registry.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/registry $(USER_INCLUDES) \
		-c $< -o $@

$(RESOURCE_LIMITS_OBJ): $(USER_DIR)/resource/resource_limits.c $(USER_DIR)/resource/resource_limits.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-c $< -o $@

$(ROLLBACK_OBJ): $(USER_DIR)/rollback/rollback.c $(USER_DIR)/rollback/rollback.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-c $< -o $@

$(AUDIT_OBJ): $(USER_DIR)/audit/audit.c $(USER_DIR)/audit/audit.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-c $< -o $@

$(TOPOLOGY_OBJ): $(USER_DIR)/topology/topology.c $(USER_DIR)/topology/topology.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-c $< -o $@

$(EVENT_DB_OBJ): $(USER_DIR)/mgmt/event_db.c $(USER_DIR)/mgmt/event_db.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 $(USER_INCLUDES) -I$(USER_DIR)/mgmt -c $< -o $@

# Build user-space loader
$(LOADER): $(USER_DIR)/loader/rswitch_loader.c $(USER_DIR)/loader/profile_parser.c $(wildcard $(USER_DIR)/loader/*.h) $(USER_DIR)/lifecycle/lifecycle.h $(RS_LOG_OBJ) $(LIFECYCLE_OBJ) $(RESOURCE_LIMITS_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/loader/rswitch_loader.c $(USER_DIR)/loader/profile_parser.c \
		$(LIFECYCLE_OBJ) $(RESOURCE_LIMITS_OBJ) $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build hot-reload tool
$(HOT_RELOAD): $(USER_DIR)/reload/hot_reload.c $(USER_DIR)/loader/profile_parser.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/loader $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/reload/hot_reload.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build VOQd daemon
$(VOQD): $(USER_DIR)/voqd/voqd.c $(USER_DIR)/voqd/voq.c $(USER_DIR)/voqd/shaper.c $(USER_DIR)/voqd/ringbuf_consumer.c $(USER_DIR)/voqd/state_ctrl.c $(USER_DIR)/voqd/nic_queue.c $(USER_DIR)/voqd/afxdp_socket.c $(USER_DIR)/voqd/voqd_dataplane.c $(wildcard $(USER_DIR)/voqd/*.h) $(RS_LOG_OBJ) $(RESOURCE_LIMITS_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) -DHAVE_LIBBPF_XSK \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(LIBXDP_CFLAGS) -I$(USER_DIR)/voqd $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/voqd/voqd.c $(USER_DIR)/voqd/voq.c \
		$(USER_DIR)/voqd/shaper.c \
		$(USER_DIR)/voqd/ringbuf_consumer.c $(USER_DIR)/voqd/state_ctrl.c \
		$(USER_DIR)/voqd/nic_queue.c $(USER_DIR)/voqd/afxdp_socket.c \
		$(USER_DIR)/voqd/voqd_dataplane.c \
		$(RESOURCE_LIMITS_OBJ) $(RS_LOG_OBJ) $(LIBBPF_LIBS) $(LIBXDP_LIBS) -lelf -lz -lpthread

$(STPD): $(USER_DIR)/stpd/stpd.c $(USER_DIR)/stpd/stpd.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/stpd $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/stpd/stpd.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(LLDPD): $(USER_DIR)/lldpd/lldpd.c $(USER_DIR)/lldpd/lldpd.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/lldpd $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/lldpd/lldpd.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(LACPD): $(USER_DIR)/lacpd/lacpd.c $(USER_DIR)/lacpd/lacpd.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/lacpd $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/lacpd/lacpd.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(WATCHDOG): $(USER_DIR)/watchdog/watchdog.c $(USER_DIR)/watchdog/watchdog.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) -DRSWITCH_WATCHDOG_STANDALONE \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/watchdog $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/watchdog/watchdog.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(CONTROLLER): $(USER_DIR)/controller/controller.c $(USER_DIR)/controller/controller.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/controller $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/controller/controller.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(AGENT): $(USER_DIR)/agent/agent.c $(USER_DIR)/agent/agent.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/agent $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/agent/agent.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(SNMPAGENT): $(USER_DIR)/snmpagent/snmpagent.c $(USER_DIR)/snmpagent/snmpagent.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/snmpagent $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/snmpagent/snmpagent.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build mongoose library object
$(MONGOOSE_OBJ): $(USER_DIR)/mgmt/mongoose.c $(USER_DIR)/mgmt/mongoose.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -DMG_ENABLE_LINES=0 -c $(USER_DIR)/mgmt/mongoose.c -o $@

# Build management interface object
$(MGMT_IFACE_OBJ): $(USER_DIR)/mgmt/mgmt_iface.c $(USER_DIR)/mgmt/mgmt_iface.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 $(USER_INCLUDES) -I$(USER_DIR)/mgmt -c $(USER_DIR)/mgmt/mgmt_iface.c -o $@

# Build watchdog library object (non-standalone, for linking into other binaries)
$(WATCHDOG_OBJ): $(USER_DIR)/watchdog/watchdog.c $(USER_DIR)/watchdog/watchdog.h $(COMMON_DIR)/rs_log.h
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/watchdog $(USER_INCLUDES) \
		-c $< -o $@

# Build management daemon
$(MGMTD): $(USER_DIR)/mgmt/mgmtd.c $(USER_DIR)/mgmt/mgmtd.h $(USER_DIR)/mgmt/mgmt_iface.h $(USER_DIR)/mgmt/mongoose.h $(USER_DIR)/mgmt/event_db.h $(USER_DIR)/loader/profile_parser.c $(USER_DIR)/loader/profile_parser.h $(MONGOOSE_OBJ) $(MGMT_IFACE_OBJ) $(WATCHDOG_OBJ) $(EVENT_DB_OBJ) $(RS_LOG_OBJ) $(LIFECYCLE_OBJ) $(AUDIT_OBJ) $(ROLLBACK_OBJ) $(TOPOLOGY_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-I$(USER_DIR)/mgmt -I$(USER_DIR)/loader -I$(USER_DIR)/watchdog -I$(USER_DIR)/topology \
		-I$(USER_DIR)/audit -I$(USER_DIR)/rollback -I$(USER_DIR)/lifecycle \
		-o $@ $(USER_DIR)/mgmt/mgmtd.c $(USER_DIR)/loader/profile_parser.c \
		$(MONGOOSE_OBJ) $(MGMT_IFACE_OBJ) $(WATCHDOG_OBJ) $(EVENT_DB_OBJ) \
		$(LIFECYCLE_OBJ) $(AUDIT_OBJ) $(ROLLBACK_OBJ) $(TOPOLOGY_OBJ) $(RS_LOG_OBJ) \
		$(LIBBPF_LIBS) -lelf -lz -lpthread -lsqlite3

# Build rswitchctl
$(RSWITCHCTL): $(USER_DIR)/ctl/rswitchctl.c $(USER_DIR)/ctl/rswitchctl_dev.c $(USER_DIR)/ctl/rswitchctl_extended.c $(USER_DIR)/ctl/rswitchctl_acl.c $(USER_DIR)/ctl/rswitchctl_mirror.c $(USER_DIR)/loader/profile_parser.c $(USER_DIR)/watchdog/watchdog.c $(USER_DIR)/watchdog/watchdog.h $(USER_DIR)/lifecycle/lifecycle.h $(USER_DIR)/registry/registry.c $(USER_DIR)/rollback/rollback.h $(USER_DIR)/audit/audit.h $(USER_DIR)/topology/topology.h $(RS_LOG_OBJ) $(LIFECYCLE_OBJ) $(REGISTRY_OBJ) $(ROLLBACK_OBJ) $(AUDIT_OBJ) $(TOPOLOGY_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) 		-I$(USER_DIR)/ctl -I$(USER_DIR)/loader -I$(USER_DIR)/watchdog -I$(USER_DIR)/registry -I$(USER_DIR)/rollback -I$(USER_DIR)/audit -I$(USER_DIR)/topology $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/ctl/rswitchctl.c $(USER_DIR)/ctl/rswitchctl_dev.c $(USER_DIR)/ctl/rswitchctl_extended.c \
		$(USER_DIR)/ctl/rswitchctl_acl.c $(USER_DIR)/ctl/rswitchctl_mirror.c $(USER_DIR)/loader/profile_parser.c \
		$(USER_DIR)/watchdog/watchdog.c \
		$(REGISTRY_OBJ) $(ROLLBACK_OBJ) $(AUDIT_OBJ) $(TOPOLOGY_OBJ) $(LIFECYCLE_OBJ) $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsportctl
$(RSPORTCTL): $(USER_DIR)/tools/rsportctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsportctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsvlanctl
$(RSVLANCTL): $(USER_DIR)/tools/rsvlanctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsvlanctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsaclctl
$(RSACLCTL): $(USER_DIR)/tools/rsaclctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsaclctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsroutectl
$(RSROUTECTL): $(USER_DIR)/tools/rsroutectl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsroutectl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsqosctl
$(RSQOSCTL): $(USER_DIR)/tools/rsqosctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsqosctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsflowctl
$(RSFLOWCTL): $(USER_DIR)/tools/rsflowctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsflowctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsnatctl
$(RSNATCTL): $(USER_DIR)/tools/rsnatctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsnatctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rsvoqctl
$(RSVOQCTL): $(USER_DIR)/tools/rsvoqctl.c $(USER_DIR)/voqd/shaper.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rsvoqctl.c $(USER_DIR)/voqd/shaper.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build rstunnelctl
$(RSTUNNELCTL): $(USER_DIR)/tools/rstunnelctl.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rstunnelctl.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

# Build telemetry exporter
$(TELEMETRY): $(USER_DIR)/telemetry/telemetry.c $(wildcard $(USER_DIR)/telemetry/*.h) $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/telemetry $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/telemetry/telemetry.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

# Build event consumer daemon
$(EVENT_CONSUMER): $(USER_DIR)/events/event_consumer.c $(wildcard $(USER_DIR)/events/*.h) $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/events $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/events/event_consumer.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

# Build packet trace utility
$(PACKET_TRACE): $(USER_DIR)/tools/rs_packet_trace.c $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rs_packet_trace.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(SFLOW_EXPORT): $(USER_DIR)/sflow/sflow_export.c $(USER_DIR)/sflow/sflow_export.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/sflow $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/sflow/sflow_export.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

$(PROMETHEUS_EXPORTER): $(USER_DIR)/exporter/prometheus_exporter.c $(USER_DIR)/exporter/prometheus_exporter.h $(RS_LOG_OBJ)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/exporter $(USER_INCLUDES) \
		-o $@ $(USER_DIR)/exporter/prometheus_exporter.c \
		$(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz -lpthread

# Build packet trace v2 (ringbuf-based)
$(BUILD_DIR)/rs_packet_trace_v2: $(USER_DIR)/tools/rs_packet_trace_v2.c $(BPF_DIR)/tools/packet_trace.bpf.o
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-o $@ $(USER_DIR)/tools/rs_packet_trace_v2.c \
		$(LIBBPF_LIBS) -lelf -lz

# Build packet_trace.bpf.o (needed for v2)
$(BPF_DIR)/tools/packet_trace.bpf.o: bpf/tools/packet_trace.bpf.c
	@mkdir -p $(BPF_DIR)/tools
	@echo "  CC [BPF]  $@"
	@$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $@


# Build AF_XDP test program
$(AFXDP_TEST): $(USER_DIR)/afxdp/afxdp_socket.c $(USER_DIR)/afxdp/afxdp_test.c $(wildcard $(USER_DIR)/afxdp/*.h)
	@echo "  CC [USER] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -I$(USER_DIR)/afxdp \
		-o $@ $(USER_DIR)/afxdp/afxdp_socket.c $(USER_DIR)/afxdp/afxdp_test.c \
		$(LIBBPF_LIBS) -lelf -lz

# Test targets
TEST_DIR = ./test/unit
TEST_DISPATCHER = $(BUILD_DIR)/test_dispatcher
TEST_ACL = $(BUILD_DIR)/test_acl
TEST_VLAN = $(BUILD_DIR)/test_vlan
TEST_ACL_BPF = $(BUILD_DIR)/test_acl_bpf
TEST_STP = $(BUILD_DIR)/test_stp
TEST_RATE_LIMITER = $(BUILD_DIR)/test_rate_limiter
TEST_SOURCE_GUARD = $(BUILD_DIR)/test_source_guard
TEST_CONNTRACK = $(BUILD_DIR)/test_conntrack
TEST_ARP_LEARN = $(BUILD_DIR)/test_arp_learn
TEST_L2LEARN = $(BUILD_DIR)/test_l2learn
TEST_ROUTE = $(BUILD_DIR)/test_route
TEST_MIRROR = $(BUILD_DIR)/test_mirror
FUZZ_MODULES = $(BUILD_DIR)/fuzz_modules

$(TEST_DISPATCHER): $(TEST_DIR)/test_dispatcher.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_ACL): $(TEST_DIR)/test_acl.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_VLAN): $(TEST_DIR)/test_vlan.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_ACL_BPF): $(TEST_DIR)/test_acl_bpf.c $(TEST_DIR)/rs_test_runner.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $(TEST_DIR)/test_acl_bpf.c $(TEST_DIR)/rs_test_runner.c $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(FUZZ_MODULES): test/fuzz/fuzz_modules.c $(RS_LOG_OBJ)
	@echo "  CC [FUZZ] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ test/fuzz/fuzz_modules.c $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_STP): $(TEST_DIR)/test_stp.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_RATE_LIMITER): $(TEST_DIR)/test_rate_limiter.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_SOURCE_GUARD): $(TEST_DIR)/test_source_guard.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_CONNTRACK): $(TEST_DIR)/test_conntrack.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_ARP_LEARN): $(TEST_DIR)/test_arp_learn.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_L2LEARN): $(TEST_DIR)/test_l2learn.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_ROUTE): $(TEST_DIR)/test_route.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

$(TEST_MIRROR): $(TEST_DIR)/test_mirror.c $(RS_LOG_OBJ)
	@echo "  CC [TEST] $@"
	@$(CLANG) -g -O2 -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(USER_INCLUDES) \
		-o $@ $< $(RS_LOG_OBJ) $(LIBBPF_LIBS) -lelf -lz

test: $(TEST_DISPATCHER) $(TEST_ACL) $(TEST_VLAN) $(TEST_STP) $(TEST_RATE_LIMITER) $(TEST_SOURCE_GUARD) $(TEST_CONNTRACK) $(TEST_ARP_LEARN) $(TEST_L2LEARN) $(TEST_ROUTE) $(TEST_MIRROR)
	@echo "✓ Test binaries built"
	@echo "  Run: sudo ./test/unit/run_tests.sh"

test-bpf: $(TEST_ACL_BPF)
	@echo "Running BPF_PROG_RUN ACL test harness (requires root)"
	@sudo ./build/test_acl_bpf ./build/bpf/acl.bpf.o ./build/test_acl_bpf.junit.xml

fuzz: $(FUZZ_MODULES)
	@echo "Running module fuzz harness (requires root)"
	@sudo ./build/fuzz_modules ./build/bpf/acl.bpf.o acl_filter 10000

integration-test:
	@echo "Running integration tests..."
	@sudo bash ./test/integration/run_all.sh

benchmark:
	@echo "Running benchmarks..."
	@bash test/benchmark/run_all.sh

gen-docs:
	@python3 scripts/gen_api_docs.py

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Clean complete"

# ── Production install/uninstall ──────────────────────────────────
INSTALL_PREFIX ?= /opt/rswitch

install: all
	@echo "Installing rSwitch to $(INSTALL_PREFIX) ..."
	@mkdir -p $(INSTALL_PREFIX)/build/bpf
	@mkdir -p $(INSTALL_PREFIX)/scripts
	@mkdir -p $(INSTALL_PREFIX)/etc/profiles
	@mkdir -p $(INSTALL_PREFIX)/etc/systemd
	@mkdir -p $(INSTALL_PREFIX)/web
	@# Binaries
	@cp -f $(BUILD_DIR)/rswitch_loader   $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/hot_reload       $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rswitch-mgmtd    $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rswitchctl       $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsportctl        $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsvlanctl        $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsaclctl         $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsroutectl       $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsqosctl         $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsflowctl        $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsnatctl         $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rsvoqctl         $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rstunnelctl      $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rswitch-events   $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rs_packet_trace  $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rswitch-watchdog $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rswitch-telemetry $(INSTALL_PREFIX)/build/
	@cp -f $(BUILD_DIR)/rswitch-sflow    $(INSTALL_PREFIX)/build/
	@for f in $(BUILD_DIR)/rswitch-voqd $(BUILD_DIR)/rswitch-stpd $(BUILD_DIR)/rswitch-lldpd \
	          $(BUILD_DIR)/rswitch-lacpd $(BUILD_DIR)/rswitch-prometheus \
	          $(BUILD_DIR)/rswitch-controller $(BUILD_DIR)/rswitch-agent $(BUILD_DIR)/rswitch-snmpagent; do \
	    [ -f "$$f" ] && cp -f "$$f" $(INSTALL_PREFIX)/build/ || true; \
	done
	@# BPF objects
	@cp -f $(OBJ_DIR)/*.bpf.o $(INSTALL_PREFIX)/build/bpf/
	@# Scripts
	@cp -f scripts/rswitch-init.sh        $(INSTALL_PREFIX)/scripts/
	@cp -f scripts/rswitch-failsafe.sh    $(INSTALL_PREFIX)/scripts/
	@cp -f scripts/rswitch-mgmtd-start.sh $(INSTALL_PREFIX)/scripts/
	@for f in scripts/setup_nic_queues.sh scripts/cleanup_nic_queues.sh \
	          scripts/unload.sh scripts/hot-reload.sh scripts/setup_veth_egress.sh \
	          scripts/rswitch-detect-ports.sh scripts/rswitch-gen-profile.sh \
	          scripts/install.sh scripts/uninstall.sh; do \
	    [ -f "$$f" ] && cp -f "$$f" $(INSTALL_PREFIX)/scripts/ || true; \
	done
	@chmod +x $(INSTALL_PREFIX)/scripts/*.sh
	@# Config, profiles, systemd templates, web
	@cp -f etc/profiles/*.yaml $(INSTALL_PREFIX)/etc/profiles/
	@cp -f etc/systemd/*.service $(INSTALL_PREFIX)/etc/systemd/
	@cp -rf web/* $(INSTALL_PREFIX)/web/
	@echo "✓ Installed to $(INSTALL_PREFIX)"
	@echo "  Run: sudo rswitch-install to set up systemd services and start"

uninstall:
	@echo "Uninstalling rSwitch from $(INSTALL_PREFIX) ..."
	@systemctl stop rswitch-mgmtd 2>/dev/null || true
	@systemctl stop rswitch 2>/dev/null || true
	@systemctl disable rswitch-mgmtd rswitch rswitch-failsafe rswitch-watchdog 2>/dev/null || true
	@rm -f /etc/systemd/system/rswitch.service
	@rm -f /etc/systemd/system/rswitch-mgmtd.service
	@rm -f /etc/systemd/system/rswitch-failsafe.service
	@rm -f /etc/systemd/system/rswitch-watchdog.service
	@systemctl daemon-reload 2>/dev/null || true
	@rm -rf $(INSTALL_PREFIX)
	@echo "✓ Uninstalled"

install-sdk:
	@echo "Generating rSwitch SDK..."
	@mkdir -p sdk/include
	@cp bpf/include/rswitch_bpf.h sdk/include/
	@cp bpf/include/rswitch_common.h sdk/include/
	@cp bpf/core/module_abi.h sdk/include/
	@cp bpf/core/uapi.h sdk/include/
	@cp bpf/core/map_defs.h sdk/include/
	@if [ -f bpf/include/vmlinux.h ]; then cp bpf/include/vmlinux.h sdk/include/; fi
	@echo "SDK generated in sdk/"
	@echo "  Headers: sdk/include/"
	@echo "  Templates: sdk/templates/"
	@echo "  Build: make -f sdk/Makefile.module MODULE=your_module"

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
