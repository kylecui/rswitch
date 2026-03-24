> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch Development Guide

**Version**: 1.0  
**Date**: November 18, 2025  
**Status**: Active Development (v1.1-dev)

This guide consolidates the most important development information from the archived documentation, providing a comprehensive overview of the current state, roadmap, and best practices for rSwitch development.

---

## 📊 Current Project Status

### Phase Completion (100% Complete)
- ✅ **Phase 1**: Core Infrastructure - Modular XDP framework
- ✅ **Phase 2**: Modular Components - 7 CO-RE compatible modules
- ✅ **Phase 3**: VOQd Integration - AF_XDP + QoS data plane
- ✅ **Phase 4**: Control & Observability - CLI tools and telemetry
- 🔄 **Phase 5**: Performance Benchmarking & Documentation (In Progress)

### Module Status Overview

| Module | Status | Stage | Size | Key Features |
|--------|--------|-------|------|--------------|
| **dispatcher** | ✅ Complete | - | 22KB | XDP ingress orchestration |
| **egress** | ✅ Complete | - | 17KB | Devmap egress processing |
| **vlan** | ✅ Complete | 20 | 13KB | ACCESS/TRUNK/HYBRID modes |
| **l2learn** | ✅ Complete | 80 | 17KB | MAC learning & aging |
| **lastcall** | ✅ Complete | 90 | 8.2KB | Final forwarding |
| **afxdp_redirect** | ✅ Complete | 85 | 14KB | AF_XDP integration |
| **core_example** | ✅ Complete | 85 | 11KB | Development template |
| **acl** | ✅ Complete | 30 | 20KB | L3/L4 filtering |
| **mirror** | ✅ Complete | 40 | 14KB | SPAN port mirroring |
| **egress_vlan** | ✅ Complete | - | 43KB | Egress VLAN processing |
| **egress_qos** | ✅ Complete | - | - | QoS classification & marking |
| **route** | 📋 Planned | 25 | - | IPv4 LPM routing |

**CO-RE Compatibility**: 7/7 modules fully portable across kernel versions 5.8+

---

## 🎯 Development Roadmap

### Immediate Priorities (Q4 2024)

#### Week 2-3: Route Module Implementation
- **Priority**: P0 (Critical)
- **Workload**: 2-3 weeks
- **Features**:
  - IPv4 LPM routing table (BPF_MAP_TYPE_LPM_TRIE)
  - Static route configuration
  - ARP table management
  - TTL decrement and validation
  - Next-hop resolution

#### Week 4-8: Integration & Testing
- Complete ACL + Mirror + VLAN integration testing
- Performance optimization
- Documentation updates

### Q1 2025: v1.1 Release

#### QoS Module (P1, 1-2 weeks)
- Traffic classification (L3/L4, DSCP, PCP)
- QoS marking (DSCP/PCP rewrite)
- Token bucket rate limiting
- VOQd priority mapping

#### Stateful ACL (P1, 2-3 weeks)
- TCP connection tracking
- TCP state machine implementation
- LRU-based connection table
- Established/Related/Invalid state handling

### Q2 2025: v1.2 Release

#### QinQ Support (P2, 1-2 weeks)
- 802.1ad double VLAN tagging
- S-TAG/C-TAG processing
- Customer/Provider/Hybrid port modes

### Q3-Q4 2025: v2.0 Release

#### Enterprise Protocols (P3)
- **STP/RSTP** (3-4 weeks): Spanning Tree Protocol
- **LACP** (3-4 weeks): Link Aggregation Control Protocol
- **LLDP** (1 week): Link Layer Discovery Protocol

### Profile System Enhancements (Q1-Q2 2025)

#### Advanced YAML Support (P1, 2-3 weeks)
- **YAML stage overrides**: Allow profiles to override ELF-defined stages
- **Optional modules**: Conditional module loading
- **Module sub-fields**: Extended configuration options

#### Module Configuration Parameters (P1, 1 week)
- Module-specific configuration (ACL rule limits, QoS depths)
- Extended `rs_module_desc` structure
- Enhanced `rswitchctl module-config` commands

#### Profile Inheritance & Templates (P2, 2 weeks)
- Configuration inheritance (`inherits` field)
- Template system with parameterization
- Reusable profile components

---

## 🔧 Module Development Best Practices

### eBPF Programming Guidelines

#### Golden Rule: Bounds Checking
```c
// ❌ WRONG - Access before validation
if (arr[i] == target) {
    return 1;  // Verifier error: potential out-of-bounds
}

// ✅ CORRECT - Validate BEFORE access
if (i >= count) break;  // Early exit
if (arr[i] == target) { // Safe access
    return 1;
}
```

#### Packet Header Validation
```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// Check bounds BEFORE access
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

// Now safe to access eth->h_proto
__u16 proto = eth->h_proto;
```

#### Map Access Safety
```c
// Check null BEFORE dereference
struct port_config *cfg = bpf_map_lookup_elem(&map, &key);
if (!cfg)
    return XDP_DROP;

cfg->enabled = 1;  // Safe access
```

### CO-RE Compliance Requirements

All modules must be CO-RE compatible:
- ✅ Use `BPF_CORE_READ()` for kernel structure access
- ✅ Include BTF information in compiled objects
- ✅ Test across multiple kernel versions (5.8+)
- ✅ Avoid direct structure field access

### Module Structure Template

```c
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module metadata (REQUIRED)
RS_DECLARE_MODULE(
    "my_module",                    // Name
    RS_HOOK_XDP_INGRESS,           // Hook point
    35,                            // Stage (execution order)
    RS_FLAG_NEED_L2L3_PARSE,       // Parse requirements
    "My module description"        // Description
);

// Per-CPU statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} my_stats SEC(".maps");

SEC("xdp")
int my_module(struct xdp_md *ctx) {
    struct rs_ctx *rs_ctx = RS_GET_CTX();
    if (!rs_ctx)
        return XDP_DROP;

    // Module logic here
    // ...

    // Continue pipeline
    rs_ctx->next_stage = 40;
    RS_TAIL_CALL_NEXT(ctx, rs_ctx);
    return XDP_DROP;
}
```

---

## 🏗️ Architecture Overview

### Core Components

#### 1. Dispatcher (`dispatcher.bpf.o`)
- **Function**: XDP ingress packet classification and routing
- **Maps**: `rs_progs` (tail-call program array), `rs_prog_chain` (stage chaining)
- **Key Logic**: Parse Ethernet headers, determine packet type, route to appropriate module chain

#### 2. Egress Handler (`egress.bpf.o`)
- **Function**: Unified egress processing via devmap
- **Maps**: `rs_xdp_devmap` (interface routing)
- **Key Logic**: VLAN tag handling, QoS marking, final transmission

#### 3. Module Pipeline
Modules execute in stage order via tail-calls:
- **Ingress Pipeline**: dispatcher → vlan (20) → acl (30) → route (25) → l2learn (80) → lastcall (90)
- **Egress Pipeline**: egress → egress_vlan → egress_qos → devmap

#### 4. VOQd Scheduler (`rswitch-voqd`)
- **Function**: User-space QoS scheduler with AF_XDP integration
- **Modes**: BYPASS/SHADOW/ACTIVE state machine
- **Features**: DRR/WFQ scheduling, zero-copy AF_XDP, priority queues

### Key Maps and Data Structures

#### Core Infrastructure Maps
- `rs_ctx_map`: Per-CPU context storage (packet metadata, forwarding decisions)
- `rs_event_bus`: Unified event ringbuf (telemetry, debugging)
- `rs_port_config_map`: Port configuration (VLAN modes, learning settings)
- `rs_stats_map`: Per-interface statistics

#### Module-Specific Maps
- `rs_mac_table`: MAC learning table (l2learn module)
- `rs_vlan_map`: VLAN membership configuration
- `qos_config_map`: QoS rules and settings
- `acl_rules_map`: Access control rules

---

## 🧪 Testing and Validation

### Functional Testing Checklist

#### Module Loading
```bash
# Verify module discovery
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --verbose

# Check loaded programs
sudo bpftool prog list | grep rswitch

# Verify map pinning
ls /sys/fs/bpf/ | grep rs_
```

#### Packet Processing
```bash
# Test VLAN processing
sudo tcpdump -i <interface> vlan

# Verify QoS marking
sudo tcpdump -i <interface> -v | grep DSCP

# Check MAC learning
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table
```

#### Control Plane
```bash
# Test CLI tools
sudo ./build/rswitchctl show-pipeline
sudo ./build/rsqosctl stats
sudo ./build/rswitchctl show-stats
```

### Performance Testing

#### Current Environment Limitations
- **Azure VM**: Uses `hv_netvsc` (generic XDP only, no native mode)
- **No AF_XDP**: Virtual NIC doesn't support zero-copy
- **Limited PPS**: ~1-2 Mpps vs expected 10-20 Mpps

#### Real Hardware Requirements
- **NIC**: Intel X710/i40e or Mellanox CX-5/mlx5
- **Traffic Generator**: pktgen-dpdk or TRex
- **Test Metrics**: PPS, latency (p50/p95/p99), CPU utilization

### CO-RE Compatibility Testing

```bash
# Test on multiple kernels
for kernel in 5.15 5.19 6.1 6.6; do
    # Deploy on kernel $kernel
    sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml
    # Verify all modules load successfully
done
```

---

## 🚀 Deployment and Configuration

### Profile System

#### Basic Profile Structure
```yaml
name: "L2 Learning Switch"
version: "1.0"
description: "Basic L2 switching with VLAN support"

# Module pipeline
ingress:
  - vlan
  - acl
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final

# Global settings
settings:
  vlan_enforcement: true
  default_vlan: 1
  mac_learning: true

# Port configurations
ports:
  - interface: "eth0"
    mode: "access"
    access_vlan: 100
    mac_learning: true

  - interface: "eth1"
    mode: "trunk"
    native_vlan: 1
    allowed_vlans: [100, 200, 300]

# VLAN definitions
vlans:
  - id: 100
    name: "User VLAN"
    tagged_ports: ["eth1"]
    untagged_ports: ["eth0"]

  - id: 200
    name: "Server VLAN"
    tagged_ports: ["eth1", "eth2"]
```

#### Advanced Features (Planned)
```yaml
# Future: Stage overrides
modules:
  - name: "vlan"
    stage: 25  # Override ELF stage 20
    required: true

# Future: Optional modules
optional_modules:
  - name: "mirror"
    enabled: true
    condition: "debug_mode"

# Future: Module configuration
modules:
  - name: "acl"
    config:
      max_rules: 1000
      default_action: "drop"
```

### Quick Start Deployment

```bash
# 1. Build the project
make clean && make

# 2. Configure interfaces (example)
sudo ip link set eth0 up
sudo ip link set eth1 up

# 3. Load with profile
sudo ./build/rswitch_loader \
    --profile etc/profiles/l2.yaml \
    --ifaces eth0,eth1

# 4. Verify operation
sudo ./build/rswitchctl show-pipeline
sudo ./build/rswitchctl show-stats

# 5. Test connectivity
ping -I eth0 192.168.1.2  # Should work if VLAN configured
```

---

## 🔍 Troubleshooting Guide

### Common Issues and Solutions

#### 1. Module Loading Failures
**Symptom**: `Failed to load module X`
**Cause**: eBPF verifier rejection
**Solution**:
```bash
# Enable verbose logging
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --verbose

# Check verifier logs
dmesg | grep bpf
```

#### 2. Map Pinning Issues
**Symptom**: `Map not found` errors
**Cause**: Previous unclean shutdown
**Solution**:
```bash
# Clean up pinned maps
sudo rm -rf /sys/fs/bpf/rs_*

# Restart loader
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml
```

#### 3. Packet Processing Problems
**Symptom**: Packets not forwarded correctly
**Cause**: Pipeline configuration issues
**Solution**:
```bash
# Check pipeline
sudo ./build/rswitchctl show-pipeline

# Inspect maps
sudo bpftool map dump pinned /sys/fs/bpf/rs_ctx_map
sudo bpftool map dump pinned /sys/fs/bpf/rs_port_config_map
```

#### 4. Performance Issues
**Symptom**: Low throughput or high latency
**Cause**: XDP generic mode (Azure VM) or configuration
**Solution**:
- Verify NIC supports XDP native mode
- Check CPU affinity and queue isolation
- Review QoS configuration

### Debug Tools

#### Packet Tracing
```bash
# Enable packet tracing
sudo ./build/rs_packet_trace --interface eth0

# Check event bus
sudo bpftool map dump pinned /sys/fs/bpf/rs_event_bus
```

#### Map Inspection
```bash
# List all rSwitch maps
sudo bpftool map list | grep rs_

# Dump specific map
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table
```

#### Program Inspection
```bash
# List loaded programs
sudo bpftool prog list | grep rswitch

# Show program details
sudo bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher
```

---

## 📚 Key References

### Primary Documentation
- **[Migration Guide](Migration_Guide.md)**: Complete deployment and development guide
- **[Module Developer Guide](Module_Developer_Guide.md)**: Module development tutorial
- **[CO-RE Guide](archive/CO-RE_Guide.md)**: CO-RE implementation details
- **[Development Roadmap](archive/DEVELOPMENT_ROADMAP.md)**: Complete development plan

### Status and Planning
- **[Module Status Report](archive/Module_Status_Report.md)**: Current implementation status
- **[Outstanding Tasks](archive/Outstanding_Tasks_and_Recommendations.md)**: Current work items
- **[Phase 5 Readiness](archive/Phase5_Readiness_Assessment.md)**: Project status assessment
- **[Remaining Modules Roadmap](archive/REMAINING_MODULES_ROADMAP.md)**: Detailed module plans

### Technical References
- **[eBPF Best Practices](archive/EBPF_BEST_PRACTICES.md)**: Programming guidelines
- **[Module Quick Reference](archive/MODULES_QUICK_REFERENCE.md)**: Module specifications
- **[Development Log](archive/Development_Log_Summary.md)**: Implementation history

### External Resources
- [Linux XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)

---

## 🎯 Next Steps

### Immediate Actions (This Week)
1. **Complete Route Module**: Implement IPv4 LPM routing
2. **Integration Testing**: Test ACL + Mirror + VLAN integration
3. **Documentation Updates**: Update guides with latest changes

### Short Term (Q1 2025)
1. **QoS Module**: Traffic classification and marking
2. **Stateful ACL**: Connection tracking implementation
3. **Profile Enhancements**: Advanced YAML support

### Long Term (Q2-Q4 2025)
1. **Enterprise Features**: STP, LACP, LLDP
2. **Performance Benchmarking**: Real hardware testing
3. **Production Hardening**: Stability and monitoring improvements

---

*This guide consolidates information from multiple archived documents. For the most current implementation details, refer to the source code and active documentation in the main `docs/` directory.*

**Last Updated**: November 18, 2025  
**Contributors**: rSwitch Development Team</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/Development_Guide.md