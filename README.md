# rSwitch 🔄

[![License: LGPL-2.1-or-later](https://img.shields.io/badge/License-LGPL--2.1--or--later-blue)](https://opensource.org/licenses/LGPL-2.1)
[![Kernel](https://img.shields.io/badge/Kernel-5.8+-brightgreen)](https://www.kernel.org/)

**A production-grade, modular XDP switch with CO-RE compatibility and advanced QoS capabilities**

> 📖 **[中文文档 / Chinese Documentation](docs/zh-CN/README.md)**
>
> **First-read docs for physical-machine deployment and follow-up development:**
> - [物理机 Native XDP 部署与运维手册](docs/zh-CN/deployment/Physical_Machine_Native_XDP_Deployment.md)
> - [Native XDP 物理机场景排错复盘](docs/zh-CN/development/Native_XDP_Physical_Debugging_Postmortem.md)

rSwitch is a high-performance, programmable network switch built on XDP (eXpress Data Path) and AF_XDP. It features a modular architecture with CO-RE (Compile Once - Run Everywhere) compatibility, enabling seamless deployment across different kernel versions. The system includes a user-space QoS scheduler (VOQd) for fine-grained traffic control and supports comprehensive network features through its extensible module system.

## ✨ Features

### 🚀 Core Capabilities
- **High Performance**: XDP-native packet processing with zero-copy AF_XDP integration
- **CO-RE Compatible**: Single binary deployment across kernel versions 5.8+
- **Modular Architecture**: Extensible pipeline with 10+ production-ready modules
- **QoS Support**: Advanced traffic classification, marking, and scheduling via VOQd
- **Profile-Driven**: YAML-based configuration for different deployment scenarios

### 🛠️ Network Features
- **Layer 2**: MAC learning, VLAN processing (ACCESS/TRUNK/HYBRID modes)
- **Layer 3**: IPv4 routing with LPM tables and ARP management
- **Security**: Multi-level ACL with stateful filtering `[Planned: connection tracking]`
- **QoS**: Traffic marking and priority queuing `[Planned: ingress traffic classification]`
- **Monitoring**: Comprehensive telemetry and packet tracing capabilities

### 🔧 Technical Highlights
- **Zero-Copy Data Paths**: AF_XDP integration for high-throughput scenarios
- **Event-Driven Architecture**: Structured event bus for observability
- **Hot-Reload**: Runtime module updates — atomic prog_array replacement without XDP detach
- **BPF Verifier Friendly**: Bounds checking and offset masking for reliability
- **Production Ready**: Comprehensive testing and validation framework

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Development](#-development)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

Get rSwitch running in under 5 minutes:

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y build-essential cmake clang llvm pkg-config \
                     libxdp-dev libbpf-dev libsystemd-dev linux-headers-$(uname -r)

# Or install libbpf from source (recommended)
git submodule update --init --recursive
cd external/libbpf && make && sudo make install
```

### Build & Run
```bash
# Build the project
make vmlinux && make

# Quick L2 switching demo
sudo ./build/rswitch_loader \
     --profile etc/profiles/l2-simple-managed.yaml \
     --ifaces ens34,ens35,ens36
```

### Verify Operation
```bash
# Check loaded programs
sudo bpftool prog list | grep rswitch

# Verify maps and statistics
sudo bpftool map show | grep rswitch

# Check VOQd status (if enabled)
ps aux | grep rswitch-voqd
```

## 🏗️ Architecture

rSwitch follows a **dual-pipeline architecture** with separate ingress and egress processing paths, providing comprehensive packet processing from network entry to exit:

### Data Plane Components

#### XDP Pipelines
rSwitch implements **two separate pipelines** for comprehensive packet processing:

**📥 Ingress Pipeline** (Stages 10-99):
```
Packet → Dispatcher → VLAN → ACL → Route → L2Learn → LastCall
```

**📤 Egress Pipeline** (Stages 100-199):
```
Devmap → QoS → Egress VLAN → Egress Final
```

#### Pipeline Design
rSwitch's pipeline architecture enables flexible, modular packet processing:

- **🎯 Stage-Based Execution**: Modules execute in deterministic order using numbered stages (10-99 for ingress, 100-199 for egress)
- **🔗 Tail-Call Slots**: Stages map to BPF program array slots for efficient jumps between modules
- **🔍 Auto-Discovery**: Modules self-register via ELF metadata - no manual registration required
- **📋 Profile-Driven**: YAML profiles specify which modules to load and their execution order
- **🔄 Hot-Reload**: Runtime module updates without service interruption

#### Key Modules
- **dispatcher**: Ingress packet classification and routing
- **vlan**: 802.1Q VLAN processing with trunk/access/hybrid modes
- **acl**: Multi-level access control `[Planned: stateful filtering with connection tracking]`
- **route**: IPv4 LPM routing with ARP table management
- **l2learn**: MAC address learning and aging
- **qos**: Traffic classification and marking
- **mirror**: SPAN port mirroring for network analysis
- **egress_vlan**: Egress VLAN tag manipulation
- **egress_final**: Final egress processing and transmission

#### VOQd Scheduler
User-space QoS scheduler with three operational modes:
- **BYPASS**: Pure XDP fast-path (maximum performance)
- **SHADOW**: Observation mode for testing (zero impact)
- **ACTIVE**: Full QoS processing with AF_XDP redirection

#### QoS Architecture Notes

**Hardware Queue Limitations**: Traditional QoS implementation requires AF_XDP sockets bound to hardware queues. For NICs without multiple queues, rSwitch now provides two solutions:

**1. Software Queue Simulation** (`-q` / `--sw-queues`)
- Creates virtual output queues in user space using shared memory buffers
- Eliminates dependency on hardware queue count
- Supports any NIC with basic AF_XDP support
- Configurable queue depth per port/priority combination
- Maintains full QoS scheduling capabilities

**2. Queue-Independent Shadow Mode**
- Pure metadata observation without packet redirection
- Works with any NIC configuration
- No AF_XDP socket requirements
- Ideal for monitoring and statistics collection

**Usage Examples**:
```bash
# Software queues for queue-constrained NICs
sudo ./build/rswitch-voqd -m active -q -Q 2048 -i eth0

# Shadow mode without hardware queue dependency  
sudo ./build/rswitch-voqd -m shadow -q -i eth0

# Combined: software queues + shadow mode
sudo ./build/rswitch-voqd -m shadow -q -Q 1024
```

**Benefits**:
- **Broader Hardware Support**: Works with inexpensive NICs lacking multiple queues
- **Flexible Deployment**: Choose between full QoS processing or metadata-only observation
- **Performance Scaling**: Software queues provide consistent performance regardless of hardware
- **Operational Flexibility**: Mix and match modes based on use case requirements

### Control Plane
- **YAML Profiles**: Declarative configuration for different scenarios
- **Hot-Reload**: Runtime module updates without downtime
- **CLI Tools**: Comprehensive management and monitoring utilities
- **Telemetry**: Structured event bus and statistics collection

## 📦 Installation

### From Source
```bash
# Clone repository
git clone https://github.com/kylecui/rswitch.git
cd rswitch

# Initialize submodules
git submodule update --init --recursive

# Build dependencies
cd external/libbpf && make && sudo make install

# Build rSwitch
make vmlinux && make
```

### System Requirements
- **Kernel**: 5.8+ (for AF_XDP and CO-RE support)
- **NIC**: XDP-native drivers (i40e, mlx5) or generic mode
- **Libraries**: libbpf, libxdp, libsystemd, clang/LLVM
- **Permissions**: Root access for XDP program loading

## 💡 Usage

### Basic Operation

#### Start with L2 Profile
```bash
sudo ./build/rswitch_loader \
     --profile etc/profiles/l2-simple-managed.yaml \
     --ifaces eth0,eth1,eth2
```

#### Full L3 Routing
```bash
sudo ./build/rswitch_loader \
     --profile etc/profiles/l3-full.yaml \
     --ifaces eth0,eth1,eth2,eth3 \
     --verbose
```

#### All Modules (including QoS)
```bash
sudo ./build/rswitch_loader \
     --profile etc/profiles/all.yaml \
     --ifaces eth0,eth1
```

### Management Commands

#### Monitor Pipeline
```bash
# Show loaded modules and stages
sudo ./build/rswitchctl show-pipeline

# Display interface statistics
sudo ./build/rswitchctl show-stats
```

#### VOQd QoS Enhancements
```bash
# Enable software queue simulation for NICs without hardware queues
sudo ./build/rswitch-voqd -m active -q -Q 2048 -i eth0,eth1

# Queue-independent shadow mode (no AF_XDP dependency)
sudo ./build/rswitch-voqd -m shadow -q -i eth0

# Monitor software queue statistics
sudo ./build/rswitch-voqd -m active -q -S 5
```

#### VLAN Management
```bash
# Configure VLAN settings
sudo ./build/rsvlanctl show
sudo ./build/rsvlanctl add-port eth1 trunk 100,200
```

### Troubleshooting

#### Common Issues
```bash
# Check pinned maps
ls /sys/fs/bpf/ | grep rs_

# Inspect program logs
sudo bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher

# Verify VOQd health
sudo ./scripts/voqd_check.sh
```

#### Cleanup
```bash
# Stop gracefully
sudo pkill rswitch_loader

# Force cleanup if needed
sudo ./scripts/unpin_maps.sh
```

## ⚙️ Configuration

rSwitch uses YAML profiles for configuration. Profiles define module pipelines and runtime behavior:

### Basic Profile Structure
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

# VOQd configuration (optional)
voqd_config:
  enabled: true
  mode: active
  prio_mask: 0x0C  # HIGH + CRITICAL priorities
  
  # Software queue simulation (for NICs without hardware queues)
  software_queues:
    enabled: true
    queue_depth: 2048  # Per port/priority queue depth
    num_priorities: 8   # Number of priority levels
  
  # AF_XDP configuration
  afxdp_config:
    enabled: true
    zero_copy: false
    frame_size: 2048
```

### Available Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `dumb.yaml` | Simple flooding switch | No learning, minimal pipeline |
| `l2-unmanaged.yaml` | L2 with MAC learning | Unmanaged switch, no VLANs |
| `l2-simple-managed.yaml` | L2 with VLAN + DHCP snooping | Managed switch with management port |
| `l3-full.yaml` | Full L3 routing + ACL | Production routing with VLANs |
| `all.yaml` | All modules enabled | Testing, QoS, full pipeline |

Profiles support `port_defaults` — default VLAN mode, allowed VLANs, and MAC learning settings applied to all ports unless overridden by per-port `ports:` configuration. See [Configuration](docs/deployment/Configuration.md).

### Advanced Configuration

#### Custom Module Parameters
```yaml
# [Planned] — module-specific configuration (not yet implemented)
modules:
  - name: "acl"
    config:
      max_rules: 1000
      default_action: "drop"
```

#### Optional Modules
```yaml
# [Planned] — conditional module loading (not yet implemented)
optional_modules:
  - name: "mirror"
    enabled: true
    condition: "debug_mode"
```

## 🛠️ Development

### Module Development

Create new modules in `bpf/modules/` following the module ABI:

```c
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module declaration (defines stage and capabilities)
RS_DECLARE_MODULE(
    "my_module",                    // Name
    RS_HOOK_XDP_INGRESS,           // Hook point
    35,                           // Execution stage
    RS_FLAG_NEED_L2L3_PARSE,      // Parse requirements
    "My custom module"            // Description
);

SEC("xdp")
int my_module(struct xdp_md *ctx) {
    struct rs_ctx *rs_ctx = RS_GET_CTX();
    if (!rs_ctx) return XDP_DROP;

    // Module logic here
    // ...

    // Continue pipeline
    rs_ctx->next_stage = 40;
    RS_TAIL_CALL_NEXT(ctx, rs_ctx);
    return XDP_DROP;
}
```

### Build & Test

```bash
# Build all modules
make

# Build specific module
make bpf/modules/my_module.o

# Run tests
make test

# Hot-reload during development
sudo ./scripts/hot-reload.sh reload my_module
```

### CO-RE Best Practices

- Use `BPF_CORE_READ()` for kernel structure access
- Include bounds checking with `data_end` validation
- Apply offset masking: `offset & RS_L3_OFFSET_MASK`
- Test across multiple kernel versions (5.8+)

### Event Emission

Emit structured events for observability:

```c
struct rs_event_header evt = {
    .event_type = RS_EVENT_DEBUG,
    .timestamp_ns = bpf_ktime_get_ns(),
    .ifindex = ctx->ifindex,
};
RS_EMIT_EVENT(&evt, sizeof(evt));
```

## 📚 Documentation

> 📖 [Full Documentation Index](docs/Documentation_Index.md) · [中文文档](docs/zh-CN/) · [Changelog](CHANGELOG.md)

### 📘 Usage
- **[Quick Start](docs/usage/Quick_Start.md)** — Build, run, and verify in 5 minutes
- **[How To Use](docs/usage/How_To_Use.md)** — Practical usage examples and workflows
- **[Scenario Profiles](docs/usage/Scenario_Profiles.md)** — All 5 YAML profiles explained
- **[CLI Reference](docs/usage/CLI_Reference.md)** — Complete CLI tool reference
- **[Troubleshooting](docs/usage/Troubleshooting.md)** — Diagnostics and common issues

### 📦 Deployment
- **[Installation](docs/deployment/Installation.md)** — Build from source, dependencies, kernel requirements
- **[Configuration](docs/deployment/Configuration.md)** — YAML profile structure and settings reference
- **[VOQd Setup](docs/deployment/VOQd_Setup.md)** — QoS scheduler modes, AF_XDP, software queues
- **[NIC Configuration](docs/deployment/NIC_Configuration.md)** — NIC-specific setup (i40e, mlx5, hv_netvsc)
- **[Systemd Integration](docs/deployment/Systemd_Integration.md)** — Service units and production deployment

### 🛠️ Development
- **[Architecture](docs/development/Architecture.md)** — Dual-pipeline architecture deep-dive
- **[Module Developer Guide](docs/development/Module_Developer_Guide.md)** — Complete module authoring guide
- **[API Reference](docs/development/API_Reference.md)** — Macros, structs, maps, helpers, flags
- **[ABI Stability Policy](docs/development/ABI_POLICY.md)** — Version semantics, stability tiers, deprecation rules
- **[Map Pinning Convention](docs/development/MAP_PINNING.md)** — BPF map pin path standards
- **[CO-RE Guide](docs/development/CO-RE_Guide.md)** — Cross-kernel portability guide
- **[Contributing](docs/development/Contributing.md)** — Contribution workflow and standards

### 📋 Backlog
- **[Platform](docs/backlog/platform-backlog.md)** · **[API & SDK](docs/backlog/api-backlog.md)** · **[Product](docs/backlog/product-backlog.md)** · **[Ecosystem](docs/backlog/ecosystem-backlog.md)**

### 📁 Project Structure
```
rswitch/
├── bpf/modules/          # BPF program modules (CO-RE)
├── user/                 # User-space components
│   ├── loader/          # Main loader and profile parser
│   ├── voqd/            # User-space QoS scheduler
│   └── tools/           # CLI management utilities
├── etc/profiles/        # YAML configuration profiles
├── docs/                # Comprehensive documentation
├── scripts/             # Helper scripts and utilities
└── test/                # Testing framework and examples
```

## ⚠️ Known Limitations

The following features are documented or referenced but **not yet fully implemented**:

| Feature | Status | Tracking |
|---------|--------|----------|
| Stateful ACL with connection tracking | Planned | [Product Backlog 2.2](docs/backlog/product-backlog.md) |
| Ingress QoS traffic classification module | Planned | [Product Backlog 3.1](docs/backlog/product-backlog.md) |
| QinQ double VLAN tagging | Planned | [Product Backlog 1.1](docs/backlog/product-backlog.md) |
| Robust hot-reload with atomic replacement | ✅ Implemented | [Hot-Reload Documentation](docs/development/Hot_Reload.md) |
| Per-module `config:` in YAML profiles | Planned (v2.1) | [Platform Backlog 1.3](docs/backlog/platform-backlog.md) |
| Conditional `optional_modules:` loading | Planned | [Platform Backlog 1.2](docs/backlog/platform-backlog.md) |

> See the [Backlog](#-backlog) section for the full roadmap.

## 🤝 Contributing

We welcome contributions! Please see our development documentation for details on:

### Development Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following our [Module Developer Guide](docs/development/Module_Developer_Guide.md)
4. Add tests and documentation
5. Submit a pull request

### Code Standards
- **BPF Modules**: Follow CO-RE patterns and verifier-friendly coding
- **C Code**: Use consistent error handling and logging
- **Documentation**: Keep docs synchronized with code changes
- **Testing**: Include unit tests and integration validation

### Reporting Issues
- Use GitHub Issues for bug reports and feature requests
- Include relevant logs, configuration, and reproduction steps
- Check existing issues and documentation first

## 📄 License

This project is licensed under the **LGPL-2.1-or-later** License - see the [LICENSE](LICENSE) file for details.

Individual components may have different licenses:
- BPF programs: GPL-2.0 (required by BPF verifier)
- User-space utilities: LGPL-2.1-or-later
- Documentation: CC-BY-4.0

## 🙏 Acknowledgments

rSwitch builds upon the excellent work of the Linux kernel community and the eBPF ecosystem:

- **Linux Kernel**: XDP and AF_XDP infrastructure
- **libbpf**: CO-RE and BPF program management
- **Cilium**: eBPF programming patterns and best practices
- **XDP Project**: Tutorial and reference implementations

## 📞 Support

- **Documentation**: [docs/Documentation_Index.md](docs/Documentation_Index.md)
- **Issues**: [GitHub Issues](https://github.com/kylecui/rswitch/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kylecui/rswitch/discussions)

---

**rSwitch** - High-performance, programmable networking with eBPF
