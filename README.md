# rSwitch 🔄

[![License: LGPL-2.1 OR BSD-2-Clause](https://img.shields.io/badge/License-LGPL--2.1%20OR%20BSD--2--Clause-blue)](https://opensource.org/licenses/LGPL-2.1)
[![Kernel](https://img.shields.io/badge/Kernel-5.8+-brightgreen)](https://www.kernel.org/)

**A production-grade, modular XDP switch with CO-RE compatibility and advanced QoS capabilities**

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
- **Security**: Multi-level ACL with connection tracking and stateful filtering
- **QoS**: Traffic classification, DSCP/PCP marking, and priority queuing
- **Monitoring**: Comprehensive telemetry and packet tracing capabilities

### 🔧 Technical Highlights
- **Zero-Copy Data Paths**: AF_XDP integration for high-throughput scenarios
- **Event-Driven Architecture**: Structured event bus for observability
- **Hot-Reload**: Runtime module updates without service interruption
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
                     libxdp-dev libbpf-dev linux-headers-$(uname -r)

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
     --profile etc/profiles/l2.yaml \
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

rSwitch follows a **modular pipeline architecture** with clear separation between data plane and control plane:

### Data Plane Components

#### XDP Pipeline
```
Packet → Dispatcher → VLAN → ACL → Route → L2Learn → LastCall → Egress
```

#### Key Modules
- **dispatcher**: Ingress packet classification and routing
- **vlan**: 802.1Q VLAN processing with trunk/access/hybrid modes
- **acl**: Multi-level access control with stateful filtering
- **route**: IPv4 LPM routing with ARP table management
- **l2learn**: MAC address learning and aging
- **qos**: Traffic classification and marking
- **mirror**: SPAN port mirroring for network analysis

#### VOQd Scheduler
User-space QoS scheduler with three operational modes:
- **BYPASS**: Pure XDP fast-path (maximum performance)
- **SHADOW**: Observation mode for testing (zero impact)
- **ACTIVE**: Full QoS processing with AF_XDP redirection

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
- **Libraries**: libbpf, libxdp, clang/LLVM
- **Permissions**: Root access for XDP program loading

## 💡 Usage

### Basic Operation

#### Start with L2 Profile
```bash
sudo ./build/rswitch_loader \
     --profile etc/profiles/l2.yaml \
     --ifaces eth0,eth1,eth2
```

#### Enable QoS with VOQd
```bash
sudo ./build/rswitch_loader \
     --profile etc/profiles/l3-qos-voqd-test.yaml \
     --ifaces eth0,eth1,eth2,eth3 \
     --verbose
```

#### Firewall Configuration
```bash
sudo ./build/rswitch_loader \
     --profile etc/profiles/firewall.yaml \
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

#### QoS Control
```bash
# Show QoS statistics
sudo ./build/rsqosctl stats

# Monitor VOQd status
sudo ./tools/qos_monitor.sh
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
```

### Available Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `l2.yaml` | Basic L2 switching | Simple bridging |
| `l3.yaml` | L3 routing + ACL | Basic routing |
| `firewall.yaml` | Security-focused | Access control |
| `qos-voqd-test.yaml` | QoS with VOQd | Performance testing |
| `vlan-isolation.yaml` | VLAN isolation | Multi-tenant |

### Advanced Configuration

#### Custom Module Parameters
```yaml
# Planned feature - module-specific configuration
modules:
  - name: "acl"
    config:
      max_rules: 1000
      default_action: "drop"
```

#### Optional Modules
```yaml
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

### 📖 Getting Started
- **[Quick Start](docs/Quick_Start.md)** - Minimal steps to build and run
- **[How To Use](docs/How_To_Use.md)** - Practical usage examples and commands
- **[Design Philosophy](docs/Design_Philosophy.md)** - High-level architecture and principles

### 🛠️ Development Guides
- **[Module Developer Guide](docs/Module_Developer_Guide.md)** - Complete guide for authoring modules
- **[Development Guide](docs/Development_Guide.md)** - Consolidated development roadmap and best practices
- **[Migration Guide](docs/Migration_Guide.md)** - Comprehensive deployment and development guide

### ⚙️ Configuration & Scenarios
- **[Scenario Profiles](docs/Scenario_Profiles.md)** - Common YAML profiles and best practices
- **[VOQd Auto Start](docs/VOQd_Auto_Start.md)** - VOQd configuration and deployment
- **[Documentation Index](docs/Documentation_Index.md)** - Complete documentation overview

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

## 🤝 Contributing

We welcome contributions! Please see our development documentation for details on:

### Development Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following our [Module Developer Guide](docs/Module_Developer_Guide.md)
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

This project is licensed under the **LGPL-2.1 OR BSD-2-Clause** License - see the [LICENSE](LICENSE) file for details.

Individual components may have different licenses:
- BPF programs: GPL-2.0
- User-space utilities: GPL-2.0
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
