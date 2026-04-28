# Installation

Complete guide to building rSwitch from source.

## System Requirements

### Operating System

- Linux with kernel 5.8 or later
- BTF support enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Verified on: Ubuntu 22.04+, Debian 12+

### Hardware

- x86_64 architecture
- At least 2 network interfaces for switching
- Recommended: Intel X710 (i40e) or Mellanox CX-5 (mlx5) for native XDP

### Kernel Verification

```bash
# Check kernel version (5.8+ required)
uname -r

# Check BTF support (required for CO-RE)
ls /sys/kernel/btf/vmlinux

# Check XDP support
grep -i xdp /boot/config-$(uname -r) 2>/dev/null || zcat /proc/config.gz 2>/dev/null | grep -i xdp
```

## Install Dependencies

### Ubuntu / Debian

```bash
# Build essentials
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    clang \
    llvm \
    pkg-config

# BPF libraries
sudo apt install -y \
    libxdp-dev \
    libbpf-dev

# Systemd integration (required for rswitch_loader service management)
sudo apt install -y \
    libsystemd-dev

# OpenSSL (required for mgmt daemon authentication)
sudo apt install -y \
    libssl-dev

# Kernel headers (for vmlinux.h generation)
sudo apt install -y \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r)

# Optional: for NIC configuration
sudo apt install -y ethtool
```

### Fedora / RHEL

```bash
sudo dnf install -y \
    gcc \
    make \
    cmake \
    clang \
    llvm \
    pkg-config \
    libxdp-devel \
    libbpf-devel \
    systemd-devel \
    kernel-devel \
    bpftool \
    ethtool
```

### Verify Tool Versions

```bash
clang --version    # 10+ required
llvm-strip --version
bpftool --version  # 5.8+ required
pkg-config --modversion libbpf  # 0.6+ required
```

## Clone and Build

### Clone the Repository

```bash
git clone --recurse-submodules <repo-url>
cd rSwitch/rswitch
```

If you already cloned without submodules:
```bash
git submodule update --init --recursive
```

The `external/libbpf` submodule provides a vendored libbpf if your system version is too old.

### Build

```bash
cd rswitch/

# Step 1: Generate vmlinux.h (first time only, or after kernel upgrade)
make vmlinux

# Step 2: Build everything
make
```

### Build Output

Binaries are placed in `build/`:

| Binary | Description |
|--------|-------------|
| `rswitch_loader` | Main loader — loads BPF modules, manages pipeline |
| `rswitch-voqd` | VOQd user-space QoS scheduler |
| `rswitchctl` | Pipeline management and monitoring |
| `rsvlanctl` | VLAN configuration |
| `rsaclctl` | ACL management |
| `rsqosctl` | QoS monitoring |

BPF object files are in `build/bpf/`:

| Object | Description |
|--------|-------------|
| `dispatcher.bpf.o` | XDP ingress entry point |
| `egress.bpf.o` | Devmap egress callback |
| `vlan.bpf.o` | VLAN processing module |
| `acl.bpf.o` | ACL module |
| `l2learn.bpf.o` | MAC learning module |
| `lastcall.bpf.o` | Final forwarding module |
| `*.bpf.o` | Other modules |

### Clean Build

```bash
make clean && make
```

## Verify Installation

```bash
# Quick test: load with a simple profile
sudo ./build/rswitch_loader \
    --profile etc/profiles/dumb.yaml \
    --ifaces ens34,ens35

# Check it loaded
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rswitch

# Stop
# Press Ctrl+C in the loader terminal
```

## Cross-Kernel Deployment

Thanks to CO-RE, compiled BPF objects can run on different kernel versions without recompilation:

```bash
# Build on development machine
make vmlinux && make

# Copy binaries to target machine
scp -r build/ target:/opt/rswitch/
scp -r etc/profiles/ target:/opt/rswitch/etc/profiles/

# Run on target (no build tools needed, just libbpf)
ssh target "cd /opt/rswitch && sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --ifaces eth0,eth1"
```

**Target machine requirements**:
- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- libbpf runtime library
- Root access

## Troubleshooting Build Issues

### vmlinux.h Generation Fails

```
bpftool: command not found
```

```bash
sudo apt install linux-tools-$(uname -r)
# Or specify path:
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### Missing BTF

```
/sys/kernel/btf/vmlinux: No such file or directory
```

Your kernel doesn't have BTF enabled. Upgrade to a kernel with `CONFIG_DEBUG_INFO_BTF=y` (standard in most modern distros).

### libbpf Version Too Old

```
undefined reference to 'bpf_object__open_file'
```

Use the vendored libbpf:
```bash
cd external/libbpf/src
make
make install PREFIX=/usr/local
ldconfig
```

### clang Too Old

```
error: unknown argument: '-mcpu=v3'
```

Upgrade clang to version 10 or later:
```bash
sudo apt install clang-14
export CC=clang-14
make
```

## Directory Structure

```
rswitch/
├── bpf/
│   ├── include/         # BPF headers (rswitch_bpf.h, vmlinux.h)
│   ├── core/            # Core BPF programs (dispatcher, egress, module_abi)
│   └── modules/         # BPF modules (vlan, acl, l2learn, etc.)
├── user/
│   ├── loader/          # rswitch_loader source
│   ├── voqd/            # VOQd scheduler source
│   └── tools/           # CLI tools source
├── etc/
│   └── profiles/        # YAML profile files
├── scripts/             # Helper scripts
├── test/                # Tests
├── docs/                # Documentation
├── external/
│   └── libbpf/          # Vendored libbpf (git submodule)
├── build/               # Build output (binaries, BPF objects)
└── Makefile
```

## Next Steps

- [Quick Start](../usage/Quick_Start.md) — get running in 5 minutes
- [NIC Configuration](NIC_Configuration.md) — hardware-specific setup
- [Configuration](Configuration.md) — YAML profile reference
- [Systemd Integration](Systemd_Integration.md) — production service setup
