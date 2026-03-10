# Quick Start

Get rSwitch running in under 5 minutes.

## Prerequisites

- Linux kernel 5.8+ with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- Root / sudo access
- Build tools: `build-essential`, `cmake`, `clang`, `llvm`, `pkg-config`
- Libraries: `libxdp-dev`, `libbpf-dev`, `linux-headers-$(uname -r)`
- At least 2 network interfaces for switching

> For detailed installation steps, see [Installation](../deployment/Installation.md).

## Build

```bash
cd rswitch/
make vmlinux   # Generate vmlinux.h for CO-RE (first time only)
make
```

Binaries are placed in `build/`:
- `rswitch_loader` — main loader
- `rswitch-voqd` — QoS scheduler
- `rswitchctl`, `rsvlanctl`, `rsaclctl`, `rsqosctl` — CLI tools

## Choose a Profile

Profiles define which modules run and in what order. They live in `etc/profiles/`:

```bash
ls etc/profiles/
```

Common starting points:

| Profile | Description |
|---------|-------------|
| `dumb.yaml` | Simple flooding switch (no learning) |
| `l2.yaml` | L2 learning switch with VLAN support |
| `l3.yaml` | L3 routing with basic ACL |
| `firewall.yaml` | Security-focused with ordered ACLs |

## Run

```bash
# Set your profile and interfaces
PROFILE=etc/profiles/l2.yaml
INTERFACES=ens34,ens35,ens36

# Start rSwitch
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces $INTERFACES
```

> **Tip**: If you see "No such file" errors when reading maps, wait 3–5 seconds for initialization, or use `scripts/rswitch_start.sh` which handles timing automatically.

## Verify

```bash
# Check loaded BPF programs
sudo bpftool prog list | grep rswitch

# Check pinned maps
sudo bpftool map show | grep rswitch
ls /sys/fs/bpf/ | grep rs_

# If using a QoS profile, check VOQd
ps -ef | grep rswitch-voqd
```

## Cleanup

```bash
# Stop rSwitch (Ctrl+C in the loader terminal, or):
sudo pkill rswitch_loader

# Remove pinned maps
sudo rm -rf /sys/fs/bpf/rs_*
# Or use the unpin script:
sudo ./scripts/unpin_maps.sh
```

## Loader Flags

| Flag | Description |
|------|-------------|
| `--profile <path>` | YAML profile file |
| `--ifaces <if1,if2>` | Comma-separated interface list |
| `--verbose` | Verbose logging |
| `--debug` | Debug-level logging |
| `--xdp-mode <mode>` | `native` or `generic` (default: native) |
| `--detach` | Detach XDP programs and exit |

## Next Steps

- [How to Use](How_To_Use.md) — comprehensive usage guide
- [Scenario Profiles](Scenario_Profiles.md) — all available profiles explained
- [CLI Reference](CLI_Reference.md) — CLI tool commands
- [Troubleshooting](Troubleshooting.md) — common issues and solutions
