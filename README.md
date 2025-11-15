# rSwitch - Reconfigurable Switch

Production implementation of the modular, programmable XDP-based switch.

## Build Environment Prerequisites
```bash
sudo apt install build-essential cmake llvm clang pkg-config make open-vm-tools libxdp-dev libbpf-dev linux-headers-$(uname -r)
```

## Recent Updates

### ✅ Phase 1 Complete: Multi-Level ACL Architecture (2024-01)

**Problem Solved:** Original ACL used linear loop (`for i=0..64`) limiting scalability and performance

**New Design:** Three-level indexed lookup system
- **Level 1:** 5-tuple exact match (BPF_MAP_TYPE_HASH, O(1))
- **Level 2:** IP prefix match (BPF_MAP_TYPE_LPM_TRIE, O(log N))
- **Level 3:** Default policy (configurable PASS/DROP)

**Performance:** 21x faster than linear iteration, scales to 65k+ rules

**Control Tool:** `rsaclctl` for rule management
```bash
# Block specific connection
sudo rsaclctl add-5t --proto tcp --src 10.1.2.3 --dst 192.168.1.100 --dport 22 --action drop

# Block entire subnet
sudo rsaclctl add-lpm-src --prefix 10.0.0.0/8 --action drop

# Set default and enable
sudo rsaclctl set-default --action pass
sudo rsaclctl enable
```

**Documentation:** See [`docs/ACL_Architecture.md`](docs/ACL_Architecture.md) for complete design details

### ✅ Phase 0 Complete: L3/L4 Parsing Verification

- IPv4 address extraction verified via debug logging
- Protocol detection (ICMP, TCP, UDP) working
- Port extraction from TCP/UDP headers correct
- DSCP parsing from TOS field operational
- All parsed data available in `rs_ctx->layers` for downstream modules

## Directory Structure

```
rswitch/
├── bpf/
│   ├── core/           # Core XDP programs (dispatcher, egress, egress_final)
│   ├── modules/        # Pluggable modules (vlan, ACL, route, l2learn, lastcall)
│   └── include/        # Shared headers (module_abi.h, uapi.h, parsing helpers)
├── user/
│   ├── loader/         # Auto-discovering module loader
│   ├── tools/          # rsaclctl, rsportctl, rsvlanctl, test scripts
│   └── cli/            # rswitchctl CLI/API
├── etc/
│   └── profiles/       # YAML profiles (dumb.yaml, l2.yaml, l3.yaml, firewall.yaml)
├── scripts/            # Build/deployment scripts
├── docs/               # Implementation docs (ACL_Architecture.md, ...)
└── build/              # Build output (generated)
```

## Quick Start

### Prerequisites

```bash
# Ensure libbpf is installed to /usr/local/bpf/
cd ../external/libbpf/src
make install BUILD_STATIC_ONLY=1 PREFIX=/usr/local/bpf
```

### Build

```bash
# First time: generate vmlinux.h for CO-RE
make vmlinux

# Build all modules and loader
make

# Clean rebuild
make clean all
```

### Run

```bash
# Load with profile
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --iface ens34,ens35,ens36

# Check status
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rswitch
```

## Development

### Adding a New Module

1. Create `bpf/modules/mymodule.bpf.c`:
```c
#include "core/module_abi.h"
#include "core/uapi.h"

RS_DECLARE_MODULE("mymodule", RS_HOOK_XDP_INGRESS, 35, RS_FLAG_NEED_L2L3_PARSE);

SEC("xdp")
int mymodule_ingress(struct xdp_md *ctx) {
    // Your logic here
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

2. Rebuild: `make`

3. Add to profile (`etc/profiles/custom.yaml`):
```yaml
name: "custom-switch"
ingress:
  - vlan       # stage 20
  - mymodule   # stage 35
  - lastcall   # stage 90
```

4. Load: `sudo ./build/rswitch_loader --profile etc/profiles/custom.yaml`

### Module Stages (Ordering)

- **10-19**: Pre-processing
- **20-29**: VLAN processing
- **30-39**: Access control / Policy
- **40-59**: Routing / Forwarding logic
- **70-89**: Learning / Observability
- **90-99**: Final decision (lastcall always at 90)

## Architecture

See `../docs/` for comprehensive design documentation:
- `rSwitch_Definition.md` - Core definition and capabilities
- `Reconfigurable_Switch_Overview.md` - Engineering value
- `data_plane_desgin_with_af_XDP.md` - Hybrid XDP+AF_XDP design
- `Milestone1_plan.md` - Implementation roadmap

## Migration from PoC

The `../src/` directory contains the original proof-of-concept. This `rswitch/` directory is the production implementation with:
- ✅ Modular plugin architecture
- ✅ Profile-based configuration
- ✅ Auto-discovering loader
- ✅ Hot-reload support
- ✅ AF_XDP integration ready

## License

SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
