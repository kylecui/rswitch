# How to Use rSwitch

This guide covers day-to-day operations: starting, configuring, monitoring, and managing an rSwitch instance.

## Workflow Overview

```
1. Build        →  make vmlinux && make
2. Choose       →  Select a YAML profile
3. Configure    →  (Optional) Set up NIC queues, VLAN offload
4. Start        →  rswitch_loader --profile ... --ifaces ...
5. Validate     →  bpftool / CLI tools
6. Operate      →  Monitor, adjust ACLs/VLANs/QoS at runtime
7. Shutdown     →  Ctrl+C or pkill, then clean up maps
```

## 1. Building

```bash
cd rswitch/

# First time: generate vmlinux.h for CO-RE portability
make vmlinux

# Build everything
make

# Clean rebuild
make clean && make
```

All binaries are output to `build/`.

## 2. Choosing a Profile

Profiles are YAML files in `etc/profiles/` that define which BPF modules to load and how ports, VLANs, and QoS are configured. See [Scenario Profiles](Scenario_Profiles.md) for full details.

```bash
# List available profiles
ls etc/profiles/

# Preview a profile
cat etc/profiles/l2-vlan.yaml
```

## 3. Pre-Launch Configuration (Optional)

### Disable Hardware VLAN Offload

Required if your profile uses VLAN processing — hardware VLAN offload strips tags before XDP sees them.

```bash
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens35 rx-vlan-offload off
# Or use the helper script:
sudo ./tools/scripts/all/disable_vlan_offload.sh ens34 ens35
```

> **Note**: rSwitch loader v1.1+ automatically disables VLAN offload and enables promiscuous mode on attach. Manual setup is only needed for older versions or troubleshooting.

### Set Up NIC Queues

For performance tuning (IRQ affinity, queue isolation):

```bash
sudo scripts/setup_nic_queues.sh ens34 2
```

See [NIC Configuration](../deployment/NIC_Configuration.md) for details.

## 4. Starting rSwitch

### Basic Start

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l2.yaml \
    --ifaces ens34,ens35,ens36
```

### With Verbose Logging

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l3-qos-voqd-test.yaml \
    --ifaces ens34,ens35 \
    --verbose
```

### With Generic XDP (for unsupported NICs)

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l2.yaml \
    --ifaces ens34,ens35 \
    --xdp-mode generic
```

### Using the Start Script

The start script handles map readiness checks and VOQd startup timing:

```bash
sudo scripts/rswitch_start.sh etc/profiles/l3-qos-voqd-test.yaml ens34,ens35
```

## 5. Validating Operation

### Check Loaded Programs

```bash
sudo bpftool prog list | grep rswitch
```

Expected output shows dispatcher + your profile's modules.

### Check Pinned Maps

```bash
sudo bpftool map show | grep rswitch
# Or:
ls /sys/fs/bpf/ | grep rs_
```

Expected maps: `rs_ctx_map`, `rs_progs`, `rs_prog_chain`, `rs_port_config_map`, `rs_stats_map`, `rs_event_bus`, `rs_mac_table`, `rs_vlan_map`, `rs_xdp_devmap`.

### Check VOQd (if QoS profile)

```bash
ps -ef | grep rswitch-voqd
sudo ./build/rsqosctl stats
```

### Pipeline Inspection

```bash
sudo ./build/rswitchctl show-pipeline
sudo ./build/rswitchctl show-stats
```

### Diagnostics Script

```bash
sudo scripts/rswitch_diag.sh
sudo scripts/voqd_check.sh
```

## 6. Runtime Operations

### View MAC Table

```bash
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table
# Or:
sudo ./build/rswitchctl mac-table
```

### Manage VLANs

```bash
sudo ./build/rsvlanctl show
sudo ./build/rsvlanctl add 100 "Management"
sudo ./build/rsvlanctl add-port 100 ens34 tagged
```

### Manage ACLs

```bash
sudo ./build/rsaclctl show
sudo ./build/rsaclctl add 10 "src=10.0.0.0/8" drop
sudo ./build/rsaclctl del 10
```

### QoS Statistics

```bash
sudo ./build/rsqosctl stats
sudo ./build/rsqosctl queues
```

### View Events

```bash
sudo bpftool map dump pinned /sys/fs/bpf/rs_event_bus
```

## 7. Hot-Reload a Module (Development)

After modifying a BPF module source file:

```bash
# Rebuild
make

# Reload the module
sudo scripts/hot-reload.sh reload my_module
```

## 8. Shutdown and Cleanup

### Graceful Shutdown

Press `Ctrl+C` in the loader terminal. The loader will:
1. Send SIGTERM to VOQd (if running)
2. Wait up to 5 seconds for graceful stop
3. Detach XDP programs from all interfaces
4. Clean up BPF maps

### Manual Shutdown

```bash
sudo pkill rswitch_loader
# If VOQd is running separately:
sudo pkill rswitch-voqd
```

### Clean Up Pinned Maps

```bash
sudo ./scripts/unpin_maps.sh
# Or manually:
sudo rm -rf /sys/fs/bpf/rs_*
```

### Detach XDP Programs Only

```bash
sudo ./build/rswitch_loader --detach --profile etc/profiles/l2.yaml
```

## Tips

- **Wait for maps**: After starting, allow 3–5 seconds for map initialization before querying.
- **Check VLAN offload**: If VLAN traffic doesn't work, verify `rx-vlan-offload: off` with `ethtool -k <iface>`.
- **Use native XDP**: Prefer `--xdp-mode native` for production performance. Use `generic` only for unsupported NICs or testing.
- **Profile ordering matters**: Module execution follows stage numbers defined in ELF metadata, not YAML list order.

## See Also

- [Quick Start](Quick_Start.md) — minimal 5-minute setup
- [Scenario Profiles](Scenario_Profiles.md) — profile reference
- [CLI Reference](CLI_Reference.md) — all CLI commands
- [Troubleshooting](Troubleshooting.md) — common issues
