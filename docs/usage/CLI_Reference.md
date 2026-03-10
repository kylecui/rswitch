# CLI Reference

rSwitch provides several command-line tools for runtime management and monitoring. All tools are built to `build/` and require root privileges.

## rswitchctl

Main control utility for pipeline management and monitoring.

### Pipeline

```bash
# Show active pipeline (loaded modules, stage order)
sudo ./build/rswitchctl show-pipeline

# Show per-port and per-module statistics
sudo ./build/rswitchctl show-stats
sudo ./build/rswitchctl stats [interface]
```

### MAC Table

```bash
# Display learned MAC addresses
sudo ./build/rswitchctl mac-table

# Add a static MAC entry
sudo ./build/rswitchctl mac-add <mac_address> <vlan_id> <interface>

# Delete a MAC entry
sudo ./build/rswitchctl mac-del <mac_address> <vlan_id>
```

### Events

```bash
# Show events from the event bus
sudo ./build/rswitchctl show-events
```

## rsvlanctl

VLAN configuration utility.

```bash
# Show all VLAN configuration
sudo ./build/rsvlanctl show

# Add a VLAN
sudo ./build/rsvlanctl add <vlan_id> [name]

# Delete a VLAN
sudo ./build/rsvlanctl del <vlan_id>

# Add a port to a VLAN
sudo ./build/rsvlanctl add-port <vlan_id> <interface> [tagged|untagged]

# Remove a port from a VLAN
sudo ./build/rsvlanctl del-port <vlan_id> <interface>
```

## rsaclctl

Access control list management utility.

```bash
# Show all ACL rules
sudo ./build/rsaclctl show

# Add an ACL rule
sudo ./build/rsaclctl add <priority> <match_expression> <action>

# Delete an ACL rule by priority
sudo ./build/rsaclctl del <priority>
```

### Match Expression Examples

```bash
# Block traffic from a subnet
sudo ./build/rsaclctl add 10 "src=10.0.0.0/8" drop

# Allow specific destination port
sudo ./build/rsaclctl add 20 "dst_port=80" permit

# Block specific source IP
sudo ./build/rsaclctl add 5 "src=192.168.1.100" drop
```

## rsqosctl

QoS configuration and monitoring utility.

```bash
# Show QoS statistics
sudo ./build/rsqosctl stats

# Show queue status
sudo ./build/rsqosctl queues

# Set port priority
sudo ./build/rsqosctl set-prio <interface> <priority>
```

## rsvoqctl

VOQd scheduler control utility.

```bash
# Show VOQd status
sudo ./build/rsvoqctl status

# Show VOQd statistics
sudo ./build/rsvoqctl stats
```

## rswitch_loader

The main loader binary. Not typically used as a "tool" but is the entry point for running rSwitch.

```bash
sudo ./build/rswitch_loader [options]
```

| Option | Description |
|--------|-------------|
| `--profile <path>` | Path to YAML profile file |
| `--ifaces <if1,if2,...>` | Comma-separated list of interfaces |
| `--verbose` | Enable verbose logging |
| `--debug` | Enable debug-level logging |
| `--xdp-mode <native\|generic>` | XDP attach mode (default: native) |
| `--detach` | Detach XDP programs from interfaces and exit |

## rswitch-voqd

The VOQd user-space scheduler. Usually started automatically by the loader when `voqd_config.enabled: true` in the profile.

```bash
sudo ./build/rswitch-voqd [options]
```

| Option | Description |
|--------|-------------|
| `-i <interfaces>` | Comma-separated interface list |
| `-m <mode>` | VOQd mode: `bypass`, `shadow`, or `active` |
| `-p <num_ports>` | Number of ports |
| `-P <prio_mask>` | Priority mask (hex) |
| `-q` | Enable software queues |
| `-Q <depth>` | Software queue depth |
| `-s` | Enable scheduler |
| `-S <interval>` | Stats reporting interval (seconds) |

## bpftool Commands

Standard `bpftool` commands useful for rSwitch inspection:

```bash
# List loaded BPF programs
sudo bpftool prog list | grep rswitch

# List BPF maps
sudo bpftool map list | grep rs_

# Dump a specific pinned map
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table
sudo bpftool map dump pinned /sys/fs/bpf/rs_port_config_map
sudo bpftool map dump pinned /sys/fs/bpf/rs_stats_map
sudo bpftool map dump pinned /sys/fs/bpf/rs_ctx_map

# Inspect program instructions
sudo bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher

# Check VOQd state map
sudo bpftool map dump name voqd_state_map
```

## Helper Scripts

Located in `scripts/`:

| Script | Description |
|--------|-------------|
| `rswitch_start.sh` | Start loader with map readiness checks and VOQd |
| `rswitch_diag.sh` | Quick diagnostics (programs, maps, interfaces) |
| `voqd_check.sh` | Validate VOQd readiness and state |
| `unpin_maps.sh` | Remove all pinned rSwitch maps |
| `hot-reload.sh` | Hot-reload a BPF module without full restart |
| `setup_nic_queues.sh` | Configure NIC IRQ affinity and queue isolation |

Located in `tools/`:

| Script | Description |
|--------|-------------|
| `tools/qos_verify.sh` | Quick QoS verification |
| `tools/qos_monitor.sh` | Real-time QoS monitoring |
| `tools/scripts/all/disable_vlan_offload.sh` | Disable HW VLAN offload on interfaces |
| `tools/scripts/all/promisc_switch.sh` | Enable promiscuous mode on interfaces |

## See Also

- [How to Use](How_To_Use.md) — usage workflows
- [Troubleshooting](Troubleshooting.md) — common issues
- [VOQd Setup](../deployment/VOQd_Setup.md) — VOQd deployment guide
