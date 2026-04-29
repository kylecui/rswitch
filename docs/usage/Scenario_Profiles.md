# Scenario Profiles

Profiles are YAML configuration files that define the rSwitch pipeline: which BPF modules load, how ports are configured, and what settings apply. They live in `etc/profiles/`.

## Profile Structure

A profile contains these sections:

```yaml
name: "Profile Name"
version: "1.0"
description: "What this profile does"

# Which modules to load (names must match RS_DECLARE_MODULE names)
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1

# Global settings
settings:
  mac_learning: true
  vlan_enforcement: true
  # ...

# Per-port configuration
ports:
  - interface: "ens34"
    vlan_mode: access
    pvid: 100
    # ...

# VLAN definitions
vlans:
  - vlan_id: 100
    name: "Users"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens35"]

# VOQd scheduler (optional)
voqd_config:
  enabled: true
  mode: active
  # ...
```

> **Important**: Module execution order is determined by stage numbers embedded in the BPF ELF metadata (`RS_DECLARE_MODULE`), not by the order in the YAML list. The YAML list only selects which modules to load.

## Available Modules

### Ingress Pipeline (stages 10–99)

| Module | Stage | Description |
|--------|-------|-------------|
| `vlan` | 20 | VLAN tag processing (access/trunk/hybrid) |
| `acl` | 30 | L3/L4 access control lists |
| `route` | 50 | IPv4 LPM routing |
| `mirror` | 70 | SPAN port mirroring |
| `l2learn` | 80 | MAC address learning and aging |
| `afxdp_redirect` | 85 | AF_XDP redirect for QoS/VOQd |
| `lastcall` | 90 | Final forwarding decision (always last) |

### Egress Pipeline (stages 100–199)

| Module | Stage | Description |
|--------|-------|-------------|
| `egress_qos` | 170 | QoS classification and marking |
| `egress_vlan` | 180 | Egress VLAN tag insertion/removal |
| `egress_final` | 190 | Final egress processing (always last) |

## Included Profiles

rSwitch ships 5 curated profiles, organized from simplest to most complete. Legacy profiles are archived in `etc/profiles/archive/`.

| Profile | Ingress Modules | Egress Modules | Port Defaults | Management | Use Case |
|---------|----------------|----------------|---------------|------------|----------|
| `dumb.yaml` | lastcall | egress_final | — | No | Simple flooding switch, no learning |
| `l2-unmanaged.yaml` | l2learn, lastcall | egress_final | mac_learning | No | Unmanaged L2 switch |
| `l2-simple-managed.yaml` | vlan, dhcp_snoop, l2learn, lastcall | egress_vlan, egress_final | trunk, vlan[1] | Yes | Managed L2 switch with VLAN + DHCP snooping |
| `l3-full.yaml` | vlan, acl, dhcp_snoop, route, l2learn, lastcall | egress_vlan, egress_final | trunk, vlan[1] | Yes | Full L3 routing with ACL |
| `all.yaml` | vlan, acl, dhcp_snoop, route, mirror, l2learn, killswitch, arp_learn, afxdp_redirect, lastcall | egress_qos, egress_vlan, egress_final | trunk, vlan[1] | Yes | All modules — testing, QoS, full pipeline |

### Port Defaults

Profiles can define `port_defaults:` — default settings applied to **all** ports passed via `--ifaces` unless overridden by per-port `ports:` configuration:

```yaml
port_defaults:
  vlan_mode: trunk
  allowed_vlans: [1]
  native_vlan: 1
  mac_learning: true
  default_priority: 1
```

This eliminates repetitive per-port configuration when all ports share the same baseline. See [Configuration](../deployment/Configuration.md) for the full reference.

## Settings Reference

The `settings` section supports these keys:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mac_learning` | bool | `true` | Enable MAC address learning globally |
| `mac_aging_time` | int | `300` | MAC entry aging time in seconds |
| `vlan_enforcement` | bool | `true` | Enforce VLAN membership rules |
| `default_vlan` | int | `1` | Default VLAN for untagged traffic |
| `unknown_unicast_flood` | bool | `true` | Flood unknown unicast packets |
| `broadcast_flood` | bool | `true` | Flood broadcast packets |
| `stats_enabled` | bool | `true` | Enable per-port statistics |
| `ringbuf_enabled` | bool | `true` | Enable event ringbuf |
| `debug` | bool | `false` | Enable debug-level logging |

## Port Configuration

The `ports` section configures each physical interface:

```yaml
ports:
  - interface: "ens34"
    enabled: true
    vlan_mode: trunk           # off | access | trunk | hybrid
    pvid: 1                    # Port VLAN ID (access mode)
    native_vlan: 1             # Native VLAN (trunk mode)
    allowed_vlans: [1, 100, 200]  # Allowed VLANs (trunk/hybrid)
    mac_learning: true         # Per-port MAC learning override
    default_priority: 0        # Default QoS priority (0–7)
```

### VLAN Modes

| Mode | Behavior |
|------|----------|
| `off` | No VLAN processing |
| `access` | Untagged traffic only, assigned to `pvid` |
| `trunk` | Tagged traffic, `native_vlan` for untagged frames |
| `hybrid` | Mix of tagged and untagged VLANs |

## Writing a Custom Profile

1. Copy an existing profile as a starting point:
   ```bash
   cp etc/profiles/l2-simple-managed.yaml etc/profiles/my-custom.yaml
   ```

2. Edit module lists, settings, and port configuration.

3. Load and test:
   ```bash
   sudo ./build/rswitch_loader --profile etc/profiles/my-custom.yaml --ifaces ens34,ens35
   ```

### Best Practices

- Always include `lastcall` as the last ingress module.
- Always include `egress_final` as the last egress module.
- Order modules logically: VLAN → ACL → Route → Learning → Forwarding.
- Use specific `allowed_vlans` lists rather than allowing all VLANs.
- Minimize heavy per-packet modules on fast paths.
- For QoS with VOQd, set appropriate CPU affinity and verify AF_XDP socket creation.

## VOQd Configuration

Profiles that use QoS include a `voqd_config` section. See [VOQd Setup](../deployment/VOQd_Setup.md) for full details.

```yaml
voqd_config:
  enabled: true
  mode: active              # bypass | shadow | active
  num_ports: 4
  prio_mask: 0x0C           # Which priorities to intercept
  enable_afxdp: true
  zero_copy: false
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  cpu_affinity: 2
  enable_scheduler: true
  software_queues:
    enabled: false
    queue_depth: 1024
    num_priorities: 8
```

## See Also

- [Quick Start](Quick_Start.md) — get running in 5 minutes
- [Configuration](../deployment/Configuration.md) — YAML configuration reference
- [CLI Reference](CLI_Reference.md) — runtime management commands
