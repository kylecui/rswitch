# Configuration Reference

This document is the definitive reference for rSwitch YAML profile configuration. For usage-oriented guidance, see [Scenario Profiles](../usage/Scenario_Profiles.md).

## Profile File Format

Profiles are YAML files located in `etc/profiles/`. They define the complete runtime configuration for an rSwitch instance.

```yaml
# Required
name: "Profile Name"
version: "1.0"

# Optional
description: "Human-readable description"

# Module selection (required)
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1
  - egress_module_2

# Global settings (optional)
settings:
  key: value

# Port configuration (optional)
ports:
  - interface: "ens34"
    # ...

# VLAN definitions (optional)
vlans:
  - vlan_id: 100
    # ...

# VOQd configuration (optional)
voqd_config:
  enabled: true
  # ...
```

## Module Selection

### Ingress Modules

List module names under `ingress:`. Only listed modules are loaded. Execution order is determined by stage numbers embedded in the BPF ELF metadata, **not** by YAML list order.

```yaml
ingress:
  - vlan         # stage 20 — VLAN processing
  - acl          # stage 30 — access control
  - route        # stage 50 — L3 routing
  - mirror       # stage 70 — port mirroring
  - l2learn      # stage 80 — MAC learning
  - afxdp_redirect  # stage 85 — AF_XDP QoS redirect
  - lastcall     # stage 90 — final forwarding (always include)
```

### Egress Modules

```yaml
egress:
  - egress_qos    # stage 170 — QoS enforcement
  - egress_vlan   # stage 180 — VLAN tag insertion/removal
  - egress_final  # stage 190 — final egress (always include)
```

### Rules

- `lastcall` must be the last ingress module.
- `egress_final` must be the last egress module.
- Module names must match the `name` parameter in `RS_DECLARE_MODULE()`.
- Currently, only simple module name lists are supported. Module sub-fields (stage overrides, optional modules, per-module config) are planned but not yet implemented.

## Settings Section

Global behavior settings applied at load time.

```yaml
settings:
  mac_learning: true          # Enable MAC address learning
  mac_aging_time: 300         # MAC entry aging time (seconds)
  vlan_enforcement: true      # Enforce VLAN membership rules
  default_vlan: 1             # Default VLAN for untagged traffic
  unknown_unicast_flood: true # Flood unknown unicast packets
  broadcast_flood: true       # Flood broadcast packets
  stats_enabled: true         # Enable per-port statistics collection
  ringbuf_enabled: true       # Enable event ringbuf for observability
  debug: false                # Enable debug-level BPF logging
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mac_learning` | bool | `true` | Global MAC learning toggle |
| `mac_aging_time` | int | `300` | Seconds before learned MAC entries expire |
| `vlan_enforcement` | bool | `true` | Drop packets violating VLAN membership |
| `default_vlan` | int | `1` | VLAN assigned to untagged traffic |
| `unknown_unicast_flood` | bool | `true` | Flood frames with unknown destination MAC |
| `broadcast_flood` | bool | `true` | Flood broadcast frames to all ports |
| `stats_enabled` | bool | `true` | Collect per-port RX/TX/drop statistics |
| `ringbuf_enabled` | bool | `true` | Enable the `rs_event_bus` ring buffer |
| `debug` | bool | `false` | Enable verbose BPF debug output |

## Port Defaults Section

Profile-wide port defaults applied to **all** interfaces passed via `--ifaces`. Per-port `ports:` entries override these defaults.

```yaml
port_defaults:
  vlan_mode: trunk
  allowed_vlans: [1]
  native_vlan: 1
  mac_learning: true
  default_priority: 1
```

| Key | Type | Description |
|-----|------|-------------|
| `vlan_mode` | string | Default VLAN mode for all ports (`off`, `access`, `trunk`, `hybrid`) |
| `allowed_vlans` | int[] | Default allowed VLAN list |
| `native_vlan` | int | Default native VLAN for trunk mode |
| `mac_learning` | bool | Default MAC learning toggle |
| `default_priority` | int | Default QoS priority 0–7 |

When `port_defaults` is present, the loader calls `configure_ports()` which applies these settings to every interface. Any interface also listed in `ports:` uses the per-port values instead.

## Ports Section

Per-interface configuration.

```yaml
ports:
  - interface: "ens34"
    enabled: true
    vlan_mode: trunk
    pvid: 1
    native_vlan: 1
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0

  - interface: "ens35"
    enabled: true
    vlan_mode: access
    pvid: 100
    mac_learning: true
    default_priority: 0
```

| Key | Type | Description |
|-----|------|-------------|
| `interface` | string | Interface name (e.g., `ens34`) |
| `enabled` | bool | Whether this port is active |
| `vlan_mode` | string | `off`, `access`, `trunk`, or `hybrid` |
| `pvid` | int | Port VLAN ID (used in access mode) |
| `native_vlan` | int | Native VLAN (used in trunk mode for untagged frames) |
| `allowed_vlans` | int[] | List of allowed VLAN IDs (trunk/hybrid modes) |
| `mac_learning` | bool | Per-port override for MAC learning |
| `default_priority` | int | Default QoS priority 0–7 (7 = highest) |

### VLAN Modes

| Mode | Value | Behavior |
|------|-------|----------|
| `off` | 0 | No VLAN processing on this port |
| `access` | 1 | Untagged traffic only; assigned to `pvid` |
| `trunk` | 2 | Tagged traffic; `native_vlan` for untagged frames |
| `hybrid` | 3 | Mix of tagged and untagged VLANs |

## VLANs Section

Define VLAN membership across ports.

```yaml
vlans:
  - vlan_id: 100
    name: "Management"
    tagged_ports: ["ens34", "ens36"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "Servers"
    tagged_ports: ["ens34"]
    untagged_ports: []
```

| Key | Type | Description |
|-----|------|-------------|
| `vlan_id` | int | VLAN identifier (1–4094) |
| `name` | string | Human-readable VLAN name |
| `tagged_ports` | string[] | Interfaces that send/receive tagged frames for this VLAN |
| `untagged_ports` | string[] | Interfaces that send/receive untagged frames for this VLAN |

## VOQd Configuration Section

Configures the VOQd user-space QoS scheduler. See [VOQd Setup](VOQd_Setup.md) for deployment details.

```yaml
voqd_config:
  # Basic
  enabled: true
  mode: active           # bypass | shadow | active
  num_ports: 4
  prio_mask: 0x0C        # Which priorities to intercept (bitmask)

  # AF_XDP
  enable_afxdp: true
  zero_copy: false       # Requires NIC driver support
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  busy_poll: false

  # Scheduler
  enable_scheduler: true
  cpu_affinity: 2        # Pin VOQd to specific CPU core

  # Software queues (for NICs without hardware queues)
  software_queues:
    enabled: false
    queue_depth: 1024
    num_priorities: 8
```

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Auto-start VOQd with loader |
| `mode` | string | `bypass` (fast-path only), `shadow` (observe), `active` (full QoS) |
| `num_ports` | int | Number of ports VOQd manages |
| `prio_mask` | hex/int | Bitmask of priorities to intercept |
| `enable_afxdp` | bool | Enable AF_XDP data plane |
| `zero_copy` | bool | Zero-copy AF_XDP (requires NIC support) |
| `rx_ring_size` | int | AF_XDP RX ring size |
| `tx_ring_size` | int | AF_XDP TX ring size |
| `frame_size` | int | UMEM frame size in bytes |
| `batch_size` | int | Packet batch size per poll |
| `poll_timeout_ms` | int | Poll timeout in milliseconds |
| `busy_poll` | bool | Enable busy polling (lower latency, higher CPU) |
| `enable_scheduler` | bool | Enable DRR/WFQ scheduler |
| `cpu_affinity` | int | CPU core to pin VOQd threads |
| `software_queues.enabled` | bool | Enable software queue emulation |
| `software_queues.queue_depth` | int | Depth of each software queue |
| `software_queues.num_priorities` | int | Number of priority levels |

## Complete Example

```yaml
name: "Production L3 Router"
version: "1.0"
description: "L3 routing with VLAN, ACL, and QoS"

ingress:
  - vlan
  - acl
  - route
  - l2learn
  - afxdp_redirect
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final

settings:
  mac_learning: true
  mac_aging_time: 300
  vlan_enforcement: true
  default_vlan: 1
  stats_enabled: true

port_defaults:
  vlan_mode: trunk
  allowed_vlans: [1, 100, 200]
  native_vlan: 1
  mac_learning: true
  default_priority: 0

ports:
  - interface: "ens35"
    enabled: true
    vlan_mode: access
    pvid: 100
    mac_learning: true

  - interface: "ens36"
    enabled: true
    vlan_mode: access
    pvid: 200

vlans:
  - vlan_id: 100
    name: "Users"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "Servers"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens36"]

voqd_config:
  enabled: true
  mode: active
  num_ports: 3
  prio_mask: 0x0C
  enable_afxdp: true
  zero_copy: false
  rx_ring_size: 2048
  tx_ring_size: 2048
  batch_size: 256
  enable_scheduler: true
  cpu_affinity: 2
```

## Future Configuration Features (Planned)

The following features are designed but not yet implemented:

- **Stage overrides**: Override ELF-defined stage numbers from YAML
- **Optional modules**: Conditional loading based on build flags or runtime conditions
- **Module sub-fields**: Per-module configuration parameters (e.g., ACL max rules)
- **Profile inheritance**: `inherits: base-profile.yaml` for configuration reuse
- **Template system**: Parameterized profiles with variable substitution

## See Also

- [Scenario Profiles](../usage/Scenario_Profiles.md) — usage-oriented profile guide
- [VOQd Setup](VOQd_Setup.md) — VOQd deployment
- [NIC Configuration](NIC_Configuration.md) — NIC-specific setup
- [Installation](Installation.md) — build from source
