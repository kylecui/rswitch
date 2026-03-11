# Intent Translation Engine

## What It Is

`scripts/intent_engine.py` is a developer/operator utility that converts high-level, declarative network intents into concrete rSwitch profile YAML and module-specific configuration files.

Intent files describe **what** behavior you want (segmentation, security, QoS, routing, monitoring). The engine resolves **how** to realize that behavior by selecting modules and building a ready-to-load profile.

## Input Intent Format

The engine expects this structure:

```yaml
intent:
  name: "campus-edge-switch"
  description: "Campus edge switch with VLAN segmentation and security"

  segments:
    - name: "student"
      vlan: 100
      ports: [1, 2, 3, 4]

  security:
    acl: true
    source_guard: true
    dhcp_snooping: true

  qos:
    enabled: true
    default_class: "best-effort"

  monitoring:
    sflow: false
    mirror: false
    telemetry: true

  routing:
    enabled: true

  high_availability:
    stp: true
    lacp: false
```

## How To Run

Basic generation:

```bash
python3 scripts/intent_engine.py examples/intents/campus_edge.yaml -o output/
```

Validation only:

```bash
python3 scripts/intent_engine.py examples/intents/campus_edge.yaml --validate
```

Dry-run (no files written):

```bash
python3 scripts/intent_engine.py examples/intents/campus_edge.yaml -o output/ --dry-run
```

## Generated Artifacts

For an intent named `campus-edge-switch`, the engine writes:

- `output/campus-edge-switch.yaml` (main rSwitch profile)
- `output/module_configs/campus-edge-switch_vlan.yaml` (if VLAN segments exist)
- `output/module_configs/campus-edge-switch_acl.yaml` (if ACL is enabled)
- `output/module_configs/campus-edge-switch_qos.yaml` (if QoS is enabled)

## Supported Intent Fields

- `intent.name` (required): profile name and output filename prefix
- `intent.description` (optional): profile description
- `intent.segments[]`: segmentation model (segment name, VLAN ID, port list)
- `intent.security.acl`: enable ACL module
- `intent.security.source_guard`: enable source guard module
- `intent.security.dhcp_snooping`: enable DHCP snooping module
- `intent.qos.enabled`: enable ingress QoS classify + rate limiting modules
- `intent.qos.default_class`: default class name (best-effort, bulk, video, voice, control, critical)
- `intent.monitoring.sflow`: enable sFlow module
- `intent.monitoring.mirror`: enable mirror module
- `intent.monitoring.telemetry`: add telemetry config block
- `intent.routing.enabled`: enable route + conntrack + nat modules
- `intent.high_availability.stp`: enable STP module
- `intent.high_availability.lacp`: enable LACP module
- `intent.tunnels.enabled`: enable tunnel module
- `intent.tunnels.type`: tunnel type (default `vxlan`)
- `intent.ecmp.enabled`: enable ECMP flow-table module
- `intent.ecmp.max_paths`: maximum ECMP next-hop paths (default `16`)

## Intent To Module Mapping

| Intent Field | Ingress Modules Added | Egress Modules Added |
|---|---|---|
| Always | `dispatcher`, `l2learn`, `lastcall` | `egress`, `egress_final` |
| `segments` | `vlan` | `egress_vlan` |
| `security.acl` | `acl` | - |
| `security.source_guard` | `source_guard` | - |
| `security.dhcp_snooping` | `dhcp_snoop` | - |
| `qos.enabled` | `qos_classify`, `rate_limiter` | - |
| `monitoring.sflow` | `sflow` | - |
| `monitoring.mirror` | `mirror` | - |
| `routing.enabled` | `route`, `conntrack`, `nat` | - |
| `high_availability.stp` | `stp` | - |
| `high_availability.lacp` | `lacp` | - |
| `tunnels.enabled` | `tunnel` | - |
| `ecmp.enabled` | `flow_table` | - |

## Validation Rules

The engine validates intent data before generation:

- Required `intent.name`
- Segment VLAN range (`1..4094`)
- Port values are integer and positive
- No duplicate segment names
- No duplicate VLAN IDs across segments
- No overlapping port assignments across segments
- Boolean fields validated for security, QoS, monitoring, routing, and HA sections

Warnings are shown for potentially risky combinations (for example: source guard without DHCP snooping).

## Example Intents

- `examples/intents/campus_edge.yaml`
- `examples/intents/datacenter_tor.yaml`
- `examples/intents/simple_bridge.yaml`

## Notes

- Generated profile format uses `name`, `description`, `modules`, `egress_modules`, and `config`.
- Stage ordering is resolved internally from hardcoded module stage maps.
- The tool is offline and standalone; it does not modify running dataplane state.
