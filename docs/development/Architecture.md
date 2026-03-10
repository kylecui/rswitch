# Architecture Overview

This document describes the rSwitch architecture — a reconfigurable network switch built on XDP/eBPF. Understanding this architecture is essential for developing modules, extending the platform, or contributing to the core.

---

## Design Philosophy

rSwitch replaces fixed ASIC pipelines with a software-defined, profile-driven packet processing pipeline. Six principles guide the design:

| Principle | Mechanism |
|-----------|-----------|
| **Modularity** | Stage-based pipeline; modules are independent BPF programs |
| **Reconfigurability** | YAML profiles control which modules load and in what order |
| **CO-RE Portability** | BPF modules use CO-RE patterns (`vmlinux.h`, libbpf) for cross-kernel compatibility |
| **Safety** | BPF verifier compliance via bounds checks, offset masks (`& 0x3F`) |
| **Performance** | AF_XDP + VOQd for zero-copy paths and queue-based scheduling |
| **Observability** | Per-module pinned maps and unified event bus for operator visibility |

> When source code and documentation conflict, the C source under `rswitch/` is authoritative.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Profile YAML    │───>│  rswitch_loader  │───>│   VOQd (QoS)     │      │
│  │  l3-qos.yaml     │    │  (orchestrator)  │    │  AF_XDP sockets  │      │
│  └──────────────────┘    └────────┬─────────┘    └──────────────────┘      │
│                                   │                                        │
│            ┌──────────────────────┼──────────────────────┐                 │
│            │      BPF Maps (pinned in /sys/fs/bpf)       │                 │
│            │  rs_progs, rs_ctx_map, rs_prog_chain, ...   │                 │
│            └──────────────────────┼──────────────────────┘                 │
│                                   │                                        │
│  ┌──────────────────────────────────────────────────────────┐              │
│  │  CLI Tools: rswitchctl, rsvlanctl, rsaclctl, rsqosctl   │              │
│  └──────────────────────────────────────────────────────────┘              │
│                                                                            │
├────────────────────────────────────┼───────────────────────────────────────┤
│                              KERNEL SPACE                                  │
├────────────────────────────────────┼───────────────────────────────────────┤
│                                    ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        XDP INGRESS PIPELINE                           │ │
│  │  ┌──────────┐  ┌──────┐  ┌─────┐  ┌───────┐  ┌────────┐ ┌────────┐  │ │
│  │  │dispatcher│─>│ vlan │─>│ acl │─>│ route │─>│l2learn │─>│lastcall│  │ │
│  │  │ (entry)  │  │st=20 │  │st=30│  │ st=50 │  │ st=80  │ │ st=90  │  │ │
│  │  └──────────┘  └──────┘  └─────┘  └───────┘  └────────┘ └────────┘  │ │
│  │       │            │         │         │          │           │       │ │
│  │       └────────────┴─────────┴─────────┴──────────┴───────────┘       │ │
│  │                     (tail-call chain via rs_progs)                     │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                    │                                       │
│                                    ▼ XDP_REDIRECT                          │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        XDP EGRESS PIPELINE                            │ │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────────┐                      │ │
│  │  │  egress  │──>│egress_qos│──>│ egress_final │                      │ │
│  │  │ (devmap) │   │ st=170   │   │   st=190     │                      │ │
│  │  └──────────┘   └──────────┘   └──────────────┘                      │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## The Three Pillars of Reconfigurability

| Pillar | Mechanism | Benefit |
|--------|-----------|---------|
| **Module Self-Registration** | `RS_DECLARE_MODULE()` macro embeds metadata in ELF `.rodata.mod` section | Loader discovers modules automatically — no hardcoded lists |
| **Profile-Driven Loading** | YAML files specify module selection and port configuration | Operators control the pipeline without touching code |
| **Dynamic Pipeline Construction** | Tail-call `rs_progs` array built at runtime | Pipeline composition happens at load time, not compile time |

---

## Core Components

### 1. Dispatcher (`dispatcher.bpf.o`)

The XDP entry point attached to each network interface. Responsibilities:

- Initialize per-CPU context (`rs_ctx`)
- Parse Ethernet headers
- Perform initial packet classification
- Tail-call the first module in the ingress pipeline

### 2. Egress Handler (`egress.bpf.o`)

Attached as a devmap callback. When a packet is redirected via `bpf_redirect_map()`, the egress handler:

- Receives the packet on the target interface
- Initiates the egress tail-call chain (slots 255, 254, ...)

### 3. Module Pipeline

Modules execute in stage-number order via BPF tail-calls:

- **Ingress** (stages 10-99): `dispatcher → vlan(20) → acl(30) → route(50) → l2learn(80) → lastcall(90)`
- **Egress** (stages 100-199): `egress(devmap) → egress_qos(170) → egress_vlan(180) → egress_final(190)`

Each module:
1. Calls `RS_GET_CTX()` to get the shared per-CPU context
2. Performs its processing
3. Calls `RS_TAIL_CALL_NEXT()` to invoke the next module

### 4. VOQd Scheduler (`rswitch-voqd`)

User-space QoS scheduler using AF_XDP sockets:

| Mode | Value | Behavior |
|------|-------|----------|
| BYPASS | 0 | No QoS — fast path only |
| SHADOW | 1 | Observation mode — monitors traffic without affecting forwarding |
| ACTIVE | 2 | Full QoS — packets pass through priority queues and scheduling |

Features: DRR/WFQ scheduling, zero-copy AF_XDP, configurable priority queues, automatic failover on heartbeat timeout.

### 5. Loader (`rswitch_loader`)

The user-space orchestrator that ties everything together:

```
1. DISCOVERY     — Scan build/bpf/*.bpf.o, read .rodata.mod ELF sections
2. FILTERING     — Match discovered modules against YAML profile
3. SORTING       — Order by stage number (ingress ascending, egress descending)
4. CONSTRUCTION  — Load BPF objects, populate rs_progs array, configure rs_prog_chain
5. ATTACHMENT    — Attach dispatcher to interfaces, configure devmap, apply port config
```

### 6. CLI Tools

| Tool | Purpose |
|------|---------|
| `rswitchctl` | Pipeline status, statistics, MAC table management |
| `rsvlanctl` | VLAN configuration (add/delete VLANs, port membership) |
| `rsaclctl` | ACL rule management (add/delete/show rules) |
| `rsqosctl` | QoS statistics, queue status, priority settings |
| `rsvoqctl` | VOQd mode control and monitoring |

---

## Stage Numbering Convention

### Ingress Pipeline (Stages 10-99)

| Range | Phase | Modules |
|-------|-------|---------|
| 10-19 | Pre-processing | Header validation, normalization |
| 20-29 | VLAN processing | `vlan` (20) |
| 30-39 | Security | `acl` (30) |
| 40-49 | Mirroring | `mirror` (40) |
| 50-69 | Routing / QoS classification | `route` (50) |
| 70-79 | Reserved | — |
| 80-89 | Learning / AF_XDP | `l2learn` (80), `afxdp_redirect` (85) |
| 90-99 | Final forwarding | `lastcall` (90) — **always last** |

### Egress Pipeline (Stages 100-199)

| Range | Phase | Modules |
|-------|-------|---------|
| 100-139 | Reserved | — |
| 140-169 | Policy | Rate limiting, egress ACL |
| 170-179 | QoS | `egress_qos` (170) |
| 180-189 | VLAN tagging | `egress_vlan` (180) |
| 190-199 | Final | `egress_final` (190) — **always last** |

### Slot Assignment (Internal)

Stage numbers define logical order. Actual `rs_progs` array slots are assigned dynamically:

- **Ingress**: Slots 0, 1, 2, ... (ascending from 0)
- **Egress**: Slots 255, 254, 253, ... (descending from 255)

This separation ensures ingress and egress modules never collide in the prog_array.

---

## Shared Infrastructure

### Per-CPU Context (`rs_ctx`)

All modules share a per-CPU context for zero-copy, lock-free state propagation:

```c
struct rs_ctx {
    __u32 ifindex;              // Ingress interface
    __u32 timestamp;            // Arrival time
    __u8  parsed, modified;     // State flags
    struct rs_layers layers;    // Parsed L2/L3/L4 offsets and values
    __u16 ingress_vlan, egress_vlan;
    __u8  prio, dscp, ecn, traffic_class;
    __u32 egress_ifindex;       // Target output port
    __u8  action;               // XDP_PASS / XDP_DROP / XDP_REDIRECT
    __u8  mirror;               // Mirror flag
    __u16 mirror_port;
    __u32 error;                // RS_ERROR_* code
    __u32 drop_reason;          // RS_DROP_* reason
    __u32 next_prog_id;         // Next module to tail-call
    __u32 call_depth;           // Recursion guard
};
```

**Design rationale:**
- No locking — each CPU has its own context
- Zero-copy — context stays on the processing CPU through the pipeline
- Cache-friendly — data remains in L1/L2 cache

### Core Maps

| Map | Type | Purpose |
|-----|------|---------|
| `rs_ctx_map` | PERCPU_ARRAY | Per-packet context transfer between modules |
| `rs_progs` | PROG_ARRAY | Tail-call targets (ingress + egress) |
| `rs_prog_chain` | ARRAY | Next-module lookup for egress chaining |
| `rs_port_config_map` | HASH | Per-port configuration (VLAN mode, learning, etc.) |
| `rs_stats_map` | PERCPU_ARRAY | Per-interface packet/byte statistics |
| `rs_event_bus` | RINGBUF (1MB) | Unified event channel to user-space |
| `rs_mac_table` | HASH | MAC address forwarding table |
| `rs_vlan_map` | HASH | VLAN membership configuration |
| `rs_xdp_devmap` | DEVMAP_HASH | Packet redirection targets |

All maps are pinned under `/sys/fs/bpf/rs_*`.

### Event Bus

Modules emit structured events to user-space via a unified ring buffer:

```c
struct my_event {
    __u16 type;     // RS_EVENT_* constant
    __u16 len;
    // event-specific data
};

RS_EMIT_EVENT(&evt, sizeof(evt));
```

Events are best-effort — they may be dropped if the ring buffer is full.

---

## Module Self-Registration

Each module declares itself using the `RS_DECLARE_MODULE()` macro, which creates a `struct rs_module_desc` in the `.rodata.mod` ELF section:

```c
struct rs_module_desc {
    __u32 abi_version;      // ABI compatibility check
    __u32 hook;             // RS_HOOK_XDP_INGRESS or RS_HOOK_XDP_EGRESS
    __u32 stage;            // Execution order (lower = earlier)
    __u32 flags;            // RS_FLAG_* capability bits
    char  name[32];         // Module identifier
    char  description[64];  // Human-readable description
};
```

The loader reads this metadata at load time — no hardcoded module lists, no separate registration step.

---

## Comparison: Traditional vs Reconfigurable

| Aspect | Traditional Switch | rSwitch |
|--------|-------------------|---------|
| **Pipeline** | Fixed in hardware (ASIC/FPGA) | Software-defined, profile-driven |
| **Adding features** | Firmware update or hardware change | Write a BPF module, add to profile |
| **Removing features** | Often impossible | Remove from profile, reload |
| **Customization** | Limited to vendor-exposed options | Custom BPF modules with full packet access |
| **Update impact** | Full restart, traffic loss | Hot-reload individual modules |
| **Debug/trace** | Limited vendor tools | Full observability via event bus, bpftool, CLI |
| **Deployment** | Hardware-specific | Any Linux box with XDP-capable NIC |

---

## Directory Structure

```
rswitch/
├── bpf/
│   ├── include/          # BPF headers (rswitch_bpf.h, vmlinux.h)
│   ├── core/             # Core BPF programs (dispatcher.bpf.c, egress.bpf.c, module_abi.h)
│   └── modules/          # BPF modules (vlan.bpf.c, acl.bpf.c, route.bpf.c, ...)
├── user/
│   ├── loader/           # rswitch_loader (profile parser, module loader)
│   ├── voqd/             # VOQd scheduler (AF_XDP)
│   └── tools/            # CLI tools (rswitchctl, rsvlanctl, rsaclctl, rsqosctl)
├── etc/profiles/         # YAML profile files (18 profiles)
├── scripts/              # Helper scripts (startup, validation)
├── test/                 # Tests
├── docs/                 # Documentation
├── examples/             # Example configurations and demos
├── external/libbpf/      # libbpf submodule
└── build/                # Build outputs (binaries, .bpf.o files)
```

---

## Future Evolution: Network Fabric

The reconfigurable architecture is designed to evolve into a full Network Fabric controller. Planned capabilities include:

- OpenFlow-style flow tables with match/action rules
- Per-flow QoS policies
- Traffic engineering with path selection
- Multi-switch orchestration
- Intent-based networking abstractions

See [Network_Fabric_Design.md](../Network_Fabric_Design.md) for details.

---

## References

- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — How to write BPF modules
- [API_Reference.md](./API_Reference.md) — Full API reference
- [CO-RE_Guide.md](./CO-RE_Guide.md) — Cross-kernel portability
- [Contributing.md](./Contributing.md) — How to contribute
- **Paperwork** (detailed architecture deep-dives):
  - [Module_Auto-Discovery_System.md](../paperwork/Module_Auto-Discovery_System.md)
  - [Tail-Call_Pipeline_Architecture.md](../paperwork/Tail-Call_Pipeline_Architecture.md)
  - [Per-CPU_Context_Management.md](../paperwork/Per-CPU_Context_Management.md)
  - [BPF_Map_Sharing_Patterns.md](../paperwork/BPF_Map_Sharing_Patterns.md)
  - [Event_Bus_Architecture.md](../paperwork/Event_Bus_Architecture.md)
  - [VOQd_State_Machine_Architecture.md](../paperwork/VOQd_State_Machine_Architecture.md)
