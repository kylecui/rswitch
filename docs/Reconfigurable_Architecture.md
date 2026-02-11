# Reconfigurable Architecture

## Executive Summary

rSwitch implements a **reconfigurable network switch** architecture built on XDP/eBPF. The "reconfigurable" concept means the data plane can be dynamically composed from modular BPF programs at runtime, without kernel recompilation or system restart.

**Key Innovation**: Unlike traditional switches with fixed ASIC pipelines, rSwitch's packet processing pipeline is software-defined and profile-driven—operators can add, remove, or reorder processing stages by editing YAML configuration files.

---

## Core Concepts

### 1. What is "Reconfigurable"?

In traditional network hardware:
- Pipeline stages are fixed in silicon (ASIC/FPGA)
- Adding new features requires hardware replacement or vendor firmware updates
- Configuration is limited to parameters exposed by the fixed pipeline

In rSwitch's reconfigurable architecture:
- **Pipeline stages are software modules** loaded at runtime
- **Features are composable** — mix and match modules for your use case
- **Configuration defines structure** — YAML profiles specify which modules run and in what order
- **Hot-reload capable** — update individual modules without full restart

### 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │  Profile YAML    │───▶│  rswitch_loader  │───▶│   VOQd (QoS)     │       │
│  │  l3-qos.yaml     │    │  (orchestrator)  │    │  AF_XDP sockets  │       │
│  └──────────────────┘    └────────┬─────────┘    └──────────────────┘       │
│                                   │                                          │
│            ┌──────────────────────┼──────────────────────┐                   │
│            │      BPF Maps (pinned in /sys/fs/bpf)       │                   │
│            │  rs_progs, rs_ctx_map, rs_prog_chain, ...   │                   │
│            └──────────────────────┼──────────────────────┘                   │
│                                   │                                          │
├───────────────────────────────────┼──────────────────────────────────────────┤
│                              KERNEL SPACE                                    │
├───────────────────────────────────┼──────────────────────────────────────────┤
│                                   ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                        XDP INGRESS PIPELINE                              ││
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐ ││
│  │  │dispatcher│──▶│  vlan    │──▶│   acl    │──▶│  route   │──▶│lastcall│ ││
│  │  │ (entry)  │   │ stage=20 │   │ stage=30 │   │ stage=50 │   │stage=90│ ││
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └────────┘ ││
│  │       │              │              │              │              │      ││
│  │       └──────────────┴──────────────┴──────────────┴──────────────┘      ││
│  │                         (tail-call chain via rs_progs)                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                   │                                          │
│                                   ▼ XDP_REDIRECT                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                        XDP EGRESS PIPELINE                               ││
│  │  ┌──────────┐   ┌──────────┐   ┌──────────────┐                         ││
│  │  │  egress  │──▶│egress_qos│──▶│ egress_final │                         ││
│  │  │ (devmap) │   │stage=170 │   │  stage=190   │                         ││
│  │  └──────────┘   └──────────┘   └──────────────┘                         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3. The Three Pillars of Reconfigurability

| Pillar | Mechanism | Benefit |
|--------|-----------|---------|
| **Module Self-Registration** | `RS_DECLARE_MODULE()` macro embeds metadata in ELF | Modules are self-describing; loader discovers capabilities automatically |
| **Profile-Driven Loading** | YAML files specify module selection | Operators control pipeline without code changes |
| **Dynamic Pipeline Construction** | Tail-call prog_array built at runtime | Pipeline composition happens at load time, not compile time |

---

## How It Works

### Step 1: Module Self-Registration

Each BPF module declares its identity using the `RS_DECLARE_MODULE()` macro:

```c
// bpf/modules/vlan.bpf.c
RS_DECLARE_MODULE(
    "vlan",                         // Name (for profile matching)
    RS_HOOK_XDP_INGRESS,           // Hook point (ingress or egress)
    20,                             // Stage number (determines execution order)
    RS_FLAG_NEED_L2L3_PARSE |      // Capability flags
    RS_FLAG_MODIFIES_PACKET,
    "VLAN tag processing"          // Description
);
```

This macro creates a `struct rs_module_desc` in a special `.rodata.mod` ELF section:

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

### Step 2: Profile Definition

Operators create YAML profiles that specify which modules to load:

```yaml
# etc/profiles/l3-qos.yaml
name: "L3 Router with QoS"
version: "1.0"

# Modules listed here will be loaded (others skipped)
ingress:
  - vlan
  - acl
  - route
  - l2learn
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final

# Port configuration
ports:
  - interface: eth0
    vlan_mode: trunk
    pvid: 1
    allowed_vlans: [1, 100, 200]

# QoS settings (enables VOQd)
voqd:
  enabled: true
  queues: 8
```

### Step 3: Loader Discovery and Pipeline Construction

The `rswitch_loader` orchestrates the entire process:

```
1. DISCOVERY
   └─ Scan build/bpf/*.bpf.o files
   └─ For each file:
       └─ Read .rodata.mod section
       └─ Extract rs_module_desc metadata
       └─ Store module if ABI version matches

2. PROFILE FILTERING
   └─ Load YAML profile
   └─ Filter modules: keep only those in profile's ingress/egress lists
   └─ Validate no duplicate stages

3. SORTING
   └─ Separate into ingress (stages 10-99) and egress (stages 100-199)
   └─ Sort each list by stage number (ascending)

4. PIPELINE CONSTRUCTION
   └─ Load dispatcher.bpf.o (entry point, always loaded)
   └─ Load egress.bpf.o (devmap callback, always loaded)
   └─ For each module in sorted order:
       └─ Load BPF object
       └─ Get program FD
       └─ Assign to slot in rs_progs array
       └─ Configure rs_prog_chain for next-module lookup

5. ATTACHMENT
   └─ Attach dispatcher to each interface (XDP)
   └─ Configure devmap entries for egress callbacks
   └─ Apply port configuration from profile
```

### Step 4: Runtime Execution

When a packet arrives:

```c
// 1. Dispatcher receives packet, initializes context
struct rs_ctx *ctx = RS_GET_CTX();
ctx->ifindex = xdp->ingress_ifindex;
ctx->next_prog_id = 0;  // Start at first module

// 2. First tail-call to slot 0 (will be first ingress module)
bpf_tail_call(xdp, &rs_progs, 1);

// 3. Each module processes, then calls next
// In vlan.bpf.c:
RS_TAIL_CALL_NEXT(xdp, ctx);  // Increments next_prog_id, tail-calls

// 4. lastcall makes forwarding decision
ctx->egress_ifindex = lookup_fdb(dst_mac);
return bpf_redirect_map(&rs_xdp_devmap, ctx->egress_ifindex, 0);

// 5. Egress hook runs egress pipeline (similar tail-call chain)
```

---

## Stage Numbering Convention

Stages define execution order. rSwitch reserves specific ranges for different processing phases:

### Ingress Pipeline (Stages 10-99)

| Range | Phase | Example Modules |
|-------|-------|-----------------|
| 10-19 | Pre-processing | Header validation, normalization |
| 20-29 | VLAN processing | `vlan` (stage 20) |
| 30-39 | Security | `acl` (stage 30) |
| 40-49 | Routing decision | `route` (stage 50) |
| 50-69 | QoS classification | Classification, marking |
| 70-79 | Mirroring | `mirror` (stage 70) |
| 80-89 | Learning | `l2learn` (stage 80), `arp_learn` |
| 90-99 | Final forwarding | `lastcall` (stage 90) - **always last** |

### Egress Pipeline (Stages 100-199)

| Range | Phase | Example Modules |
|-------|-------|-----------------|
| 100-119 | Pre-egress | Initial egress setup |
| 120-139 | VLAN tagging | `egress_vlan` |
| 140-169 | Policy | Rate limiting, ACL enforcement |
| 170-179 | QoS | `egress_qos` (stage 170) |
| 180-189 | Telemetry | Mirroring, counters |
| 190-199 | Final | `egress_final` (stage 190) - **always last** |

### Slot Assignment (Internal)

Stages define **logical order**, but actual `rs_progs` array slots are assigned dynamically:

- **Ingress**: Slots 0, 1, 2, ... (ascending from 0)
- **Egress**: Slots 255, 254, 253, ... (descending from 255)

This separation ensures ingress and egress modules never collide in the prog_array.

---

## Creating a New Module

### 1. Create the BPF Source File

```c
// bpf/modules/my_module.bpf.c
#include "rswitch_bpf.h"

// Self-registration (REQUIRED)
RS_DECLARE_MODULE(
    "my_module",           // Name for profile matching
    RS_HOOK_XDP_INGRESS,   // or RS_HOOK_XDP_EGRESS
    45,                    // Stage number (pick unused slot in range)
    RS_FLAG_NEED_L2L3_PARSE,
    "My custom processing module"
);

SEC("xdp")
int my_module_main(struct xdp_md *xdp)
{
    // Get shared context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_PASS;
    
    // Your processing logic here
    // Access parsed headers: ctx->layers.saddr, ctx->layers.dport, etc.
    
    // Continue to next module
    RS_TAIL_CALL_NEXT(xdp, ctx);
    
    // Fallback if tail-call fails
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### 2. Add to Build System

```makefile
# Add to Makefile or meson.build
BPF_MODULES += my_module.bpf.o
```

### 3. Add to Profile

```yaml
# etc/profiles/my-profile.yaml
ingress:
  - vlan
  - my_module    # Add your module name
  - lastcall
```

### 4. Rebuild and Reload

```bash
make
sudo ./rswitch_loader -p etc/profiles/my-profile.yaml -i eth0
```

---

## Profile Examples

### Minimal L2 Switch

```yaml
name: "Basic L2 Switch"
version: "1.0"

ingress:
  - vlan
  - l2learn
  - lastcall

egress:
  - egress_final
```

### L3 Router with ACL

```yaml
name: "Secure L3 Router"
version: "1.0"

ingress:
  - vlan
  - acl          # Add ACL for packet filtering
  - route        # L3 routing decisions
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

### Full QoS Pipeline

```yaml
name: "QoS-Enabled Switch"
version: "1.0"

ingress:
  - vlan
  - acl
  - route
  - afxdp_redirect  # Redirect to user-space QoS scheduler
  - l2learn
  - lastcall

egress:
  - egress_qos      # Apply QoS policies
  - egress_vlan
  - egress_final

voqd:
  enabled: true
  queues: 8
  scheduling: strict_priority
```

---

## Shared Infrastructure

### Per-CPU Context (`rs_ctx`)

All modules share a per-CPU context structure to pass information through the pipeline:

```c
struct rs_ctx {
    // Input metadata
    __u32 ifindex;              // Ingress interface
    __u32 timestamp;            // Arrival time
    
    // Parsed headers (set by early modules)
    struct rs_layers layers;    // L2/L3/L4 offsets and values
    
    // VLAN state
    __u16 ingress_vlan;
    __u16 egress_vlan;
    
    // QoS state
    __u8  prio;                 // Priority (0-7)
    __u8  dscp;
    
    // Forwarding decision
    __u32 egress_ifindex;       // Target output port
    __u8  action;               // XDP_PASS, XDP_DROP, XDP_REDIRECT
    
    // Pipeline state
    __u32 next_prog_id;         // Next module to call
    __u32 call_depth;           // Recursion guard
};
```

### Core Maps

| Map | Type | Purpose |
|-----|------|---------|
| `rs_ctx_map` | PERCPU_ARRAY | Per-packet context transfer |
| `rs_progs` | PROG_ARRAY | Tail-call targets |
| `rs_prog_chain` | ARRAY | Next-module lookup for egress |
| `rs_port_config_map` | HASH | Per-port configuration |
| `rs_event_bus` | RINGBUF | Events to user-space (1MB) |
| `rs_xdp_devmap` | DEVMAP_HASH | Packet redirection targets |

### Event Bus

Modules emit events to user-space via a unified ring buffer:

```c
struct my_event {
    __u16 type;     // RS_EVENT_* constant
    __u16 len;
    // event-specific data
};

struct my_event evt = { .type = RS_EVENT_MAC_LEARNED, ... };
RS_EMIT_EVENT(&evt, sizeof(evt));
```

---

## Comparison: Traditional vs Reconfigurable

| Aspect | Traditional Switch | rSwitch Reconfigurable |
|--------|-------------------|------------------------|
| **Pipeline** | Fixed in hardware | Software-defined, profile-driven |
| **Adding features** | Firmware update or hardware change | Add module + update profile |
| **Removing features** | Often impossible | Remove from profile, reload |
| **Customization** | Limited to vendor options | Write custom BPF modules |
| **Update impact** | Full restart, traffic loss | Hot-reload individual modules |
| **Debug/trace** | Limited visibility | Full observability via events |

---

## Design Philosophy

### Why Tail-Calls?

- **Zero function call overhead** — tail-calls replace the current stack frame
- **Modularity** — each module is a separate BPF program with isolated verification
- **Hot-reload** — update `rs_progs[stage]` to replace a module atomically
- **Depth limit** — 33 tail-calls max (Linux kernel limit), sufficient for most pipelines

### Why Per-CPU Context?

- **No locking** — each CPU has its own context, no contention
- **Zero-copy** — context travels through pipeline without copying
- **Cache-friendly** — data stays in L1/L2 cache on the processing CPU

### Why Profile-Driven?

- **Separation of concerns** — code vs configuration
- **Operator-friendly** — no C knowledge needed to configure
- **Reproducible** — same profile = same behavior
- **Version-controlled** — profiles live in git alongside code

---

## Future Evolution: Network Fabric

The reconfigurable architecture is designed to evolve into a full **Network Fabric** controller. See [Network_Fabric_Design.md](./Network_Fabric_Design.md) for the roadmap including:

- OpenFlow-style flow tables with match/action rules
- Per-flow QoS policies
- Traffic engineering with path selection
- Multi-switch orchestration
- Intent-based networking abstractions

---

## References

- [Module_Auto-Discovery_System.md](./paperwork/Module_Auto-Discovery_System.md) — ELF metadata extraction details
- [Tail-Call_Pipeline_Architecture.md](./paperwork/Tail-Call_Pipeline_Architecture.md) — Tail-call mechanics
- [BPF_Map_Sharing_Patterns.md](./paperwork/BPF_Map_Sharing_Patterns.md) — Map ownership and sharing
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — Step-by-step module creation
