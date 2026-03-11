# rSwitch Platform Architecture

**A Reconfigurable Network Device Platform Built on XDP/eBPF**

Version 1.0 — March 2026

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [System Architecture](#2-system-architecture)
3. [Data Plane Architecture](#3-data-plane-architecture)
4. [Control Plane Architecture](#4-control-plane-architecture)
5. [Profile System](#5-profile-system)
6. [Module Lifecycle](#6-module-lifecycle)
7. [Monitoring & Observability Stack](#7-monitoring--observability-stack)
8. [Production Hardening](#8-production-hardening)
9. [Module Classification](#9-module-classification)
10. [Ecosystem & Tooling](#10-ecosystem--tooling)
11. [Comparison: Traditional vs rSwitch](#11-comparison-traditional-vs-rswitch)
12. [Directory Structure](#12-directory-structure)
13. [References](#13-references)

---

## 1. Design Philosophy

rSwitch is a software-defined, reconfigurable network device platform. It replaces fixed-function ASIC pipelines with a profile-driven BPF module pipeline running on commodity Linux hardware with XDP-capable NICs.

### Core Principles

| Principle | Mechanism | Why It Matters |
|-----------|-----------|----------------|
| **Reconfigurability** | YAML profiles select modules at load time; hot-reload swaps modules at runtime | Operators compose custom network functions without code changes |
| **Modularity** | Each network function is an independent BPF program with self-describing metadata | Modules are developed, tested, packaged, and deployed independently |
| **Performance** | XDP processes packets at the driver level; AF_XDP enables zero-copy user-space paths | Wire-speed processing on commodity hardware |
| **CO-RE Portability** | BPF CO-RE (Compile Once – Run Everywhere) via `vmlinux.h` and libbpf | Modules run across kernel versions without recompilation |
| **Safety** | BPF verifier enforces memory safety; offset masks constrain pointer arithmetic | No kernel crashes from module bugs |
| **Observability** | Unified event bus, per-module statistics, Prometheus metrics, sFlow sampling | Full visibility into every stage of the pipeline |

### The Reconfigurability Promise

Traditional network devices bake functionality into silicon. Adding a feature requires a firmware update or hardware swap. Removing an unused feature is often impossible.

rSwitch inverts this model:

```
Traditional Switch                    rSwitch
┌─────────────────────┐               ┌─────────────────────┐
│ Fixed ASIC Pipeline  │               │ Profile: campus.yaml │
│ L2 → ACL → L3 → QoS│               │   modules:           │
│ (all always active)  │               │     - vlan            │
│                      │               │     - acl             │
│ Can't remove L3      │               │     - route           │
│ if you only need L2  │               │   # No QoS? Don't    │
│                      │               │   # load it.          │
└─────────────────────┘               └─────────────────────┘
```

**Users** select capabilities through profiles. **Developers** extend the platform by writing BPF modules against a stable SDK. The platform handles discovery, loading, chaining, and lifecycle management.

---

## 2. System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                                    USER SPACE                                      │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  ┌─────────────────────────────── MANAGEMENT ────────────────────────────────────┐ │
│  │                                                                               │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │ │
│  │  │  Profile YAML │  │ Intent Engine│  │ Policy Verify│  │  Module Registry │  │ │
│  │  │  (profiles/)  │  │  (Python)    │  │  (Python)    │  │  (local index)   │  │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────────┘  └──────────────────┘  │ │
│  │         │                  │                                                   │ │
│  │         ▼                  ▼                                                   │ │
│  │  ┌──────────────────────────────────────────────────────────────────────────┐  │ │
│  │  │                        rswitch_loader (Orchestrator)                     │  │ │
│  │  │  Discovery → ABI Check → Dependency Sort → Load → Pipeline Build → Attach│ │ │
│  │  └────────────────────────────────┬─────────────────────────────────────────┘  │ │
│  │                                   │                                            │ │
│  └───────────────────────────────────┼────────────────────────────────────────────┘ │
│                                      │                                              │
│  ┌──────────────── DAEMONS ──────────┼─────────────────────────────────────────┐   │
│  │                                   │                                         │   │
│  │  ┌──────────┐ ┌────────┐ ┌───────┐│┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │  VOQd    │ │  STPd  │ │ LLDPd │││ Watchdog │ │Lifecycle │ │  sFlow   │  │   │
│  │  │(AF_XDP)  │ │(STP/   │ │(LLDP  │││(health   │ │(graceful │ │(export)  │  │   │
│  │  │QoS sched │ │ RSTP)  │ │ agent)│││ monitor) │ │ shutdown)│ │          │  │   │
│  │  └──────────┘ └────────┘ └───────┘│└──────────┘ └──────────┘ └──────────┘  │   │
│  │                                   │                                         │   │
│  │  ┌──────────┐ ┌──────────────┐    │ ┌───────────┐ ┌───────────────────┐     │   │
│  │  │  LACPd   │ │  Controller  │    │ │   Agent   │ │  SNMP Sub-Agent   │     │   │
│  │  │(link agg)│ │  (central)   │    │ │ (remote)  │ │  (pass_persist)   │     │   │
│  │  └──────────┘ └──────────────┘    │ └───────────┘ └───────────────────┘     │   │
│  └───────────────────────────────────┼─────────────────────────────────────────┘   │
│                                      │                                              │
│  ┌──────────────── CLI TOOLS ────────┼─────────────────────────────────────────┐   │
│  │                                   │                                         │   │
│  │  rswitchctl   rsportctl   rsvlanctl   rsaclctl   rsroutectl   rsqosctl     │   │
│  │  rsflowctl    rsnatctl    rsvoqctl    rstunnelctl                          │   │
│  │                                                                             │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                              │
│          ┌───────────────────────────┼───────────────────────────────┐              │
│          │      BPF Maps (pinned at /sys/fs/bpf/rs_*)               │              │
│          │  rs_progs  rs_ctx_map  rs_prog_chain  rs_event_bus       │              │
│          │  rs_port_config_map  rs_stats_map  rs_module_stats_map   │              │
│          │  rs_mac_table  rs_vlan_map  rs_module_config_map  ...    │              │
│          └───────────────────────────┼───────────────────────────────┘              │
│                                      │                                              │
├──────────────────────────────────────┼──────────────────────────────────────────────┤
│                                 KERNEL SPACE                                        │
├──────────────────────────────────────┼──────────────────────────────────────────────┤
│                                      ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────┐ │
│  │                          XDP INGRESS PIPELINE                                  │ │
│  │                                                                                │ │
│  │  ┌──────────┐ ┌────┐ ┌────┐ ┌──────┐ ┌────┐ ┌─────┐ ┌────────┐ ┌──────────┐  │ │
│  │  │dispatcher│→│stp │→│vlan│→│source│→│acl │→│route│→│l2learn │→│ lastcall │  │ │
│  │  │ (entry)  │ │ 12 │ │ 20 │ │guard │ │ 30 │ │ 50  │ │   80   │ │    90    │  │ │
│  │  └──────────┘ └────┘ └────┘ │  18  │ └────┘ └─────┘ └────────┘ └──────────┘  │ │
│  │                              └──────┘                                          │ │
│  │  + lacp(11) lldp(11) tunnel(15) dhcp_snoop(19) qos_classify(25)               │ │
│  │    rate_limiter(28) conntrack(32) mirror(45) nat(55) flow_table(60) sflow(85)  │ │
│  │                                                                                │ │
│  │       (all connected via tail-call chain through rs_progs array)               │ │
│  └────────────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                              │
│                                      ▼ XDP_REDIRECT via devmap                      │
│  ┌────────────────────────────────────────────────────────────────────────────────┐ │
│  │                          XDP EGRESS PIPELINE                                   │ │
│  │                                                                                │ │
│  │  ┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │ │
│  │  │  egress  │───→│  egress_qos  │───→│ egress_vlan  │───→│  egress_final   │  │ │
│  │  │ (devmap) │    │   st=170     │    │   st=180     │    │    st=190       │  │ │
│  │  └──────────┘    └──────────────┘    └──────────────┘    └──────────────────┘  │ │
│  │                                                                                │ │
│  │       (chained via rs_prog_chain map, slots descending from 255)               │ │
│  └────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Architectural Layers

| Layer | Components | Responsibility |
|-------|------------|----------------|
| **Management** | Loader, profiles, intent engine, policy verification, registry | Configuration and orchestration |
| **Daemons** | VOQd, STPd, LLDPd, LACPd, Watchdog, Lifecycle, sFlow exporter, Controller/Agent, SNMP | Long-running services with state |
| **CLI** | rswitchctl + 9 domain-specific tools | Operational control and monitoring |
| **Data Plane** | BPF modules (ingress + egress pipelines) | Wire-speed packet processing |
| **Shared State** | Pinned BPF maps at `/sys/fs/bpf/rs_*` | Cross-module and kernel/user communication |

---

## 3. Data Plane Architecture

### 3.1 Tail-Call Pipeline

rSwitch's data plane is a tail-call chain of BPF programs. The BPF `bpf_tail_call()` helper replaces the current program with another from a program array (`rs_progs`), without returning. This enables modular pipeline composition with zero function-call overhead.

```
Packet arrives at NIC
        │
        ▼
┌─────────────┐     rs_progs[0]     rs_progs[1]     rs_progs[2]
│ dispatcher  │ ──tail_call──→ ──tail_call──→ ──tail_call──→ ...
│ (XDP entry) │
└─────────────┘
```

**Ingress pipeline**: Modules are assigned ascending slots (0, 1, 2, ...) in `rs_progs`. Each module calls `RS_TAIL_CALL_NEXT()` to advance to the next slot.

**Egress pipeline**: Modules are assigned descending slots (255, 254, 253, ...). Each module reads `rs_prog_chain[current_slot]` to find the next slot, enabling concurrent execution on multiple output ports without race conditions.

### 3.2 Per-CPU Shared Context (`rs_ctx`)

All modules in a pipeline share a per-CPU context via `rs_ctx_map` (a `PERCPU_ARRAY` with a single entry). This provides:

- **Zero-copy state transfer** — context stays in L1/L2 cache on the processing CPU
- **Lock-free concurrency** — each CPU has its own context instance
- **Cross-module communication** — upstream modules populate fields consumed by downstream modules

```c
struct rs_ctx {
    // Input metadata
    __u32 ifindex;              // Ingress interface
    __u32 timestamp;            // Packet arrival time

    // Parsing state (populated by dispatcher/vlan)
    struct rs_layers layers;    // L2/L3/L4 offsets, addresses, ports

    // VLAN state (populated by vlan module)
    __u16 ingress_vlan;         // Classified VLAN
    __u16 egress_vlan;          // Outgoing VLAN

    // QoS state (populated by qos_classify)
    __u8  prio, dscp, ecn, traffic_class;

    // Forwarding decision (populated by route/l2learn)
    __u32 egress_ifindex;       // Output port
    __u8  action;               // XDP_PASS / XDP_DROP / XDP_REDIRECT

    // Mirror state (populated by mirror)
    __u8  mirror;
    __u16 mirror_port;

    // Error state
    __u32 error;                // RS_ERROR_* code
    __u32 drop_reason;          // RS_DROP_* reason

    // Pipeline state
    __u32 next_prog_id;         // Next module slot
    __u32 call_depth;           // Recursion guard (max 32)
};
```

### 3.3 Verifier-Safe Packet Access

BPF modules must pass the kernel verifier. rSwitch provides offset masks that constrain pointer arithmetic to safe ranges:

| Mask | Value | Max Offset | Layer |
|------|-------|------------|-------|
| `RS_L3_OFFSET_MASK` | `0x3F` | 63 bytes | L3 (IP header start) |
| `RS_L4_OFFSET_MASK` | `0x7F` | 127 bytes | L4 (TCP/UDP header start) |
| `RS_PAYLOAD_MASK` | `0xFF` | 255 bytes | Payload start |

```c
// Safe pattern: mask offset before pointer arithmetic
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

### 3.4 Core BPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `rs_ctx_map` | `PERCPU_ARRAY` | Per-packet context shared across all modules |
| `rs_progs` | `PROG_ARRAY` | Tail-call targets (ingress slots 0-99, egress 200-255) |
| `rs_prog_chain` | `ARRAY` | Egress next-module lookup (avoids race conditions) |
| `rs_port_config_map` | `HASH` | Per-interface configuration (VLAN mode, learning, QoS) |
| `rs_stats_map` | `PERCPU_ARRAY` | Per-interface packet/byte counters |
| `rs_module_stats_map` | `PERCPU_ARRAY` | Per-module processing statistics |
| `rs_module_config_map` | `HASH` | Per-module config parameters from YAML profiles |
| `rs_mac_table` | `HASH` | MAC address forwarding table (65K entries) |
| `rs_vlan_map` | `HASH` | VLAN membership bitmasks (4K VLANs) |
| `rs_event_bus` | `RINGBUF` | Unified event channel to user-space (1MB) |
| `rs_ifindex_to_port_map` | `HASH` | ifindex → 0-based port index mapping |
| `qinq_config_map` | `HASH` | Q-in-Q (802.1ad) configuration |

All maps are pinned under `/sys/fs/bpf/` and accessible from both BPF programs and user-space tools.

### 3.5 Event Bus

All modules emit structured events to a shared 1MB ring buffer (`rs_event_bus`):

```c
// Event type ranges (per-module namespacing)
0x0000-0x00FF  Core events (packet trace, debug)
0x0100-0x01FF  L2 events (MAC learned/moved/aged)
0x0200-0x02FF  ACL events (rule hit/deny)
0x0300-0x03FF  Route events
0x0400-0x04FF  Mirror events
0x0500-0x05FF  QoS events
0xFF00-0xFFFF  Error events
```

User-space consumers (telemetry, event consumer, sFlow exporter) read from `rs_event_bus` using `bpf_ringbuf_poll()`.

---

## 4. Control Plane Architecture

### 4.1 Loader (`rswitch_loader`)

The loader is the platform orchestrator. It executes a 6-step pipeline:

```
1. DISCOVERY      Scan build/bpf/*.bpf.o, read .rodata.mod ELF sections
                  Extract RS_DECLARE_MODULE() metadata: name, hook, stage, flags
                  Read .rodata.moddep for RS_DEPENDS_ON() declarations

2. ABI CHECK      Verify each module's abi_version matches RS_ABI_VERSION (v1.0)
                  Major version mismatch → reject module
                  Minor version mismatch → load with warning

3. FILTERING      Match discovered modules against YAML profile module list
                  Apply stage overrides from extended module entries
                  Evaluate conditional modules (interface/file/sysctl checks)

4. DEPENDENCY     Build dependency graph from RS_DEPENDS_ON() declarations
                  Topological sort (Kahn's algorithm)
                  Detect and reject cycles

5. LOADING        Load BPF objects into kernel via libbpf
                  Pin shared maps, populate rs_progs array
                  Configure rs_prog_chain for egress linking
                  Write module-specific config params to rs_module_config_map

6. ATTACHMENT     Attach dispatcher XDP program to each configured interface
                  Configure devmap for packet redirection
                  Apply port configuration (VLAN, QoS, security)
```

### 4.2 CLI Tools

| Tool | Maps Accessed | Key Commands |
|------|---------------|--------------|
| `rswitchctl` | All maps | `show-pipeline`, `show-stats`, `show-abi`, `show-profile`, `validate-profile`, `reload`, `show-neighbors`, `show-topology`, `health`, `dev` |
| `rsportctl` | `rs_port_config_map` | Port enable/disable, mode, speed |
| `rsvlanctl` | `rs_vlan_map`, `rs_port_config_map` | VLAN add/delete, port membership, Q-in-Q |
| `rsaclctl` | ACL maps, source guard, DHCP snoop | ACL rules, IP source guard, DHCP snooping bindings |
| `rsroutectl` | Route maps, ARP maps | Static routes, ECMP, ARP entries |
| `rsqosctl` | QoS maps | Queue stats, class maps, policy maps |
| `rsflowctl` | `flow_table_map` | Flow table entries, stats, aging |
| `rsnatctl` | NAT maps | SNAT/DNAT rules, NAT translations |
| `rsvoqctl` | VOQd socket | VOQd mode, queue stats, shaper config |
| `rstunnelctl` | Tunnel maps | VXLAN/GRE tunnel endpoints |

### 4.3 Daemons

| Daemon | Protocol/Function | BPF Interaction |
|--------|-------------------|-----------------|
| `rswitch-voqd` | QoS scheduling (DRR/WFQ) | AF_XDP sockets for zero-copy packet scheduling |
| `rswitch-stpd` | STP/RSTP | Reads STP BPDUs from BPF, manages port states |
| `rswitch-lldpd` | LLDP neighbor discovery | Reads LLDP frames from BPF, populates neighbor DB |
| `rswitch-lacpd` | LACP link aggregation | Reads LACP PDUs from BPF, manages LAG groups |
| `rswitch-watchdog` | Health monitoring | Polls module stats, triggers auto-recovery |
| `rswitch-sflow` | sFlow v5 export | Reads sampled packets from BPF, sends to collector |
| `rswitch-prometheus` | Prometheus metrics | Reads all stats maps, serves HTTP `/metrics` on :9417 |
| `rswitch-controller` | Multi-switch orchestration | TCP daemon, pushes profiles and configs to agents |
| `rswitch-agent` | Remote management | Receives commands from controller, applies locally |
| `rswitch-snmpagent` | SNMP monitoring | pass_persist sub-agent for IF-MIB, RSWITCH-MIB |

### 4.4 Multi-Switch Architecture

For multi-switch deployments, the Controller/Agent model provides centralized management:

```
                    ┌──────────────┐
                    │  Controller  │
                    │  (central)   │
                    └──┬───┬───┬──┘
                       │   │   │   TCP connections
              ┌────────┘   │   └────────┐
              ▼            ▼            ▼
         ┌─────────┐ ┌─────────┐ ┌─────────┐
         │  Agent  │ │  Agent  │ │  Agent  │
         │ Switch1 │ │ Switch2 │ │ Switch3 │
         └─────────┘ └─────────┘ └─────────┘
```

Commands: `push-profile`, `push-config`, `reload-module`, `get-status`, `get-stats`, `exec`.

---

## 5. Profile System

### 5.1 Profile Structure

Profiles are YAML files that define the complete switch personality:

```yaml
# etc/profiles/l3-router.yaml
name: "l3-router"
description: "Layer 3 router with ACL and QoS"
inherits: "base"          # Profile inheritance

modules:
  - vlan                  # Simple form: use default stage
  - name: acl             # Extended form: with overrides
    stage: 30
    optional: false
  - name: qos_classify
    stage: 25
    condition: "interface:eth2"   # Only load if eth2 exists
    config:
      default_class: "best-effort"
      dscp_trust: true

ports:
  - interface: "eth0"
    vlan_mode: "trunk"
    native_vlan: 1
    allowed_vlans: [10, 20, 30]
  - interface: "eth1"
    vlan_mode: "access"
    access_vlan: 10

vlans:
  - id: 10
    name: "Users"
  - id: 20
    name: "Servers"
```

### 5.2 Profile Inheritance

Profiles can inherit from parent profiles, enabling composition:

```
base.yaml → l2-switch.yaml → campus-switch.yaml
                             → datacenter-switch.yaml
```

The loader resolves inheritance recursively: child modules extend (not replace) parent modules; child ports override parent ports by interface name.

### 5.3 Intent-Based Configuration

The intent engine (`scripts/intent_engine.py`) translates high-level network intent YAML into concrete rSwitch profiles:

```yaml
# examples/intents/campus.yaml
intent: "campus_network"
requirements:
  vlans:
    - id: 10
      name: "Student"
      security: high      # → Selects source_guard + dhcp_snoop modules
    - id: 20
      name: "Faculty"
      qos: priority        # → Selects qos_classify + rate_limiter modules
  monitoring: full         # → Selects mirror + sflow modules
```

### 5.4 Policy Verification

The policy verification tool (`scripts/policy_verify.py`) validates that a resolved profile satisfies organizational policies:

```yaml
# examples/policies/campus_policy.yaml
required_modules:
  - acl
  - source_guard
forbidden_modules:
  - afxdp_redirect
port_constraints:
  - must_have_vlan: true
  - max_vlans_per_trunk: 50
```

---

## 6. Module Lifecycle

### 6.1 Module Self-Registration

Every BPF module declares itself with the `RS_DECLARE_MODULE()` macro:

```c
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE(
    "acl",                                     // Name
    RS_HOOK_XDP_INGRESS,                       // Hook point
    30,                                        // Stage number
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP,// Capability flags
    "Access control list filtering"            // Description
);

// Optional: declare dependencies
RS_DEPENDS_ON("vlan");

SEC("xdp")
int acl_prog(struct xdp_md *xdp_ctx) {
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;

    // Module logic here...

    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;  // Fallthrough = drop
}
```

The macro embeds a `struct rs_module_desc` in the `.rodata.mod` ELF section. The loader reads this section at discovery time — no hardcoded module lists, no separate registration step.

### 6.2 ABI Versioning

The ABI uses MAJOR.MINOR semantic versioning packed into a `__u32`:

- **Major version bump**: Breaking changes (struct layout, map format). Modules with mismatched major version are rejected.
- **Minor version bump**: Additive changes (new flags, new helper functions). Modules with older minor version still load.

Current version: **v1.0** (`RS_ABI_VERSION = 0x00010000`).

### 6.3 API Stability Tiers

| Tier | Annotation | Guarantee |
|------|-----------|-----------|
| **Stable** | `RS_API_STABLE` | No breaking changes across minor versions |
| **Experimental** | `RS_API_EXPERIMENTAL` | May change between minor versions |
| **Internal** | `RS_API_INTERNAL` | May change at any time; not for external modules |

Stable APIs: `RS_DECLARE_MODULE`, `RS_GET_CTX`, `RS_TAIL_CALL_NEXT`, `RS_TAIL_CALL_EGRESS`, `RS_EMIT_EVENT`, all `RS_FLAG_*` constants.

### 6.4 Hot-Reload

Individual modules can be replaced at runtime without disrupting the pipeline:

```bash
rswitchctl reload acl              # Replace acl module atomically
rswitchctl reload acl --dry-run    # Validate without applying
```

The hot-reload process:
1. Load new BPF object and verify ABI compatibility
2. Atomically swap the `rs_progs` array entry
3. Verify the new module is processing packets
4. On failure: rollback to previous version automatically

### 6.5 Module Packaging (.rsmod)

Modules are packaged as `.rsmod` archives for distribution:

```bash
rswitchctl pack-module ./my_module.bpf.o    # Creates my_module.rsmod
rswitchctl install-module my_module.rsmod    # Installs to module directory
rswitchctl list-modules                      # List installed modules
```

A `.rsmod` file contains the compiled BPF object, metadata, and optional documentation.

### 6.6 Module Scaffolding

```bash
rswitchctl new-module my_filter --stage 35 --hook ingress --flags NEED_L2L3_PARSE,MAY_DROP
```

Generates a ready-to-build module source file from SDK templates.

---

## 7. Monitoring & Observability Stack

### 7.1 Built-in Telemetry

| Source | Data | Consumer |
|--------|------|----------|
| `rs_stats_map` | Per-interface rx/tx packets, bytes, drops, errors | `rswitch-telemetry`, `rswitch-prometheus` |
| `rs_module_stats_map` | Per-module packets processed/forwarded/dropped/error | `rswitchctl show-stats --module <name>` |
| `rs_event_bus` | Structured events (MAC learn, ACL hit, errors) | `rswitch-events` |
| sFlow BPF sampling | 1-in-N packet samples with flow metadata | `rswitch-sflow` → sFlow collector |
| Watchdog health checks | Module responsiveness, map utilization | `rswitchctl health` |

### 7.2 Prometheus Integration

`rswitch-prometheus` (port 9417) exposes all metrics in Prometheus format:

```
rswitch_port_rx_packets{ifindex="4",port="eth0"} 1234567
rswitch_port_rx_bytes{ifindex="4",port="eth0"} 987654321
rswitch_module_packets_processed{module="acl"} 5000000
rswitch_module_packets_dropped{module="acl"} 42
```

### 7.3 Grafana Dashboards

Pre-built dashboards in `monitoring/grafana/`:

| Dashboard | Panels |
|-----------|--------|
| **Overview** | Port throughput, pipeline health, error rates, top talkers |
| **QoS** | Queue depth, scheduling rates, drop rates per class |
| **Security** | ACL hit rates, source guard violations, DHCP snoop events |
| **VLAN** | Per-VLAN traffic distribution, membership changes |

### 7.4 Alerting Rules

Pre-built Prometheus alerting rules in `monitoring/alerts/rswitch-alerts.yml`:
- Port down, high error rate, high drop rate
- Module not processing, event bus overflow
- Resource exhaustion (map utilization > 80%)
- Watchdog health check failures

### 7.5 SNMP Support

`rswitch-snmpagent` implements a Net-SNMP pass_persist sub-agent exposing:
- Standard IF-MIB counters (ifInOctets, ifOutOctets, ifOperStatus, ...)
- Custom RSWITCH-MIB (module stats, pipeline status, VLAN info)

MIB definition: `mibs/RSWITCH-MIB.txt`

---

## 8. Production Hardening

### 8.1 Graceful Lifecycle Management

`rswitch-lifecycle` provides ordered startup and shutdown:

**Startup**: Validate environment → Load profile → Attach BPF → Start daemons → Confirm ready

**Shutdown**: Stop daemons → Drain queues → Persist state → Detach BPF → Unpin maps

State is persisted to `/var/lib/rswitch/state/` for crash recovery.

### 8.2 Watchdog & Auto-Recovery

`rswitch-watchdog` monitors system health:
- Polls module statistics for activity (stalled module detection)
- Monitors BPF map utilization
- Checks daemon process health
- Triggers auto-recovery: module reload, daemon restart, or full pipeline rebuild

```bash
rswitchctl health              # Quick health check
rswitchctl health --json       # Machine-readable health report
```

### 8.3 Configuration Rollback

`rswitch-rollback` provides snapshot-based configuration management:

```bash
rswitchctl snapshot-create "before QoS changes"    # Save current state
rswitchctl apply new-profile.yaml --confirm 300    # Auto-rollback in 5 min
rswitchctl confirm                                  # Accept changes
rswitchctl rollback                                 # Manual rollback
rswitchctl snapshot-list                            # List available snapshots
```

Auto-rollback timer prevents lockout from misconfigurations on remote switches.

### 8.4 Resource Exhaustion Protection

`rswitch-resource-limits` monitors and enforces:
- BPF map entry utilization (warning at 80%, critical at 95%)
- Memory usage tracking
- Per-module resource budgets

### 8.5 Audit Logging

Every administrative action is recorded:

```bash
rswitchctl audit-log                    # View recent actions
rswitchctl audit-log --since "1h ago"   # Filter by time
rswitchctl audit-rotate                 # Rotate log files
```

Audit records include: timestamp, user, action, target, old/new values.

---

## 9. Module Classification

### 9.1 By OSI Layer

| OSI Layer | Modules | Stage(s) |
|-----------|---------|----------|
| **L1** (Physical) | *None (handled by kernel/NIC driver)* | — |
| **L2** (Data Link) | `dispatcher`, `vlan`, `egress_vlan`, `l2learn`, `stp`, `lacp`, `lldp`, `lastcall`, `egress`, `egress_final` | 10-12, 20, 80, 90, 170-190 |
| **L2.5** (Tunneling) | `tunnel` (VXLAN/GRE decapsulation) | 15 |
| **L3** (Network) | `route` (ECMP, ARP), `conntrack`, `nat` (SNAT/DNAT), `arp_learn` | 32, 50, 55 |
| **L3/L4** (Transport) | `acl` (5-tuple filtering), `source_guard`, `dhcp_snoop`, `flow_table` | 18-19, 30, 60 |
| **L4+** (Application) | `qos_classify`, `rate_limiter`, `egress_qos`, `mirror`, `sflow` | 25, 28, 45, 85, 170 |

### 9.2 By Function

| Function | Modules | Description |
|----------|---------|-------------|
| **Core Pipeline** | `dispatcher`, `egress`, `egress_final`, `lastcall` | Pipeline infrastructure (entry, exit, forwarding) |
| **Switching** | `vlan`, `egress_vlan`, `l2learn`, `stp`, `lacp`, `lldp` | L2 forwarding, VLAN, loop prevention, aggregation, discovery |
| **Routing** | `route`, `conntrack`, `nat`, `flow_table`, `arp_learn` | L3 forwarding, connection tracking, NAT, fast-path |
| **Security** | `acl`, `source_guard`, `dhcp_snoop` | Access control, anti-spoofing, rogue DHCP prevention |
| **QoS** | `qos_classify`, `rate_limiter`, `egress_qos` | Traffic classification, policing, scheduling |
| **Monitoring** | `mirror`, `sflow` | Traffic mirroring (SPAN/RSPAN/ERSPAN), sampling |
| **Tunneling** | `tunnel` | VXLAN/GRE decapsulation |
| **Utility** | `afxdp_redirect`, `veth_egress`, `core_example` | AF_XDP offload, veth, development example |

### 9.3 By Necessity Level

#### Required — Platform will not function without these

| Module | Stage | Reason |
|--------|-------|--------|
| `dispatcher` | 10 | XDP entry point; initializes context and starts pipeline |
| `lastcall` | 90 | Final forwarding decision; manages devmap |
| `egress` | — | Devmap callback; initiates egress pipeline |
| `egress_final` | 190 | Final egress processing; packet delivery |

#### Recommended — Most deployments need these

| Module | Stage | Reason |
|--------|-------|--------|
| `vlan` | 20 | VLAN classification and filtering |
| `egress_vlan` | 180 | Egress VLAN tag insertion/removal |
| `l2learn` | 80 | Dynamic MAC learning for L2 forwarding |
| `acl` | 30 | Access control (security baseline) |
| `route` | 50 | L3 routing with ECMP support |

#### Optional — Specific use cases

| Module | Stage | Use Case |
|--------|-------|----------|
| `stp` | 12 | Loop prevention (multi-switch L2 topologies) |
| `lacp` | 11 | Link aggregation (bonded links) |
| `lldp` | 11 | Neighbor discovery and topology mapping |
| `tunnel` | 15 | Overlay networks (VXLAN, GRE) |
| `source_guard` | 18 | IP source address validation (campus/edge) |
| `dhcp_snoop` | 19 | DHCP snooping for binding table (campus/edge) |
| `qos_classify` | 25 | Traffic classification by DSCP/PCP/5-tuple |
| `rate_limiter` | 28 | Token-bucket rate limiting |
| `conntrack` | 32 | Stateful connection tracking |
| `mirror` | 45 | Traffic mirroring (SPAN, RSPAN, ERSPAN) |
| `nat` | 55 | Network address translation (SNAT/DNAT) |
| `flow_table` | 60 | Hardware-offload-style flow caching |
| `sflow` | 85 | sFlow v5 packet sampling |
| `egress_qos` | 170 | Egress QoS enforcement |

#### Advanced — Specialized or experimental

| Module | Stage | Use Case |
|--------|-------|----------|
| `afxdp_redirect` | 85 | AF_XDP socket redirect for user-space processing |
| `veth_egress` | — | Veth pair egress handling (container networking) |
| `core_example` | — | Reference implementation for developers |

### 9.4 Complete Module Inventory

**27 BPF modules** total:

| # | Module | Hook | Stage | Flags | Dependencies |
|---|--------|------|-------|-------|-------------|
| 1 | `dispatcher` | Ingress | 10 | — | — |
| 2 | `lacp` | Ingress | 11 | NEED_L2L3_PARSE | — |
| 3 | `lldp` | Ingress | 11 | NEED_L2L3_PARSE | — |
| 4 | `stp` | Ingress | 12 | NEED_L2L3_PARSE, MAY_DROP | — |
| 5 | `tunnel` | Ingress | 15 | NEED_L2L3_PARSE, MODIFIES_PACKET | — |
| 6 | `source_guard` | Ingress | 18 | NEED_L2L3_PARSE, MAY_DROP | vlan |
| 7 | `dhcp_snoop` | Ingress | 19 | NEED_L2L3_PARSE, NEED_FLOW_INFO, CREATES_EVENTS | vlan |
| 8 | `vlan` | Ingress | 20 | NEED_L2L3_PARSE, NEED_VLAN_INFO, MODIFIES_PACKET | — |
| 9 | `qos_classify` | Ingress | 25 | NEED_L2L3_PARSE, NEED_FLOW_INFO | — |
| 10 | `rate_limiter` | Ingress | 28 | NEED_L2L3_PARSE, MAY_DROP | qos_classify |
| 11 | `acl` | Ingress | 30 | NEED_L2L3_PARSE, NEED_FLOW_INFO, MAY_DROP, CREATES_EVENTS | — |
| 12 | `conntrack` | Ingress | 32 | NEED_L2L3_PARSE, NEED_FLOW_INFO | — |
| 13 | `mirror` | Ingress | 45 | NEED_L2L3_PARSE | — |
| 14 | `route` | Ingress | 50 | NEED_L2L3_PARSE, MODIFIES_PACKET | — |
| 15 | `nat` | Ingress | 55 | NEED_L2L3_PARSE, NEED_FLOW_INFO, MODIFIES_PACKET | conntrack |
| 16 | `flow_table` | Ingress | 60 | NEED_L2L3_PARSE, NEED_FLOW_INFO | — |
| 17 | `l2learn` | Ingress | 80 | NEED_L2L3_PARSE, NEED_VLAN_INFO, CREATES_EVENTS | — |
| 18 | `arp_learn` | Ingress | 80 | NEED_L2L3_PARSE | — |
| 19 | `afxdp_redirect` | Ingress | 85 | — | — |
| 20 | `sflow` | Ingress | 85 | NEED_L2L3_PARSE, NEED_FLOW_INFO | — |
| 21 | `lastcall` | Ingress | 90 | — | — |
| 22 | `egress` | Egress | — | — | — |
| 23 | `egress_qos` | Egress | 170 | — | — |
| 24 | `egress_vlan` | Egress | 180 | MODIFIES_PACKET | — |
| 25 | `egress_final` | Egress | 190 | — | — |
| 26 | `core_example` | Ingress | — | — | — |
| 27 | `veth_egress` | Egress | — | — | — |

### 9.5 Stage Number Map

```
INGRESS PIPELINE (stages 10-99)
═══════════════════════════════════════════════════════════════════════════

  10          11         12         15         18         19         20
  dispatcher  lacp       stp        tunnel     source     dhcp       vlan
              lldp                             guard      snoop

  25          28         30         32         45         50         55
  qos         rate       acl        conntrack  mirror     route      nat
  classify    limiter

  60          80         85                    90
  flow        l2learn    afxdp                 lastcall
  table       arp_learn  sflow

EGRESS PIPELINE (stages 170-190)
═══════════════════════════════════════════════════════════════════════════

  egress(devmap) → 170:egress_qos → 180:egress_vlan → 190:egress_final
```

---

## 10. Ecosystem & Tooling

### 10.1 SDK

The `sdk/` directory provides everything needed to develop modules outside the main tree:

| Component | Purpose |
|-----------|---------|
| `sdk/include/` | Stable headers (rswitch_bpf.h, module_abi.h, uapi.h, map_defs.h) |
| `sdk/templates/` | Starter modules (simple, stateful, egress) |
| `sdk/Makefile.module` | Standalone build rules |
| `sdk/test/` | Unit test harness and map mocks |
| `sdk/docs/` | SDK quick start guide |

### 10.2 Module Registry

Local module registry (`user/registry/`) maintains a JSON index of installed modules with metadata, version tracking, and dependency resolution.

### 10.3 Module Marketplace

Static HTML portal (`docs/marketplace/`) for browsing available modules. Reads from `modules.json` catalog.

### 10.4 Testing Framework

| Level | Location | Purpose |
|-------|----------|---------|
| Unit tests | `test/unit/` | BPF program logic testing with mock maps |
| Integration tests | `test/integration/` | End-to-end pipeline validation |
| Benchmark tests | `test/benchmark/` | Throughput and latency measurement |
| Fuzz tests | `test/fuzz/` | Input fuzzing for BPF modules |
| SDK tests | `sdk/test/` | External module testing |

### 10.5 CI/CD

GitHub Actions pipeline (`.github/workflows/ci.yml`):
- Build verification (user-space + BPF)
- Unit tests
- Integration tests
- Static analysis
- Documentation generation

### 10.6 Documentation Generator

`scripts/gen_api_docs.py` extracts API documentation from source headers and generates `docs/development/API_Reference_Generated.md`.

---

## 11. Comparison: Traditional vs rSwitch

| Aspect | Traditional Switch | rSwitch |
|--------|-------------------|---------|
| **Pipeline** | Fixed in hardware (ASIC/FPGA) | Software-defined, profile-driven |
| **Adding features** | Firmware update or hardware change | Write a BPF module, add to profile |
| **Removing features** | Often impossible | Remove from profile, reload |
| **Customization** | Limited to vendor-exposed options | Custom BPF modules with full packet access |
| **Update impact** | Full restart, traffic loss | Hot-reload individual modules |
| **Debug/trace** | Limited vendor tools | Full observability via event bus, bpftool, CLI |
| **Deployment** | Hardware-specific | Any Linux box with XDP-capable NIC |
| **Multi-tenancy** | VLAN/VRF only | Custom isolation modules possible |
| **Monitoring** | SNMP/syslog | Prometheus, Grafana, sFlow, SNMP, event bus |
| **Configuration** | Vendor CLI | YAML profiles, intent engine, REST (future) |
| **Disaster recovery** | Startup config | Snapshot-based rollback with auto-rollback timer |

---

## 12. Directory Structure

```
rswitch/
├── bpf/
│   ├── include/              # BPF headers (rswitch_bpf.h, rswitch_common.h, vmlinux.h)
│   ├── core/                 # Core infrastructure (dispatcher, egress, uapi.h, module_abi.h, map_defs.h)
│   └── modules/              # All pluggable BPF modules (23 modules)
├── user/
│   ├── loader/               # rswitch_loader + profile_parser
│   ├── ctl/                  # rswitchctl (main CLI + dev subcommands)
│   ├── tools/                # Domain-specific CLI tools (rsvlanctl, rsaclctl, ...)
│   ├── voqd/                 # VOQd QoS scheduler (AF_XDP) + shaper
│   ├── reload/               # Hot-reload engine
│   ├── telemetry/            # Telemetry reader daemon
│   ├── events/               # Event bus consumer daemon
│   ├── stpd/                 # STP/RSTP daemon
│   ├── lldpd/                # LLDP daemon
│   ├── lacpd/                # LACP daemon
│   ├── sflow/                # sFlow v5 exporter
│   ├── exporter/             # Prometheus metrics exporter
│   ├── watchdog/             # Health monitoring daemon
│   ├── lifecycle/            # Graceful startup/shutdown
│   ├── resource/             # Resource exhaustion protection
│   ├── registry/             # Module registry (JSON index)
│   ├── rollback/             # Snapshot-based config rollback
│   ├── audit/                # Audit logging
│   ├── controller/           # Multi-switch controller daemon
│   ├── agent/                # Remote agent daemon
│   ├── topology/             # Topology discovery from LLDP
│   ├── snmpagent/            # SNMP pass_persist sub-agent
│   └── common/               # Shared libraries (rs_log)
├── sdk/                      # External module development kit
│   ├── include/              # Stable SDK headers
│   ├── templates/            # Module templates (simple, stateful, egress)
│   ├── test/                 # Test harness and map mocks
│   ├── docs/                 # SDK documentation
│   └── Makefile.module       # Standalone build rules
├── etc/profiles/             # YAML profile files (18+ profiles)
├── scripts/                  # Helper scripts (intent engine, policy verify, API doc gen)
├── test/                     # Test suites (unit, integration, benchmark, fuzz)
├── monitoring/               # Grafana dashboards + Prometheus alert rules
├── mibs/                     # SNMP MIB definitions
├── examples/                 # Example configs, intents, policies
├── docs/                     # Documentation (usage, deployment, development, backlog)
├── external/libbpf/          # libbpf submodule
├── build/                    # Build outputs
└── Makefile                  # Build system (~490 lines)
```

---

## 13. References

### Internal Documentation

- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — How to write BPF modules
- [API_Reference.md](./API_Reference.md) — Full API reference
- [API_Reference_Generated.md](./API_Reference_Generated.md) — Auto-generated API docs
- [CO-RE_Guide.md](./CO-RE_Guide.md) — Cross-kernel portability
- [Contributing.md](./Contributing.md) — How to contribute
- [Distributed_State_Sync.md](./Distributed_State_Sync.md) — Multi-switch state sync design
- [SDK Quick Start](../../sdk/docs/SDK_Quick_Start.md) — External module development

### Operational Guides

- [Quick_Start.md](../usage/Quick_Start.md) — Get started in 5 minutes
- [How_To_Use.md](../usage/How_To_Use.md) — Detailed usage guide
- [Intent_Engine.md](../usage/Intent_Engine.md) — Intent-based configuration
- [Policy_Verification.md](../usage/Policy_Verification.md) — Policy compliance checking
- [Installation.md](../deployment/Installation.md) — Build and install
- [Configuration.md](../deployment/Configuration.md) — Profile and port configuration

### Architecture Deep-Dives

- [Module_Auto-Discovery_System.md](../paperwork/Module_Auto-Discovery_System.md)
- [Tail-Call_Pipeline_Architecture.md](../paperwork/Tail-Call_Pipeline_Architecture.md)
- [Per-CPU_Context_Management.md](../paperwork/Per-CPU_Context_Management.md)
- [BPF_Map_Sharing_Patterns.md](../paperwork/BPF_Map_Sharing_Patterns.md)
- [Event_Bus_Architecture.md](../paperwork/Event_Bus_Architecture.md)
- [VOQd_State_Machine_Architecture.md](../paperwork/VOQd_State_Machine_Architecture.md)
