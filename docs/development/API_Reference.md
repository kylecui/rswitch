# API Reference

Complete API reference for rSwitch module developers, integrators, and operators. This document covers all public interfaces across three API layers.

---

## API Layers

| Layer | Audience | Purpose |
|-------|----------|---------|
| **BPF Module API** | Module developers | Create custom packet processing modules |
| **Profile API** | Operators | Configure pipeline via YAML |
| **Control API** | Applications | Runtime control and monitoring |

---

## 1. BPF Module API

### Header Files

```c
#include "rswitch_bpf.h"    // Main BPF header (includes vmlinux.h, helpers)
#include "module_abi.h"     // Module self-registration (RS_DECLARE_MODULE)
#include "uapi.h"           // Shared structures (rs_ctx, rs_layers)
#include "map_defs.h"       // Map definitions and helper functions
```

Location: `bpf/include/` and `bpf/core/`

---

### Core Macros

#### RS_DECLARE_MODULE

Registers a module with the auto-discovery system by embedding metadata in the ELF `.rodata.mod` section.

```c
RS_DECLARE_MODULE(name, hook, stage, flags, description)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `const char*` | Module identifier (max 31 chars) — matches YAML profile entries |
| `hook` | `enum` | `RS_HOOK_XDP_INGRESS` or `RS_HOOK_XDP_EGRESS` |
| `stage` | `__u32` | Execution order: 10-99 (ingress), 100-199 (egress) |
| `flags` | `__u32` | Capability flags (OR-combined, see table below) |
| `description` | `const char*` | Human-readable description (max 63 chars) |

#### RS_GET_CTX

Retrieves the per-CPU packet context from `rs_ctx_map`.

```c
struct rs_ctx *ctx = RS_GET_CTX();
// Returns: pointer to struct rs_ctx, or NULL on failure
```

**Always** check the return value for NULL.

#### RS_TAIL_CALL_NEXT

Continues to the next module in the **ingress** pipeline.

```c
RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `xdp_ctx` | `struct xdp_md *` | XDP context |
| `rs_ctx` | `struct rs_ctx *` | rSwitch per-CPU context |

Behavior: Increments `rs_ctx->next_prog_id`, performs `bpf_tail_call()` to the next ingress slot. If the tail-call fails, control returns to the caller.

#### RS_TAIL_CALL_EGRESS

Continues to the next module in the **egress** pipeline.

```c
RS_TAIL_CALL_EGRESS(xdp_ctx, rs_ctx)
```

Behavior: Looks up the next module from `rs_prog_chain` map. Egress slots are assigned descending from 255.

#### RS_EMIT_EVENT

Sends a structured event to user-space via the unified ring buffer (`rs_event_bus`).

```c
int RS_EMIT_EVENT(event_ptr, event_size)
// Returns: 0 on success, -1 if ringbuf full
```

---

### Capability Flags

| Flag | Value | Meaning |
|------|-------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | `0x01` | Module requires L2/L3 headers parsed |
| `RS_FLAG_NEED_VLAN_INFO` | `0x02` | Module requires VLAN information |
| `RS_FLAG_NEED_FLOW_INFO` | `0x04` | Module requires 5-tuple flow info |
| `RS_FLAG_MODIFIES_PACKET` | `0x08` | Module may modify packet data |
| `RS_FLAG_MAY_DROP` | `0x10` | Module may drop packets |
| `RS_FLAG_CREATES_EVENTS` | `0x20` | Module generates ring buffer events |

---

### Data Structures

#### struct rs_module_desc

Embedded in ELF `.rodata.mod` section by `RS_DECLARE_MODULE()`:

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

#### struct rs_ctx

Per-packet processing context shared across all pipeline modules:

```c
struct rs_ctx {
    // Input metadata
    __u32 ifindex;              // Ingress interface index
    __u32 timestamp;            // Packet arrival timestamp

    // Parsing state
    __u8  parsed;               // 0 = not parsed, 1 = L2/L3 parsed
    __u8  modified;             // 0 = unchanged, 1 = packet modified
    struct rs_layers layers;    // Parsed layer information

    // VLAN processing
    __u16 ingress_vlan;         // VLAN ID determined at ingress
    __u16 egress_vlan;          // VLAN ID for egress tagging

    // QoS and priority
    __u8  prio;                 // Priority (0-7, 7 = highest)
    __u8  dscp;                 // DSCP value
    __u8  ecn;                  // ECN bits
    __u8  traffic_class;        // User-defined traffic class

    // Forwarding decision
    __u32 egress_ifindex;       // Target egress interface
    __u8  action;               // XDP_PASS, XDP_DROP, XDP_REDIRECT
    __u8  mirror;               // 0 = no mirror, 1 = mirror required
    __u16 mirror_port;          // Mirror destination port

    // Error handling
    __u32 error;                // Error code (RS_ERROR_*)
    __u32 drop_reason;          // Drop reason (RS_DROP_*)

    // Pipeline state
    __u32 next_prog_id;         // Next program slot to tail-call
    __u32 call_depth;           // Current tail-call depth (recursion guard)
};
```

#### struct rs_layers

Parsed packet layer information:

```c
struct rs_layers {
    __u16 eth_proto;            // ETH_P_IP, ETH_P_IPV6, ETH_P_ARP, etc.
    __u16 vlan_ids[2];          // VLAN IDs (outer, inner)
    __u8  vlan_depth;           // Number of VLAN tags (0-2)
    __u8  ip_proto;             // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, etc.

    __be32 saddr;               // Source IP (network byte order)
    __be32 daddr;               // Destination IP (network byte order)
    __be16 sport;               // Source port (network byte order)
    __be16 dport;               // Destination port (network byte order)

    __u16 l2_offset;            // Ethernet header offset
    __u16 l3_offset;            // IP header offset
    __u16 l4_offset;            // TCP/UDP header offset
    __u16 payload_offset;       // Payload offset
    __u32 payload_len;          // Payload length
};
```

---

### Helper Functions

#### Packet Access (CO-RE safe)

```c
struct ethhdr *get_ethhdr(struct xdp_md *ctx);
struct iphdr  *get_iphdr(struct xdp_md *ctx, __u16 offset);
struct ipv6hdr *get_ipv6hdr(struct xdp_md *ctx, __u16 offset);
void *GET_HEADER(struct xdp_md *ctx, __u16 offset, type);
```

#### CO-RE Field Operations

```c
READ_KERN(dst, src);                        // CO-RE field read
int FIELD_EXISTS(struct, field);            // Check if field exists in running kernel
size_t FIELD_SIZE(struct, field);           // Get field size
int CHECK_BOUNDS(struct xdp_md *ctx, void *ptr, __u32 size);  // Packet bounds check
```

#### Port Configuration

```c
struct rs_port_config *rs_get_port_config(__u32 ifindex);
```

#### MAC Table

```c
struct rs_mac_entry *rs_mac_lookup(__u8 *mac, __u16 vlan);
int rs_mac_update(__u8 *mac, __u16 vlan, __u32 ifindex, __u64 timestamp);
```

#### VLAN Membership

```c
// Returns: 1 if member, 0 if not
// Sets *is_tagged: 1 = tagged member, 0 = untagged member
int rs_is_vlan_member(__u16 vlan, __u32 ifindex, int *is_tagged);
```

#### Statistics

```c
void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes);
void rs_stats_update_drop(struct rs_ctx *ctx);
```

#### Debug

```c
// Conditional debug output (only with -DDEBUG)
bpf_debug(fmt, ...);
// Alias:
rs_debug(fmt, ...);
```

---

### Offset Masks (Verifier Safety)

Use these masks when computing packet data pointers to satisfy the BPF verifier:

| Mask | Value | Max Offset | Use Case |
|------|-------|------------|----------|
| `RS_L3_OFFSET_MASK` | `0x3F` | 63 bytes | L2 headers (Ethernet + up to 2 VLAN tags) |
| `RS_L4_OFFSET_MASK` | `0x7F` | 127 bytes | L2 + L3 headers |
| `RS_PAYLOAD_MASK` | `0xFF` | 255 bytes | Full header stack |

Usage pattern:

```c
void *data = (void *)(long)xdp->data;
void *data_end = (void *)(long)xdp->data_end;

struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

---

### Error Codes

#### Module Error Codes (`rs_ctx->error`)

| Code | Name | Description |
|------|------|-------------|
| 0 | `RS_ERROR_NONE` | No error |
| 1 | `RS_ERROR_PARSE_FAILED` | Packet parsing failed |
| 2 | `RS_ERROR_INVALID_VLAN` | Invalid VLAN configuration |
| 3 | `RS_ERROR_ACL_DENY` | ACL denied packet |
| 4 | `RS_ERROR_NO_ROUTE` | No route to destination |
| 5 | `RS_ERROR_QUEUE_FULL` | Queue full (QoS) |
| 99 | `RS_ERROR_INTERNAL` | Internal error |

#### Drop Reasons (`rs_ctx->drop_reason`)

| Code | Name | Description |
|------|------|-------------|
| 0 | `RS_DROP_NONE` | Not dropped |
| 1 | `RS_DROP_PARSE_ERROR` | Packet parse error |
| 2 | `RS_DROP_VLAN_FILTER` | VLAN membership filter |
| 3 | `RS_DROP_ACL_BLOCK` | ACL rule blocked |
| 4 | `RS_DROP_NO_FWD_ENTRY` | No forwarding entry in MAC/FDB table |
| 5 | `RS_DROP_TTL_EXCEEDED` | TTL reached zero |
| 6 | `RS_DROP_RATE_LIMIT` | Rate limiter dropped |
| 7 | `RS_DROP_CONGESTION` | Congestion / queue overflow |

---

## 2. Profile API (YAML Configuration)

### Profile Structure

```yaml
name: "Profile Name"          # Required
version: "1.0"                # Required
description: "Description"    # Optional

# Module selection (simple lists — stage order from ELF metadata)
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1
  - egress_module_2

# Global settings
settings:
  mac_learning: true           # Enable MAC learning
  mac_aging_time: 300          # MAC aging time (seconds)
  vlan_enforcement: true       # Enforce VLAN membership
  default_vlan: 1              # Default VLAN for untagged packets
  unknown_unicast_flood: true  # Flood unknown unicast
  broadcast_flood: true        # Flood broadcast
  stats_enabled: true          # Enable statistics collection
  ringbuf_enabled: true        # Enable event ring buffer
  debug: false                 # Enable debug logging

# Port configuration
ports:
  - interface: "eth0"
    enabled: true
    vlan_mode: trunk           # off | access | trunk | hybrid
    pvid: 1                    # Port VLAN ID
    native_vlan: 1             # Native VLAN for trunk ports
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0        # Default QoS priority (0-7)

# VLAN configuration
vlans:
  - vlan_id: 100
    name: "Management"
    tagged_ports: ["eth0", "eth1"]
    untagged_ports: []

# VOQd (QoS scheduler) configuration
voqd:
  enabled: false
  mode: 1                      # 0=BYPASS, 1=SHADOW, 2=ACTIVE
  num_ports: 4
  prio_mask: 0xFF
  zero_copy: true
  rx_ring_size: 4096
  tx_ring_size: 4096
  frame_size: 4096
  batch_size: 64
  poll_timeout_ms: 100
  enable_scheduler: true
  cpu_affinity: -1
  busy_poll: false
  enable_afxdp: true
  software_queues:
    enabled: false
    queue_depth: 1024
    num_priorities: 8
```

### VLAN Modes

| Mode | Value | Behavior |
|------|-------|----------|
| `off` | 0 | No VLAN processing on this port |
| `access` | 1 | Untagged traffic only; assigned to `pvid` |
| `trunk` | 2 | Tagged traffic; `native_vlan` for untagged frames |
| `hybrid` | 3 | Mix of tagged and untagged VLANs |

### Available Modules

#### Ingress (stages 10-99)

| Module | Stage | Description |
|--------|-------|-------------|
| `vlan` | 20 | VLAN tag processing (access/trunk/hybrid modes) |
| `acl` | 30 | L3/L4 access control lists |
| `mirror` | 40 | SPAN port mirroring |
| `route` | 50 | IPv4 LPM routing |
| `l2learn` | 80 | MAC address learning and aging |
| `afxdp_redirect` | 85 | AF_XDP socket redirect for QoS |
| `lastcall` | 90 | Final forwarding decision (**must be last**) |

#### Egress (stages 100-199)

| Module | Stage | Description |
|--------|-------|-------------|
| `egress_qos` | 170 | QoS classification and marking |
| `egress_vlan` | 180 | Egress VLAN tag insertion/removal |
| `egress_final` | 190 | Final egress processing (**must be last**) |

### Example Profiles

18 YAML profile files are included in `etc/profiles/`. Key examples:

| Profile | Use Case |
|---------|----------|
| `dumb.yaml` | Passthrough (no processing) |
| `l2.yaml` | Basic L2 switch |
| `l2-vlan.yaml` | L2 switch with VLAN |
| `l3.yaml` | L3 router |
| `l3-acl-lab.yaml` | L3 router with ACL filtering |
| `firewall.yaml` | ACL-based firewall |
| `l3-qos-voqd-test.yaml` | Full QoS with VOQd scheduling |
| `all-modules-test.yaml` | All modules loaded (testing) |

---

## 3. Control API (C Library)

### Loader Functions

```c
// Initialize loader context
void loader_ctx_init(struct loader_ctx *ctx);

// Load and parse a YAML profile
int profile_load(const char *filename, struct rs_profile *profile);

// Free profile resources
void profile_free(struct rs_profile *profile);

// Print profile information to stdout
void profile_print(const struct rs_profile *profile);
```

### BPF Map Access (via libbpf)

```c
// Open a pinned map by path
int bpf_obj_get(const char *pathname);

// CRUD operations on map elements
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_delete_elem(int fd, const void *key);
```

### Pinned Map Paths

| Map | Path | Type |
|-----|------|------|
| Context | `/sys/fs/bpf/rs_ctx_map` | PERCPU_ARRAY |
| Programs | `/sys/fs/bpf/rs_progs` | PROG_ARRAY |
| Program chain | `/sys/fs/bpf/rs_prog_chain` | ARRAY |
| Port config | `/sys/fs/bpf/rs_port_config_map` | HASH |
| Statistics | `/sys/fs/bpf/rs_stats_map` | PERCPU_ARRAY |
| Event bus | `/sys/fs/bpf/rs_event_bus` | RINGBUF |
| MAC table | `/sys/fs/bpf/rs_mac_table` | HASH |
| VLAN map | `/sys/fs/bpf/rs_vlan_map` | HASH |
| Device map | `/sys/fs/bpf/rs_xdp_devmap` | DEVMAP_HASH |

### Event Consumption

```c
#include <bpf/libbpf.h>

static int handle_event(void *ctx, void *data, size_t size) {
    struct rs_event_header *hdr = data;
    switch (hdr->type) {
    case RS_EVENT_MAC_LEARNED:
        // Handle MAC learned event
        break;
    case RS_EVENT_ACL_HIT:
        // Handle ACL hit event
        break;
    }
    return 0;
}

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    while (running) {
        ring_buffer__poll(rb, 100);  // 100ms timeout
    }

    ring_buffer__free(rb);
    return 0;
}
```

---

## 4. CLI Tools Reference

### rswitchctl

```bash
rswitchctl show-pipeline          # Show loaded modules and pipeline order
rswitchctl show-stats             # Show per-port statistics
rswitchctl stats [interface]      # Show stats for specific interface
rswitchctl mac-table              # Show MAC address table
rswitchctl mac-add <mac> <vlan> <interface>   # Add static MAC entry
rswitchctl mac-del <mac> <vlan>               # Delete MAC entry
rswitchctl show-events            # Monitor event bus
```

### rsvlanctl

```bash
rsvlanctl show                    # Show VLAN configuration
rsvlanctl add <vlan_id> [name]    # Create VLAN
rsvlanctl del <vlan_id>           # Delete VLAN
rsvlanctl add-port <vlan_id> <interface> [tagged|untagged]  # Add port to VLAN
```

### rsaclctl

```bash
rsaclctl show                     # Show ACL rules
rsaclctl add <priority> <match> <action>   # Add ACL rule
rsaclctl del <priority>           # Delete ACL rule
```

### rsqosctl

```bash
rsqosctl stats                    # Show QoS statistics
rsqosctl queues                   # Show queue status
rsqosctl set-prio <interface> <priority>   # Set port priority
```

### rswitch_loader

```bash
rswitch_loader --profile <path>   # Load with specified YAML profile
               --ifaces <if1,if2> # Attach to interfaces (comma-separated)
               --verbose          # Enable verbose output
               --debug            # Enable debug logging
               --xdp-mode <mode>  # XDP mode: native, generic, offload
               --detach           # Detach XDP programs from interfaces
```

### rswitch-voqd

```bash
rswitch-voqd -m <mode>            # VOQd mode: 0=BYPASS, 1=SHADOW, 2=ACTIVE
             -q <num>             # Number of software queues
             -Q <depth>           # Queue depth
             -i <interfaces>     # Comma-separated interface list
             -S <interval>       # Stats reporting interval (seconds)
             -p <ports>          # Number of ports
             -P <prio_mask>      # Priority mask
```

---

## 5. Version Compatibility

| ABI Version | rSwitch Version | Notes |
|-------------|-----------------|-------|
| 1 | 1.0.0+ | Initial release |

The loader checks `rs_module_desc.abi_version` against `RS_ABI_VERSION` at load time. Incompatible modules are rejected.

---

## See Also

- [Architecture.md](./Architecture.md) — System architecture overview
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — Module development tutorial
- [CO-RE_Guide.md](./CO-RE_Guide.md) — Cross-kernel portability
- [Configuration](../deployment/Configuration.md) — YAML profile format details
- [CLI_Reference](../usage/CLI_Reference.md) — CLI usage examples
