# API Reference and Library Usage Guide

This document provides the public API reference for rSwitch, designed for external users who want to:
1. **Integrate rSwitch** into their applications
2. **Develop custom modules** for the pipeline
3. **Control rSwitch** programmatically

---

## API Overview

rSwitch exposes three API layers:

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

### Core Macros

#### RS_DECLARE_MODULE

Registers a module with the auto-discovery system.

```c
RS_DECLARE_MODULE(name, hook, stage, flags, description)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `const char*` | Module identifier (max 31 chars) |
| `hook` | `enum rs_hook_point` | `RS_HOOK_XDP_INGRESS` or `RS_HOOK_XDP_EGRESS` |
| `stage` | `__u32` | Execution order (10-99 ingress, 100-199 egress) |
| `flags` | `__u32` | Capability flags (see below) |
| `description` | `const char*` | Human-readable description (max 63 chars) |

**Capability Flags:**

| Flag | Value | Meaning |
|------|-------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | `0x01` | Requires L2/L3 headers parsed |
| `RS_FLAG_NEED_VLAN_INFO` | `0x02` | Requires VLAN information |
| `RS_FLAG_NEED_FLOW_INFO` | `0x04` | Requires 5-tuple flow info |
| `RS_FLAG_MODIFIES_PACKET` | `0x08` | May modify packet data |
| `RS_FLAG_MAY_DROP` | `0x10` | May drop packets |
| `RS_FLAG_CREATES_EVENTS` | `0x20` | Generates ringbuf events |

**Example:**

```c
RS_DECLARE_MODULE(
    "my_filter",
    RS_HOOK_XDP_INGRESS,
    35,  // After ACL (30), before route (50)
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP,
    "Custom packet filter"
);
```

#### RS_GET_CTX

Retrieves the per-CPU packet context.

```c
struct rs_ctx *ctx = RS_GET_CTX();
```

**Returns:** Pointer to `struct rs_ctx` or `NULL` if lookup fails.

**Usage:**
```c
SEC("xdp")
int my_module(struct xdp_md *xdp) {
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;
    
    // Access parsed headers
    __be32 src_ip = ctx->layers.saddr;
    __be16 dst_port = ctx->layers.dport;
    
    // Continue pipeline
    RS_TAIL_CALL_NEXT(xdp, ctx);
    return XDP_PASS;
}
```

#### RS_TAIL_CALL_NEXT (Ingress)

Continues to the next module in the ingress pipeline.

```c
RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `xdp_ctx` | `struct xdp_md *` | XDP context |
| `rs_ctx` | `struct rs_ctx *` | rSwitch context |

**Behavior:**
- Increments `rs_ctx->next_prog_id`
- Performs `bpf_tail_call()` to next ingress module
- If tail-call fails, control returns to caller

#### RS_TAIL_CALL_EGRESS (Egress)

Continues to the next module in the egress pipeline.

```c
RS_TAIL_CALL_EGRESS(xdp_ctx, rs_ctx)
```

**Behavior:**
- Looks up next module from `rs_prog_chain` map
- Uses slot-based chaining (255 → 254 → ...)
- Safe for concurrent execution during flooding

#### RS_EMIT_EVENT

Sends an event to user-space via the unified event bus.

```c
int RS_EMIT_EVENT(event_ptr, event_size)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_ptr` | `void *` | Pointer to event structure |
| `event_size` | `size_t` | Size of event in bytes |

**Returns:** `0` on success, `-1` if ringbuf full.

**Example:**
```c
struct my_event {
    __u16 type;
    __u16 len;
    __u32 ifindex;
    __be32 src_ip;
};

struct my_event evt = {
    .type = RS_EVENT_ACL_BASE + 1,
    .len = sizeof(evt),
    .ifindex = ctx->ifindex,
    .src_ip = ctx->layers.saddr,
};
RS_EMIT_EVENT(&evt, sizeof(evt));
```

### Data Structures

#### struct rs_ctx

Per-packet processing context shared across all modules.

```c
struct rs_ctx {
    // Input metadata
    __u32 ifindex;              // Ingress interface index
    __u32 timestamp;            // Packet arrival timestamp
    
    // Parsing state
    __u8  parsed;               // 0=not parsed, 1=L2/L3 parsed
    __u8  modified;             // 0=unchanged, 1=packet modified
    struct rs_layers layers;    // Parsed layer information
    
    // VLAN processing results
    __u16 ingress_vlan;         // VLAN ID determined at ingress
    __u16 egress_vlan;          // VLAN ID for egress
    
    // QoS and priority
    __u8  prio;                 // Priority (0-7, 7=highest)
    __u8  dscp;                 // DSCP value
    __u8  ecn;                  // ECN bits
    __u8  traffic_class;        // User-defined traffic class
    
    // Forwarding decision
    __u32 egress_ifindex;       // Target egress interface
    __u8  action;               // XDP_PASS, XDP_DROP, XDP_REDIRECT
    __u8  mirror;               // 0=no mirror, 1=mirror required
    __u16 mirror_port;          // Mirror destination port
    
    // Error handling
    __u32 error;                // Error code (RS_ERROR_*)
    __u32 drop_reason;          // Drop reason (RS_DROP_*)
    
    // Pipeline state
    __u32 next_prog_id;         // Next program to tail-call
    __u32 call_depth;           // Current tail-call depth
};
```

#### struct rs_layers

Parsed packet layer information.

```c
struct rs_layers {
    __u16 eth_proto;            // ETH_P_IP, ETH_P_IPV6, etc.
    __u16 vlan_ids[2];          // VLAN IDs (outer to inner)
    __u8  vlan_depth;           // Number of VLAN tags (0-2)
    __u8  ip_proto;             // IPPROTO_TCP, IPPROTO_UDP, etc.
    
    __be32 saddr;               // Source IP (network byte order)
    __be32 daddr;               // Destination IP
    __be16 sport;               // Source port
    __be16 dport;               // Destination port
    
    __u16 l2_offset;            // Ethernet header offset
    __u16 l3_offset;            // IP header offset
    __u16 l4_offset;            // TCP/UDP header offset
    __u16 payload_offset;       // Payload offset
    __u32 payload_len;          // Payload length
};
```

### Helper Functions

#### Port Configuration

```c
// Get port configuration by interface index
struct rs_port_config *rs_get_port_config(__u32 ifindex);
```

#### MAC Table

```c
// Lookup MAC forwarding entry
struct rs_mac_entry *rs_mac_lookup(__u8 *mac, __u16 vlan);

// Update MAC table (for learning)
int rs_mac_update(__u8 *mac, __u16 vlan, __u32 ifindex, __u64 timestamp);
```

#### VLAN Membership

```c
// Check if port is member of VLAN
// Returns: 1 if member, 0 if not
// Sets *is_tagged: 1=tagged member, 0=untagged member
int rs_is_vlan_member(__u16 vlan, __u32 ifindex, int *is_tagged);
```

#### Statistics

```c
// Update RX statistics
void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes);

// Update drop statistics
void rs_stats_update_drop(struct rs_ctx *ctx);
```

### Offset Masks (Verifier Safety)

Use these masks when accessing packet data to satisfy the BPF verifier:

```c
#define RS_L3_OFFSET_MASK  0x3F   // Max 63 bytes for L2 headers
#define RS_L4_OFFSET_MASK  0x7F   // Max 127 bytes for L2+L3
#define RS_PAYLOAD_MASK    0xFF   // Max 255 bytes for headers

// Safe header access pattern
void *data = (void *)(long)xdp->data;
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

---

## 2. Profile API (YAML Configuration)

### Profile Structure

```yaml
name: "Profile Name"
version: "1.0"
description: "Optional description"

# Module selection
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1
  - egress_module_2

# Settings
settings:
  mac_learning: true
  mac_aging_time: 300
  vlan_enforcement: true
  default_vlan: 1
  unknown_unicast_flood: true
  broadcast_flood: true
  stats_enabled: true
  ringbuf_enabled: true
  debug: false

# Port configuration
ports:
  - interface: "eth0"
    enabled: true
    vlan_mode: trunk        # off|access|trunk|hybrid
    pvid: 1
    native_vlan: 1
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0

# VLAN configuration
vlans:
  - vlan_id: 100
    name: "Management"
    tagged_ports: ["eth0", "eth1"]
    untagged_ports: []

# VOQd (QoS scheduler)
voqd:
  enabled: false
  mode: 1                   # 0=BYPASS, 1=SHADOW, 2=ACTIVE
  num_ports: 4
  prio_mask: 0xFF
  zero_copy: true
  rx_ring_size: 4096
  tx_ring_size: 4096
  batch_size: 64
  poll_timeout_ms: 100
  enable_scheduler: true
```

### VLAN Modes

| Mode | Value | Behavior |
|------|-------|----------|
| `off` | 0 | No VLAN processing |
| `access` | 1 | Untagged only, assigned to access_vlan |
| `trunk` | 2 | Tagged traffic, native_vlan for untagged |
| `hybrid` | 3 | Mix of tagged and untagged VLANs |

### Available Modules

**Ingress (stages 10-99):**
- `vlan` (20) - VLAN tag processing
- `acl` (30) - Access control lists
- `route` (50) - L3 routing
- `mirror` (70) - Port mirroring
- `l2learn` (80) - MAC learning
- `arp_learn` (82) - ARP learning
- `afxdp_redirect` (85) - AF_XDP QoS redirect
- `lastcall` (90) - Final forwarding decision

**Egress (stages 100-199):**
- `egress_qos` (170) - QoS enforcement
- `egress_vlan` (180) - Egress VLAN tagging
- `egress_final` (190) - Final egress processing

---

## 3. Control API (C Library)

### Loader Functions

```c
// Initialize loader context
void loader_ctx_init(struct loader_ctx *ctx);

// Load profile from file
int profile_load(const char *filename, struct rs_profile *profile);

// Free profile resources
void profile_free(struct rs_profile *profile);

// Print profile information
void profile_print(const struct rs_profile *profile);
```

### Map Access

```c
// Get pinned map file descriptor
int bpf_obj_get(const char *pathname);

// Update map element
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);

// Lookup map element
int bpf_map_lookup_elem(int fd, const void *key, void *value);

// Delete map element
int bpf_map_delete_elem(int fd, const void *key);
```

### Pinned Map Paths

| Map | Path | Type |
|-----|------|------|
| `rs_ctx_map` | `/sys/fs/bpf/rs_ctx_map` | PERCPU_ARRAY |
| `rs_progs` | `/sys/fs/bpf/rs_progs` | PROG_ARRAY |
| `rs_prog_chain` | `/sys/fs/bpf/rs_prog_chain` | ARRAY |
| `rs_port_config_map` | `/sys/fs/bpf/rs_port_config_map` | HASH |
| `rs_stats_map` | `/sys/fs/bpf/rs_stats_map` | PERCPU_ARRAY |
| `rs_event_bus` | `/sys/fs/bpf/rs_event_bus` | RINGBUF |
| `rs_mac_table` | `/sys/fs/bpf/rs_mac_table` | HASH |
| `rs_vlan_map` | `/sys/fs/bpf/rs_vlan_map` | HASH |
| `rs_xdp_devmap` | `/sys/fs/bpf/rs_xdp_devmap` | DEVMAP_HASH |

### Event Consumption

```c
#include <bpf/libbpf.h>

// Event callback signature
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

// Create ring buffer manager
struct ring_buffer *ring_buffer__new(int map_fd, 
                                      ring_buffer_sample_fn sample_cb,
                                      void *ctx,
                                      const struct ring_buffer_opts *opts);

// Poll for events
int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);

// Clean up
void ring_buffer__free(struct ring_buffer *rb);
```

**Example:**

```c
static int handle_event(void *ctx, void *data, size_t size) {
    struct rs_event_header *hdr = data;
    
    switch (hdr->type) {
    case RS_EVENT_MAC_LEARNED:
        // Handle MAC learned event
        break;
    case RS_EVENT_ACL_HIT:
        // Handle ACL hit
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

## 4. CLI Tools

### rswitchctl

Main control utility for rSwitch operations.

```bash
# Show pipeline status
rswitchctl show-pipeline

# Show port statistics
rswitchctl stats [interface]

# Show MAC table
rswitchctl mac-table

# Add static MAC entry
rswitchctl mac-add <mac> <vlan> <interface>

# Delete MAC entry
rswitchctl mac-del <mac> <vlan>
```

### rsvlanctl

VLAN configuration utility.

```bash
# Show VLAN configuration
rsvlanctl show

# Add VLAN
rsvlanctl add <vlan_id> [name]

# Delete VLAN
rsvlanctl del <vlan_id>

# Add port to VLAN
rsvlanctl add-port <vlan_id> <interface> [tagged|untagged]
```

### rsaclctl

ACL management utility.

```bash
# Show ACL rules
rsaclctl show

# Add ACL rule
rsaclctl add <priority> <match> <action>

# Delete ACL rule
rsaclctl del <priority>
```

### rsqosctl

QoS configuration utility.

```bash
# Show QoS statistics
rsqosctl stats

# Show queue status
rsqosctl queues

# Set port priority
rsqosctl set-prio <interface> <priority>
```

---

## 5. Error Codes

### Module Error Codes (rs_ctx->error)

| Code | Name | Description |
|------|------|-------------|
| 0 | `RS_ERROR_NONE` | No error |
| 1 | `RS_ERROR_PARSE_FAILED` | Packet parsing failed |
| 2 | `RS_ERROR_INVALID_VLAN` | Invalid VLAN configuration |
| 3 | `RS_ERROR_ACL_DENY` | ACL denied packet |
| 4 | `RS_ERROR_NO_ROUTE` | No route to destination |
| 5 | `RS_ERROR_QUEUE_FULL` | Queue full (QoS) |
| 99 | `RS_ERROR_INTERNAL` | Internal error |

### Drop Reasons (rs_ctx->drop_reason)

| Code | Name | Description |
|------|------|-------------|
| 0 | `RS_DROP_NONE` | Not dropped |
| 1 | `RS_DROP_PARSE_ERROR` | Parse error |
| 2 | `RS_DROP_VLAN_FILTER` | VLAN filter |
| 3 | `RS_DROP_ACL_BLOCK` | ACL blocked |
| 4 | `RS_DROP_NO_FWD_ENTRY` | No forwarding entry |
| 5 | `RS_DROP_TTL_EXCEEDED` | TTL exceeded |
| 6 | `RS_DROP_RATE_LIMIT` | Rate limited |
| 7 | `RS_DROP_CONGESTION` | Congestion |

---

## 6. Best Practices

### Module Development

1. **Always check RS_GET_CTX() return value**
   ```c
   struct rs_ctx *ctx = RS_GET_CTX();
   if (!ctx) return XDP_PASS;
   ```

2. **Use offset masks for packet access**
   ```c
   struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
   ```

3. **Call RS_TAIL_CALL_NEXT at the end**
   ```c
   // Processing logic...
   RS_TAIL_CALL_NEXT(xdp, ctx);
   return XDP_PASS;  // Fallback
   ```

4. **Set ctx->action before returning**
   ```c
   if (should_drop) {
       ctx->action = XDP_DROP;
       ctx->drop_reason = RS_DROP_ACL_BLOCK;
       return XDP_DROP;
   }
   ```

### Profile Configuration

1. **Always include lastcall** as the final ingress module
2. **Always include egress_final** as the final egress module
3. **Order modules logically** - VLAN before ACL before routing
4. **Use specific VLAN lists** instead of allowing all VLANs

### Performance

1. **Minimize map lookups** - cache results in rs_ctx
2. **Use per-CPU maps** to avoid contention
3. **Batch event emission** when possible
4. **Enable zero-copy** for AF_XDP when hardware supports it

---

## 7. Version Compatibility

| API Version | rSwitch Version | Breaking Changes |
|-------------|-----------------|------------------|
| 1 | 1.0.0+ | Initial release |

Check ABI version in modules:
```c
if (desc->abi_version != RS_ABI_VERSION) {
    // Incompatible module
}
```

---

## See Also

- [Reconfigurable_Architecture.md](./Reconfigurable_Architecture.md) - Architecture overview
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) - Module development tutorial
- [Migration_Guide.md](./Migration_Guide.md) - Deployment guide
