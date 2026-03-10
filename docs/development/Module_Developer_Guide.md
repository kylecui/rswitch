# Module Developer Guide

This guide walks you through creating a custom BPF module for the rSwitch pipeline — from initial setup to production deployment. It is aligned to the source code in `bpf/modules/` and the loader in `user/loader/rswitch_loader.c`.

---

## Prerequisites

Before writing a module, you should understand:

- C programming and basic eBPF concepts
- The [Architecture](./Architecture.md) document (pipeline stages, tail-calls, per-CPU context)
- The [API Reference](./API_Reference.md) (macros, data structures, helper functions)

Build environment requirements:

- Linux kernel 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`
- clang/LLVM 10+, libbpf 0.6+, bpftool 5.8+
- See [Installation](../deployment/Installation.md) for full dependency list

---

## Quick Start: Hello World Module

### Step 1: Create the Source File

Create `bpf/modules/hello_world.bpf.c`:

```c
// SPDX-License-Identifier: GPL-2.0
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module self-registration (REQUIRED)
RS_DECLARE_MODULE(
    "hello_world",              // Name — used in YAML profiles
    RS_HOOK_XDP_INGRESS,        // Hook point
    25,                         // Stage 25 — between VLAN (20) and ACL (30)
    RS_FLAG_NEED_L2L3_PARSE,    // Requires parsed L2/L3 headers
    "Hello World example"       // Description
);

// Optional: per-CPU statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hello_stats SEC(".maps");

SEC("xdp")
int hello_world(struct xdp_md *xdp_ctx)
{
    // 1. Get shared context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    // 2. Update statistics
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&hello_stats, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    // 3. Your processing logic
    if (ctx->layers.eth_proto == bpf_htons(ETH_P_IP)) {
        rs_debug("hello_world: IPv4 packet from ifindex %u", ctx->ifindex);
    }

    // 4. Continue to next module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

    // 5. Fallback if tail-call fails
    return XDP_PASS;
}
```

### Step 2: Build

```bash
cd rswitch/
make
# Output: build/bpf/hello_world.bpf.o
```

The build system automatically discovers new `.bpf.c` files in `bpf/modules/`.

### Step 3: Add to a Profile

Create or edit a YAML profile in `etc/profiles/`:

```yaml
name: "Hello World Test"
version: "1.0"

ingress:
  - vlan
  - hello_world    # Your module (stage comes from ELF metadata)
  - acl
  - lastcall

egress:
  - egress_final
```

> **Note:** Module stages are determined solely by the `RS_DECLARE_MODULE()` macro in your BPF code. YAML profiles only list which modules to load — stage overrides are not currently supported.

### Step 4: Load and Test

```bash
sudo ./build/rswitch_loader --profile etc/profiles/hello.yaml --ifaces eth0,eth1 --verbose

# Verify the module loaded
sudo ./build/rswitchctl show-pipeline

# Check your map
sudo bpftool map dump pinned /sys/fs/bpf/hello_stats
```

---

## Module Structure in Detail

### Required Elements

Every module MUST have:

1. **License declaration**: `char _license[] SEC("license") = "GPL";`
2. **Module metadata**: `RS_DECLARE_MODULE(...)` — embeds self-description in ELF
3. **XDP entry point**: `SEC("xdp") int func_name(struct xdp_md *xdp_ctx) { ... }`
4. **Context retrieval**: `struct rs_ctx *ctx = RS_GET_CTX();` with NULL check
5. **Pipeline continuation**: `RS_TAIL_CALL_NEXT(xdp_ctx, ctx);` at the end

### RS_DECLARE_MODULE Parameters

```c
RS_DECLARE_MODULE(name, hook, stage, flags, description)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Module identifier (max 31 chars), used in YAML profiles |
| `hook` | enum | `RS_HOOK_XDP_INGRESS` or `RS_HOOK_XDP_EGRESS` |
| `stage` | u32 | Execution order: 10-99 for ingress, 100-199 for egress |
| `flags` | u32 | Capability flags (OR-combined) |
| `description` | string | Human-readable description (max 63 chars) |

### Capability Flags

| Flag | Value | When to Set |
|------|-------|-------------|
| `RS_FLAG_NEED_L2L3_PARSE` | `0x01` | Module reads L2/L3 header fields from `ctx->layers` |
| `RS_FLAG_NEED_VLAN_INFO` | `0x02` | Module reads VLAN information |
| `RS_FLAG_NEED_FLOW_INFO` | `0x04` | Module reads 5-tuple flow info (sport/dport) |
| `RS_FLAG_MODIFIES_PACKET` | `0x08` | Module may modify packet data |
| `RS_FLAG_MAY_DROP` | `0x10` | Module may drop packets |
| `RS_FLAG_CREATES_EVENTS` | `0x20` | Module emits events to the event bus |

### Stage Selection Guide

Choose a stage number based on what your module does:

| Your Module Does... | Recommended Range | Example |
|---------------------|-------------------|---------|
| Header validation / normalization | 10-19 | Pre-processing |
| VLAN processing | 20-29 | `vlan` at 20 |
| Security / filtering | 30-39 | `acl` at 30 |
| Mirroring / tapping | 40-49 | `mirror` at 40 |
| Routing / forwarding decisions | 50-69 | `route` at 50 |
| MAC learning / ARP | 80-89 | `l2learn` at 80, `afxdp_redirect` at 85 |
| Final forwarding | 90-99 | `lastcall` at 90 (always last) |
| Egress QoS | 170-179 | `egress_qos` at 170 |
| Egress VLAN tagging | 180-189 | `egress_vlan` at 180 |
| Egress final | 190-199 | `egress_final` at 190 (always last) |

---

## Working with Context

### Reading Context

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx) return XDP_DROP;

// Packet metadata
__u32 ifindex = ctx->ifindex;
__u16 eth_proto = ctx->layers.eth_proto;
__be32 src_ip = ctx->layers.saddr;
__be16 dst_port = ctx->layers.dport;

// VLAN state
__u16 vlan_id = ctx->ingress_vlan;
__u8 vlan_depth = ctx->layers.vlan_depth;

// QoS state
__u8 priority = ctx->prio;
__u8 dscp = ctx->dscp;
```

### Modifying Context

Modules update context fields to communicate decisions downstream:

```c
// Set forwarding decision
ctx->egress_ifindex = target_port;
ctx->action = XDP_REDIRECT;

// Set QoS marking
ctx->prio = 7;        // Highest priority
ctx->traffic_class = 3;

// Set VLAN for egress
ctx->egress_vlan = 200;

// Signal an error (will cause drop at lastcall)
ctx->error = RS_ERROR_ACL_DENY;
ctx->drop_reason = RS_DROP_ACL_BLOCK;
```

### Conditional Processing

Skip processing for irrelevant packets:

```c
// Only process IPv4 packets
if (ctx->layers.eth_proto != bpf_htons(ETH_P_IP)) {
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

// Only process packets on specific ports
struct rs_port_config *cfg = rs_get_port_config(ctx->ifindex);
if (!cfg || !cfg->enabled) {
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
```

---

## Custom Maps

### Defining Module-Specific Maps

```c
// Per-CPU statistics (no contention)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} my_stats SEC(".maps");

// Hash map with pinning (accessible from user-space)
struct my_key {
    __u32 src_ip;
    __u32 dst_ip;
};

struct my_value {
    __u64 packet_count;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct my_key);
    __type(value, struct my_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_flow_table SEC(".maps");
```

### Accessing Shared Maps

Core infrastructure maps are available to all modules:

```c
// Port configuration
struct rs_port_config *cfg = rs_get_port_config(ctx->ifindex);

// MAC table
struct rs_mac_entry *entry = rs_mac_lookup(dst_mac, vlan_id);

// VLAN membership
int is_tagged;
int is_member = rs_is_vlan_member(vlan_id, ctx->ifindex, &is_tagged);

// Statistics
rs_stats_update_rx(ctx, packet_bytes);
rs_stats_update_drop(ctx);
```

---

## Emitting Events

Send structured events to user-space for monitoring and debugging:

```c
struct my_event {
    __u16 type;         // Event type identifier
    __u16 len;          // Total event size
    __u32 ifindex;      // Source interface
    __be32 src_ip;      // Event-specific data
    __be32 dst_ip;
};

struct my_event evt = {
    .type = RS_EVENT_ACL_BASE + 1,  // Use appropriate event range
    .len = sizeof(evt),
    .ifindex = ctx->ifindex,
    .src_ip = ctx->layers.saddr,
    .dst_ip = ctx->layers.daddr,
};
RS_EMIT_EVENT(&evt, sizeof(evt));
```

**Best practices:**
- Events are best-effort — may drop if ring buffer is full
- Use sampling for high-frequency events (e.g., every 1000th packet)
- Include timestamps, interface indices, and CPU IDs for debugging
- Keep event structures small (< 256 bytes)

---

## BPF Verifier Compliance

The BPF verifier ensures your program is safe. Common pitfalls and solutions:

### Bounds Checking

```c
// WRONG — verifier rejects
void *data = (void *)(long)xdp_ctx->data;
struct iphdr *iph = data + ctx->layers.l3_offset;  // Unbounded offset!

// CORRECT — use offset masks
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

### Map Lookups

```c
// WRONG — null dereference
__u64 *val = bpf_map_lookup_elem(&map, &key);
*val += 1;  // Verifier error!

// CORRECT — null check first
__u64 *val = bpf_map_lookup_elem(&map, &key);
if (val)
    __sync_fetch_and_add(val, 1);
```

### Loop Bounds

```c
// WRONG — unbounded loop
for (int i = 0; i < count; i++) { ... }

// CORRECT — bounded loop with compile-time max
#pragma unroll
for (int i = 0; i < MAX_ENTRIES; i++) {
    if (i >= count) break;
    // process...
}
```

### Offset Masks Reference

| Mask | Value | Use Case |
|------|-------|----------|
| `RS_L3_OFFSET_MASK` | `0x3F` (63) | L2 header size (Ethernet + VLAN tags) |
| `RS_L4_OFFSET_MASK` | `0x7F` (127) | L2 + L3 header size |
| `RS_PAYLOAD_MASK` | `0xFF` (255) | Total header size |

---

## Packet Modification

If your module modifies packets, set `RS_FLAG_MODIFIES_PACKET` in the module declaration:

```c
RS_DECLARE_MODULE("my_modifier", RS_HOOK_XDP_INGRESS, 45,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
    "Packet modifier example");

SEC("xdp")
int my_modifier(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // Access IP header safely
    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    // Modify TTL
    __u8 old_ttl = iph->ttl;
    if (old_ttl <= 1) {
        ctx->error = RS_ERROR_INTERNAL;
        ctx->drop_reason = RS_DROP_TTL_EXCEEDED;
        return XDP_DROP;
    }
    iph->ttl = old_ttl - 1;

    // Update checksum (required after modification)
    // ... checksum update logic ...

    ctx->modified = 1;
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
```

---

## Egress Modules

Egress modules use `RS_HOOK_XDP_EGRESS` and stages 100-199:

```c
RS_DECLARE_MODULE("my_egress", RS_HOOK_XDP_EGRESS, 175,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
    "Custom egress processing");

SEC("xdp")
int my_egress(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_PASS;

    // Egress processing...

    // Use RS_TAIL_CALL_EGRESS for egress pipeline
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);
    return XDP_PASS;
}
```

Key differences from ingress modules:
- Use `RS_TAIL_CALL_EGRESS()` instead of `RS_TAIL_CALL_NEXT()`
- Egress slots are assigned descending from 255
- `rs_prog_chain` map is used for next-module lookup

---

## VOQd Integration

For modules that interact with the VOQd QoS scheduler:

```c
// Check VOQd state before processing
struct voqd_state *state = bpf_map_lookup_elem(&voqd_state_map, &key);
if (state && state->mode == VOQD_MODE_ACTIVE) {
    // Full QoS processing — redirect to AF_XDP socket
    redirect_to_voqd(ctx, xdp_ctx);
} else {
    // Fast-path — skip QoS, continue pipeline
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
}
```

VOQd modes: BYPASS (0), SHADOW (1), ACTIVE (2).

---

## Multi-Stage Modules

For complex processing that needs multiple pipeline stages:

```c
// File: bpf/modules/complex_stage1.bpf.c
RS_DECLARE_MODULE("complex_stage1", RS_HOOK_XDP_INGRESS, 35, ...);

// File: bpf/modules/complex_stage2.bpf.c
RS_DECLARE_MODULE("complex_stage2", RS_HOOK_XDP_INGRESS, 36, ...);
```

List both in the YAML profile:
```yaml
ingress:
  - vlan
  - complex_stage1
  - complex_stage2
  - lastcall
```

---

## Testing and Debugging

### Debug Logging

```c
// Only emitted when compiled with -DDEBUG
rs_debug("my_module: processed pkt ifindex=%u proto=0x%x",
         ctx->ifindex, ctx->layers.eth_proto);
```

### Inspecting Maps

```bash
# List all rSwitch maps
sudo bpftool map list | grep rs_

# Dump a specific map
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table

# Dump your custom map
sudo bpftool map dump pinned /sys/fs/bpf/my_flow_table
```

### Inspecting Programs

```bash
# List loaded programs
sudo bpftool prog list | grep rswitch

# Disassemble a program
sudo bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher

# Show program statistics
sudo bpftool prog show pinned /sys/fs/bpf/rswitch_dispatcher
```

### Pipeline Verification

```bash
# Show the current pipeline
sudo ./build/rswitchctl show-pipeline

# Show per-port statistics
sudo ./build/rswitchctl show-stats

# Monitor events
sudo ./build/rswitchctl show-events
```

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| Verifier rejection | Unbounded access, missing null check | Use offset masks, check all map lookups |
| Module not discovered | Missing `RS_DECLARE_MODULE()` | Verify the macro is present and `.bpf.o` builds cleanly |
| Tail-call failure | Stage number conflict, rs_progs full | Check for duplicate stages, verify pipeline with `show-pipeline` |
| Map not found | Unclean shutdown left stale pins | `sudo rm -rf /sys/fs/bpf/rs_*` and restart |
| Context is NULL | `rs_ctx_map` not initialized | Ensure dispatcher is loaded before your module |
| Low performance | Too many map lookups, non-CO-RE access | Cache results in context, use per-CPU maps, follow CO-RE patterns |

---

## Reference Modules

Study these existing modules as examples:

| Module | Complexity | Good Example Of |
|--------|-----------|-----------------|
| `core_example.bpf.c` | Simple | Basic module structure, CO-RE patterns |
| `vlan.bpf.c` | Medium | Context modification, VLAN processing, port config access |
| `acl.bpf.c` | Complex | Multi-map architecture, L3/L4 filtering, drop reasons |
| `l2learn.bpf.c` | Medium | MAC table updates, event emission, aging |
| `egress_qos.bpf.c` | Complex | Egress pipeline, QoS marking, VOQd integration |

All module source files are in `bpf/modules/`.

---

## See Also

- [Architecture.md](./Architecture.md) — System architecture overview
- [API_Reference.md](./API_Reference.md) — Complete API reference
- [CO-RE_Guide.md](./CO-RE_Guide.md) — Cross-kernel portability guide
- [Configuration](../deployment/Configuration.md) — YAML profile format
- **Paperwork deep-dives**: `docs/paperwork/` directory
