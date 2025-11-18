# Module Developer Guide

This guide shows how to author a BPF module, compile, test and include it into
a runtime profile. It is aligned to the `rswitch/bpf/modules` and loader
(`rswitch/user/loader/rswitch_loader.c`) implementation.

**IMPORTANT: This guide describes the current implementation. Module configuration comes from ELF metadata. YAML profiles currently support advanced sections (settings, voqd_config, ports, vlans) but only simple module lists - no module sub-fields or stage overrides.**

## Core Architecture Concepts

Before writing modules, understand these fundamental rSwitch concepts:

### 1. Tail-Call Pipeline Architecture

rSwitch uses a **stage-based pipeline** where modules execute in deterministic order via tail-calls:

- **Stages**: Numbered execution slots (10-99 for ingress, 100-199 for egress)
- **Tail-calls**: Efficient jumps between BPF programs using `rs_progs` program array
- **Stage mapping**: Your stage number becomes the array index
- **Pipeline flow**: `dispatcher → stage 20 → stage 30 → ... → final stage`

### 2. Per-CPU Context Management

All modules share a **per-CPU context** (`rs_ctx`) for state propagation:

```c
// Access context in every module
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx) return XDP_DROP;

// Context contains:
// - Packet metadata (ifindex, eth_proto, parsed layers)
// - Forwarding decisions (egress_ifindex, action)
// - Module state (VLAN info, QoS settings, ACL results)
// - Pipeline control (next_stage, error codes)
```

**Key Rules:**
- Use `RS_GET_CTX()` macro, never access `rs_ctx_map` directly
- Each CPU has its own context instance (no synchronization needed)
- Context persists across the entire pipeline
- Update context for downstream modules

### 3. Event Bus Architecture

Emit structured events for observability:

```c
// Use predefined event types
RS_EMIT_EVENT(&event, sizeof(event));

// Events include:
// - Packet processing events (RX/TX/drop)
// - Module-specific events (MAC learn, ACL hit, route lookup)
// - State machine events (VOQd transitions)
// - Performance events (latency samples)
```

**Best Practices:**
- Include timestamps, interface indices, CPU IDs
- Use sampling for high-frequency events
- Events are best-effort (may drop if ringbuf full)

### 4. CO-RE Portability Patterns

rSwitch uses **Compile Once - Run Everywhere** for kernel compatibility:

```c
// CO-RE safe access (REQUIRED)
__u32 len = BPF_CORE_READ(skb, len);

// Instead of direct access (breaks on kernel changes)
// __u32 len = skb->len;  // NON-CO-RE COMPLIANT
```

**CO-RE Rules:**
- Use `BPF_CORE_READ()` for kernel structure fields
- Store offsets in context for bounds checking
- Use offset masking: `offset & RS_L3_OFFSET_MASK`
- All structures must have `__attribute__((preserve_access_index))`

### 5. BPF Map Sharing Patterns

rSwitch uses three map ownership models:

**Core Infrastructure Maps** (shared across all modules):
- `rs_ctx_map`: Per-CPU context storage
- `rs_event_bus`: Unified event ringbuf
- `rs_port_config_map`: Port configuration
- `rs_stats_map`: Per-interface statistics

**Module-Owned Maps** (primary owner with extern access):
- `rs_mac_table`: MAC learning table (l2learn module)
- ACL/Route maps: Specialized multi-map architectures

**Single-Owner Maps** (no sharing):
- `rs_xdp_devmap`: XDP device map (lastcall only)

### 6. Module Auto-Discovery System

Modules are automatically discovered via ELF metadata:

```c
// Required macro in every module - THIS DEFINES THE STAGE
RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS, 35,
                  RS_FLAG_NEED_L2L3_PARSE,
                  "My custom module description");
```

**IMPORTANT: Module configuration (stages, hooks, requirements) comes from ELF metadata, NOT from YAML profiles.** The current YAML profiles only specify which modules to load by name.

**Metadata includes:**
- Module name and description
- Hook point (ingress/egress) - determines pipeline direction
- Stage number (execution order) - **this is the key ordering mechanism**
- Capability flags
- Version information

### 7. VOQd State Machine Architecture

For QoS modules, understand the VOQd state machine:

```c
enum voqd_mode {
    VOQD_MODE_BYPASS = 0,    // Fast-path only
    VOQD_MODE_SHADOW = 1,    // Observation mode
    VOQD_MODE_ACTIVE = 2,    // Full QoS processing
};
```

**State Transitions:**
- Manual: User-controlled via `rswitchctl`
- Auto-failover: On VOQd heartbeat timeout
- Overload: When ringbuf fills up
- Recovery: When VOQd restarts

## Authoring a Module

### Basic Module Structure

1. Create `rswitch/bpf/modules/my_module.bpf.c` and use the module ABI headers:
```c
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module metadata (REQUIRED)
RS_DECLARE_MODULE(
    "hello_world",                         // Module name
    RS_HOOK_XDP_INGRESS,                  // Hook point
    35,                                   // Stage (after VLAN=20, before ACL=30)
    RS_FLAG_NEED_L2L3_PARSE,              // Parse requirements
    "Hello World example module"          // Description
);

// Module-specific maps (optional)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hello_stats SEC(".maps");

// Main processing function
SEC("xdp")
int hello_world(struct xdp_md *xdp_ctx)
{
    // Get shared context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        return XDP_DROP;
    }

    // Update statistics
    __u32 key = 0;
    __u64 *stats = bpf_map_lookup_elem(&hello_stats, &key);
    if (stats) {
        __sync_fetch_and_add(stats, 1);
    }

    // Emit event (optional)
    struct rs_event_header evt = {
        .event_type = RS_EVENT_DEBUG,
        .timestamp_ns = bpf_ktime_get_ns(),
        .ifindex = ctx->ifindex,
        .cpu_id = bpf_get_smp_processor_id(),
    };
    RS_EMIT_EVENT(&evt, sizeof(evt));

    // Debug logging (optional)
    rs_debug("Hello World: processed packet on ifindex %u", ctx->ifindex);

    // Continue pipeline
    ctx->next_stage = 40;  // Next module stage
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;  // Tail-call failed
}
```

### Module Rules and Best Practices

- **Stage Assignment**: Choose appropriate stage number (see pipeline ordering)
- **Flag Usage**: Set `RS_FLAG_*` for parsing requirements and behavior
- **Error Handling**: Use `ctx->error` and `ctx->drop_reason` for failures
- **CO-RE Compliance**: Always use `BPF_CORE_READ()` for kernel structures
- **Bounds Checking**: Verify packet data access with `data_end` checks
- **Performance**: Minimize map lookups, prefer per-CPU operations
- **Testing**: Include debug prints and event emission for development

### Advanced Module Features

#### Conditional Processing

```c
// Check if module should process this packet
if (ctx->layers.eth_proto != bpf_htons(ETH_P_IP)) {
    // Skip processing for non-IP packets
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
```

#### Packet Modification

```c
// Modify packet (set RS_FLAG_MODIFIES_PACKET)
if (ctx->action == RS_ACTION_MODIFY_TTL) {
    struct iphdr *iph = get_iphdr(ctx, xdp_ctx);
    if (iph) {
        __u8 old_ttl = BPF_CORE_READ(iph, ttl);
        BPF_CORE_WRITE(iph, ttl, old_ttl - 1);
        ctx->modified = 1;
        // Update checksum...
    }
}
```

#### Custom Maps

```c
// Define module-specific maps
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
} my_custom_map SEC(".maps");
```

## Hello World Module Example

Here's a complete, runnable hello-world module:

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * rSwitch Hello World Module
 *
 * Demonstrates basic module structure, context usage,
 * statistics collection, and event emission.
 */

#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module declaration
RS_DECLARE_MODULE(
    "hello_world",
    RS_HOOK_XDP_INGRESS,
    25,  // Between VLAN (20) and ACL (30)
    RS_FLAG_NEED_L2L3_PARSE,
    "Hello World demonstration module"
);

// Per-CPU statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hello_packets_processed SEC(".maps");

// Packet counter map (shared across CPUs)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hello_total_packets SEC(".maps");

// Custom event structure
struct hello_event {
    RS_EVENT_COMMON
    __u16 eth_proto;
    __u32 packet_size;
    char message[32];
};

SEC("xdp")
int hello_world(struct xdp_md *xdp_ctx)
{
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // Get shared context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) {
        return XDP_DROP;
    }

    // Update per-CPU statistics
    __u32 key = 0;
    __u64 *per_cpu_count = bpf_map_lookup_elem(&hello_packets_processed, &key);
    if (per_cpu_count) {
        __sync_fetch_and_add(per_cpu_count, 1);
    }

    // Update global counter (with atomic operations)
    __u64 *total_count = bpf_map_lookup_elem(&hello_total_packets, &key);
    if (total_count) {
        __sync_fetch_and_add(total_count, 1);
    }

    // Calculate packet size
    __u32 packet_size = (__u32)((char *)data_end - (char *)data);

    // Emit custom event (every 1000th packet to avoid spam)
    if (total_count && (*total_count % 1000) == 0) {
        struct hello_event evt = {
            .header = {
                .event_type = RS_EVENT_DEBUG,
                .timestamp_ns = bpf_ktime_get_ns(),
                .ifindex = ctx->ifindex,
                .cpu_id = bpf_get_smp_processor_id(),
            },
            .sequence_number = *total_count,
            .eth_proto = ctx->layers.eth_proto,
            .packet_size = packet_size,
        };
        __builtin_memcpy(evt.message, "Hello from rSwitch!", 19);
        RS_EMIT_EVENT(&evt, sizeof(evt));
    }

    // Debug logging (only in debug builds)
    rs_debug("Hello World: processed packet #%llu, size=%u, proto=0x%x",
             total_count ? *total_count : 0, packet_size, ctx->layers.eth_proto);

    // Demonstrate context state usage
    if (ctx->layers.vlan_depth > 0) {
        rs_debug("Hello World: VLAN packet detected (depth=%u)",
                 ctx->layers.vlan_depth);
    }

    // Continue to next module in pipeline
    ctx->next_stage = 30;  // ACL module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

    // If tail-call fails, drop packet
    return XDP_DROP;
}
```

## Compilation and Testing

### Compilation

```bash
# Build all modules
make

# Build specific module
make bpf/modules/hello_world.o
```

### Profile Integration

1. Edit a profile file in `rswitch/etc/profiles/custom.yaml` and add your module:

**CURRENT YAML FORMAT (Simple module lists only):**
```yaml
name: "Custom Profile with Hello World"
version: "1.0"

# Simple lists - no sub-fields, stages come from ELF metadata
ingress:
  - vlan
  - hello_world    # Your new module (stage defined in ELF)
  - acl

egress:
  - egress_vlan
  - egress_final
```

**NOTE: YAML profiles currently support advanced sections (settings, voqd_config, ports, vlans) but only simple module lists. Module stages are determined solely by the `RS_DECLARE_MODULE` macro in your BPF code - YAML stage overrides are not currently supported.**

**FUTURE YAML FORMAT (Not yet implemented - stage overrides not supported):**
```yaml
# This advanced format is planned but not currently supported
modules:
  - name: "vlan"
    required: true
    stage: 20  # Would override ELF stage

  - name: "hello_world"
    required: true
    stage: 25  # Would override ELF stage
```

2. Start loader with that profile:
```bash
sudo ./build/rswitch_loader --profile etc/profiles/custom.yaml --ifaces ens34,ens35
```

### Testing and Debugging

- **Enable debug logging**: Set `RS_DEBUG_LEVEL` in your module source
- **Inspect events**: Use `rswitchctl show-events` or check ringbuf
- **Monitor maps**: Use `bpftool map dump` to inspect your custom maps
- **Performance testing**: Use `rswitchctl show-stats` for throughput metrics

### Verifier Considerations

- **Loop bounds**: Unroll loops or use bounded iterations
- **Pointer arithmetic**: Use offset masking for bounds checking
- **Map access**: Always check return values from `bpf_map_lookup_elem()`
- **CO-RE compliance**: Test on multiple kernel versions

## Advanced Topics

### Module Dependencies

For modules that depend on others:

```c
// Check if previous module processed correctly
if (ctx->parsed && ctx->layers.l3_offset) {
    // VLAN module already parsed, we can use the results
    process_based_on_vlan(ctx);
}
```

### State Machine Integration

For QoS modules integrating with VOQd:

```c
// Check VOQd state before processing
struct voqd_state *state = bpf_map_lookup_elem(&voqd_state_map, &key);
if (state && state->mode == VOQD_MODE_ACTIVE) {
    // Full QoS processing
    redirect_to_voqd(ctx, xdp_ctx);
} else {
    // Fast-path only
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
}
```

### Multi-Stage Modules

For complex processing requiring multiple stages:

```c
// Stage 1: Initial processing
RS_DECLARE_MODULE("complex_mod_stage1", RS_HOOK_XDP_INGRESS, 35, ...);

// Stage 2: Continuation processing  
RS_DECLARE_MODULE("complex_mod_stage2", RS_HOOK_XDP_INGRESS, 36, ...);
```

## Future Work: Advanced YAML Profile Support

**The current rSwitch implementation supports advanced YAML profiles with module configuration overrides.**

### Planned Features

#### 1. Module Configuration Parameters (Planned)
Support module-specific configuration parameters:
```yaml
# Future: Module configuration parameters
modules:
  - name: "acl"
    config:
      default_action: "drop"
      max_rules: 1000
```

#### 2. Optional Modules
```yaml
optional_modules:
  - name: "debug_monitor"
    enabled: true
    condition: "debug_build"
```

#### 3. Module Configuration Parameters
```yaml
modules:
  - name: "acl"
    config:
      default_action: "drop"
      max_rules: 1000
```

### Implementation Requirements

To implement these features, the following components need updates:

1. **Profile Parser** (`user/loader/profile_parser.c`):
   - Parse module sub-fields (`required`, `stage`, `config`)
   - Support `optional_modules` section
   - Validate stage conflicts between YAML and ELF

2. **Loader Logic** (`user/loader/rswitch_loader.c`):
   - Handle optional module loading
   - Validate module dependencies

3. **Module Metadata** (`bpf/core/module_abi.h`):
   - Extend `rs_module_desc` with configuration fields
   - Add dependency information

### Migration Path

When advanced YAML support is implemented:
1. Existing simple profiles will continue to work
2. New profiles can use advanced features
3. Backward compatibility maintained

## Troubleshooting

### Common Issues

1. **Verifier rejections**: Check bounds, use CO-RE macros, avoid unbounded loops
2. **Missing context**: Ensure `RS_GET_CTX()` returns valid pointer
3. **Stage conflicts**: Check for duplicate stage numbers in profile
4. **Map access failures**: Verify map pinning and permissions

### Debug Tools

```bash
# Inspect loaded modules
rswitchctl show-pipeline

# Check map contents
bpftool map dump pinned /sys/fs/bpf/rs_ctx_map

# Monitor events
bpftool map dump pinned /sys/fs/bpf/rs_event_bus

# Program inspection
bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher
```

## Useful Paths

- **Module source**: `rswitch/bpf/modules/`
- **Core headers**: `rswitch/bpf/include/`
- **Loader**: `rswitch/user/loader/rswitch_loader.c`
- **Profiles**: `rswitch/etc/profiles/`
- **Tests**: `rswitch/test/`
- **Documentation**: `rswitch/docs/paperwork/` (detailed architecture docs)

This guide covers the essential concepts and patterns for developing rSwitch modules. Refer to the paperwork documents for deep dives into specific architectures.
