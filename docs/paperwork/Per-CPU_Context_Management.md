# Per-CPU Context Management

## Overview

rSwitch implements a sophisticated per-CPU context management system that enables efficient sharing of packet state across the entire BPF pipeline. This document details the `rs_ctx` structure, CO-RE safe access patterns, and the memory management strategies that make this system work.

## rs_ctx Structure Design

### Core Context Structure

```c
// uapi.h - Shared kernel-user context
struct rs_ctx {
    // Packet metadata
    __u32 ifindex;                    // Ingress interface index
    __u16 eth_proto;                  // Ethernet protocol (host byte order)
    __u8  pkt_type;                   // Packet type classification

    // Parsing state
    __u8  parsed;                     // Packet successfully parsed
    __u8  modified;                   // Packet modified by modules
    __u16 error;                      // Error code if processing failed

    // Layer information
    struct rs_layers layers;          // Parsed header information

    // Forwarding decisions
    __u32 egress_ifindex;             // Target egress interface
    __u32 action;                     // XDP action (PASS/DROP/REDIRECT)

    // VLAN processing
    __u16 ingress_vlan;               // VLAN packet arrived on
    __u8  vlan_action;                // VLAN processing result

    // QoS classification
    __u8  prio;                       // Priority level (0-7)
    __u8  ecn;                        // ECN marking (0x00=normal, 0x03=CE)

    // ACL results
    __u8  acl_action;                 // ACL action taken
    __u16 acl_rule_id;                // Matching ACL rule ID

    // Pipeline control
    __u32 next_stage;                 // Next pipeline stage
    __u32 drop_reason;                // Reason for dropping packet

    // Mirror/SPAN
    __u8  mirror;                     // Packet should be mirrored

    // Statistics
    __u64 timestamp_ns;               // Packet arrival timestamp
};
```

### Layer Information Structure

```c
struct rs_layers {
    // Ethernet
    struct ethhdr eth;

    // VLAN (QinQ support)
    __u8  vlan_depth;                 // Number of VLAN tags (0-2)
    __u16 vlan_ids[RS_MAX_VLAN_DEPTH]; // VLAN IDs
    __u8  vlan_pcp[RS_MAX_VLAN_DEPTH]; // Priority Code Points

    // IPv4/IPv6
    __u8  ip_proto;                   // IP protocol (TCP/UDP/ICMP)
    __u32 saddr;                      // Source IP (network byte order)
    __u32 daddr;                      // Destination IP (network byte order)

    // Transport
    __u16 sport;                      // Source port (network byte order)
    __u16 dport;                      // Destination port (network byte order)

    // Offsets for CO-RE safety
    __u16 l2_offset;                  // Ethernet header offset
    __u16 l3_offset;                  // IP header offset
    __u16 l4_offset;                  // Transport header offset
};
```

## Per-CPU Map Architecture

### Context Map Definition

```c
// Shared per-CPU context map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");
```

### CO-RE Safe Access Macros

```c
// RS_GET_CTX macro - Safe per-CPU context access
#define RS_GET_CTX() \
    ({ \
        __u32 key = 0; \
        struct rs_ctx *ctx = bpf_map_lookup_elem(&rs_ctx_map, &key); \
        if (!ctx) { \
            bpf_printk("Failed to get rs_ctx"); \
            return XDP_DROP; \
        } \
        ctx; \
    })
```

### Context Initialization

```c
// Dispatcher context setup
static __always_inline void init_rs_ctx(struct rs_ctx *ctx,
                                        struct xdp_md *xdp_ctx,
                                        __u32 ifindex) {
    // Zero the entire context
    memset(ctx, 0, sizeof(*ctx));

    // Basic metadata
    ctx->ifindex = ifindex;
    ctx->timestamp_ns = bpf_ktime_get_ns();
    ctx->parsed = 0;
    ctx->modified = 0;
    ctx->error = 0;

    // Default forwarding (flood)
    ctx->egress_ifindex = RS_FLOOD_IFINDEX;
    ctx->action = XDP_PASS;

    // Default QoS
    ctx->prio = 0;
    ctx->ecn = 0;

    // Pipeline starts at first stage
    ctx->next_stage = RS_FIRST_STAGE;
}
```

## Memory Layout and Alignment

### Per-CPU Memory Characteristics

- **Isolation**: Each CPU has its own context instance
- **Cache**: Context stays in CPU cache during pipeline execution
- **Size**: ~256 bytes per CPU (minimal memory footprint)
- **Alignment**: 8-byte aligned for optimal access

### Memory Access Patterns

```c
// Efficient field access (compiler optimizes)
ctx->layers.eth_proto = bpf_ntohs(eth->h_proto);
ctx->layers.saddr = iph->saddr;  // Already network byte order
ctx->layers.dport = udp->dest;   // Network byte order

// Bulk operations for performance
memcpy(&ctx->layers.eth, eth, sizeof(*eth));

// Conditional updates
if (ctx->layers.vlan_depth > 0) {
    ctx->prio = extract_pcp(ctx);
}
```

## Pipeline State Propagation

### Context Passing Between Modules

```c
// Module A (VLAN processing)
SEC("xdp")
int vlan_process(struct xdp_md *xdp_ctx) {
    struct rs_ctx *ctx = RS_GET_CTX();

    // Read current state
    __u16 vlan_id = ctx->layers.vlan_ids[0];

    // Update context
    ctx->ingress_vlan = vlan_id;
    ctx->prio = extract_pcp_from_vlan(vlan_id);

    // Set next stage
    ctx->next_stage = 30;  // ACL

    // Continue pipeline
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}

// Module B (ACL processing)
SEC("xdp")
int acl_process(struct xdp_md *xdp_ctx) {
    struct rs_ctx *ctx = RS_GET_CTX();

    // Context state preserved from VLAN module
    __u16 vlan_id = ctx->ingress_vlan;  // Still available
    __u8 prio = ctx->prio;              // Priority set by VLAN

    // ACL processing using accumulated state
    if (check_acl_rules(ctx)) {
        ctx->acl_action = ACL_ACTION_DROP;
        return XDP_DROP;
    }

    // Continue with updated context
    ctx->next_stage = 80;  // L2Learn
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
```

### State Accumulation Pattern

```c
// Progressive state building
void accumulate_packet_state(struct rs_ctx *ctx, struct xdp_md *xdp_ctx) {
    // Stage 1: Basic parsing
    parse_ethernet(ctx, xdp_ctx);

    // Stage 2: VLAN processing (builds on stage 1)
    if (ctx->parsed) {
        process_vlan(ctx, xdp_ctx);
    }

    // Stage 3: IP processing (builds on stages 1-2)
    if (ctx->parsed && ctx->layers.l3_offset) {
        parse_ip(ctx, xdp_ctx);
    }

    // Stage 4: QoS classification (uses all previous state)
    classify_qos(ctx);
}
```

## Error Handling and Recovery

### Error Propagation

```c
// Error codes
enum rs_error {
    RS_ERROR_NONE = 0,
    RS_ERROR_PARSE_FAILED = 1,
    RS_ERROR_INVALID_VLAN = 2,
    RS_ERROR_NO_ROUTE = 3,
    RS_ERROR_ACL_BLOCK = 4,
};

// Error handling pattern
static __always_inline void set_error(struct rs_ctx *ctx,
                                      enum rs_error error,
                                      enum rs_drop_reason reason) {
    ctx->error = error;
    ctx->drop_reason = reason;
    ctx->action = XDP_DROP;
}
```

### Context Validation

```c
// Validate context state between modules
static __always_inline int validate_context(struct rs_ctx *ctx) {
    // Check for previous errors
    if (ctx->error != RS_ERROR_NONE) {
        return -1;
    }

    // Validate parsing state
    if (!ctx->parsed) {
        set_error(ctx, RS_ERROR_PARSE_FAILED, RS_DROP_PARSE_ERROR);
        return -1;
    }

    // Validate forwarding decision
    if (ctx->egress_ifindex == 0 && ctx->action == XDP_REDIRECT) {
        set_error(ctx, RS_ERROR_INVALID_FWD, RS_DROP_NO_FWD_ENTRY);
        return -1;
    }

    return 0;
}
```

## Performance Optimizations

### Cache-Friendly Access Patterns

```c
// Group related fields for cache efficiency
struct rs_forwarding_state {
    __u32 egress_ifindex;
    __u32 action;
    __u8  mirror;
    __u8  pad[3];
} __attribute__((packed));

// Access patterns that maximize cache hits
void process_forwarding(struct rs_ctx *ctx) {
    // Read forwarding state (cache line 1)
    __u32 egress = ctx->egress_ifindex;
    __u32 action = ctx->action;

    // Process QoS state (cache line 2)
    __u8 prio = ctx->prio;
    __u8 ecn = ctx->ecn;

    // Update statistics (cache line 3)
    ctx->stats.packets_processed++;
}
```

### Memory Prefetching

```c
// Prefetch context for next CPU (if available)
// Note: eBPF doesn't have explicit prefetch, but compiler hints help
__attribute__((always_inline))
struct rs_ctx *get_prefetched_ctx(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&rs_ctx_map, &key);
}
```

## CO-RE Compatibility

### Offset-Based Access

```c
// CO-RE safe header access using stored offsets
static __always_inline struct ethhdr *get_eth_header(struct rs_ctx *ctx,
                                                     void *data, void *data_end) {
    __u16 offset = ctx->layers.l2_offset & RS_L2_OFFSET_MASK;

    if ((void *)((char *)data + offset + sizeof(struct ethhdr)) > data_end)
        return NULL;

    return (struct ethhdr *)((char *)data + offset);
}

// Update offset during parsing
void parse_ethernet(struct rs_ctx *ctx, struct xdp_md *xdp_ctx) {
    ctx->layers.l2_offset = 0;  // Ethernet always at offset 0
    ctx->layers.eth_proto = bpf_ntohs(ctx->layers.eth.h_proto);
}
```

### Bounds Checking

```c
// Comprehensive bounds checking for CO-RE safety
#define CHECK_BOUNDS(ptr, size, data_end) \
    ((void *)((char *)(ptr) + (size)) <= (data_end))

// Safe header access with bounds checking
struct iphdr *get_ip_header(struct rs_ctx *ctx, void *data, void *data_end) {
    if (!ctx->layers.l3_offset)
        return NULL;

    struct iphdr *iph = (struct iphdr *)((char *)data + ctx->layers.l3_offset);
    if (!CHECK_BOUNDS(iph, sizeof(*iph), data_end))
        return NULL;

    return iph;
}
```

## Debugging and Observability

### Context Dumping

```c
// Debug function to dump context state
void dump_rs_ctx(struct rs_ctx *ctx) {
    bpf_printk("rs_ctx: ifindex=%u, parsed=%d, error=%d",
               ctx->ifindex, ctx->parsed, ctx->error);
    bpf_printk("  eth_proto=0x%x, ip_proto=%u", ctx->layers.eth_proto, ctx->layers.ip_proto);
    bpf_printk("  saddr=%pI4, daddr=%pI4", &ctx->layers.saddr, &ctx->layers.daddr);
    bpf_printk("  sport=%u, dport=%u", bpf_ntohs(ctx->layers.sport), bpf_ntohs(ctx->layers.dport));
    bpf_printk("  egress_ifindex=%u, action=%u", ctx->egress_ifindex, ctx->action);
    bpf_printk("  prio=%u, ecn=%u", ctx->prio, ctx->ecn);
}
```

### Context Tracing Events

```c
// Emit context state to ringbuf for analysis
struct rs_ctx_trace_event {
    __u32 ifindex;
    __u16 eth_proto;
    __u8  prio;
    __u8  ecn;
    __u32 egress_ifindex;
    __u32 action;
    __u16 error;
    __u16 drop_reason;
};

void emit_ctx_trace(struct rs_ctx *ctx) {
    struct rs_ctx_trace_event evt = {
        .ifindex = ctx->ifindex,
        .eth_proto = ctx->layers.eth_proto,
        .prio = ctx->prio,
        .ecn = ctx->ecn,
        .egress_ifindex = ctx->egress_ifindex,
        .action = ctx->action,
        .error = ctx->error,
        .drop_reason = ctx->drop_reason,
    };

    RS_EMIT_EVENT(&evt, sizeof(evt));
}
```

## Memory Management Considerations

### Context Lifetime

- **Per-Packet**: Context created at dispatcher entry
- **Pipeline Scope**: Valid throughout entire BPF pipeline execution
- **CPU Local**: Never shared between CPUs
- **Automatic Cleanup**: Freed when packet processing completes

### Memory Pressure

```c
// Monitor context map usage
static void check_memory_pressure(void) {
    // Per-CPU arrays don't have lookup pressure issues
    // But we can monitor via debug events
    __u64 mem_pressure = bpf_ktime_get_ns();
    RS_EMIT_EVENT(&mem_pressure, sizeof(mem_pressure));
}
```

## Future Enhancements

### Extended Context Fields

```c
// Future: Extended context for advanced features
struct rs_ctx_extended {
    struct rs_ctx base;

    // MPLS support
    __u32 mpls_labels[RS_MAX_MPLS_LABELS];
    __u8  mpls_depth;

    // IPv6 support
    struct in6_addr saddr6;
    struct in6_addr daddr6;

    // GTP/overlay support
    __u32 tunnel_id;
    __u8  tunnel_type;

    // Custom metadata
    __u8  custom_data[RS_CUSTOM_DATA_SIZE];
};
```

### Context Compression

```c
// Future: Context compression for memory efficiency
struct rs_ctx_compressed {
    __u32 flags;        // Bitfield indicating which fields are set
    __u32 data[8];      // Compressed field storage

    // Accessor functions
        __u32 data[8];      // Compressed field storage

    // Accessor functions
    __u32 get_ifindex(struct rs_ctx_compressed *ctx);
    void set_ifindex(struct rs_ctx_compressed *ctx, __u32 ifindex);
}
```

## Ownership and Developer Usage

### Map Ownership

**rs_ctx_map Ownership:**
- **Owned and initialized by dispatcher**: Yes, the `rs_ctx_map` is owned and initialized by the dispatcher in `bpf/core/dispatcher.bpf.c`. The `rswitch_dispatcher()` function looks up the per-CPU context slot using `bpf_map_lookup_elem(&rs_ctx_map, &key)` and initializes it with `init_context()`, setting up packet metadata, parsing state, and forwarding decisions.
- **Per-packet initialization**: Each packet gets a fresh context initialized at the start of processing, ensuring clean state propagation through the pipeline.
- **Infrastructure management**: The loader (`rswitch_loader.c`) handles pinning to `/sys/fs/bpf/rs_ctx_map` for persistence and cross-program access.

### Developer Attention in Customized Modules

**Critical considerations for module developers:**
- **Use RS_GET_CTX() macro**: Always access the context via the `RS_GET_CTX()` macro for safe per-CPU retrieval. Never access the map directly.
- **State accumulation awareness**: Read accumulated parsing and processing state from previous pipeline stages and update context fields appropriately for subsequent modules.
- **Context validation**: Validate context state between pipeline stages using checks for `ctx->parsed`, `ctx->error`, and other relevant fields.
- **CPU-local semantics**: Remember that context is CPU-local - each CPU processes its own packets independently with separate context instances.
- **Error propagation**: Use `ctx->error` and `ctx->drop_reason` for proper error handling and pipeline termination.
- **Performance implications**: Context access is fast (per-CPU), but avoid redundant field updates and ensure efficient memory layout usage.

### Integration with Other Core Maps

The context map integrates closely with other core infrastructure:
- **rs_event_bus**: Context provides rich metadata for event emission
- **rs_stats_map**: Context drives statistical counter updates
- **rs_port_config_map**: Port configuration influences context initialization
- **rs_progs**: Context state determines tail-call progression

### Debugging Context Issues

```c
// Validate context state
static __always_inline int validate_rs_ctx(struct rs_ctx *ctx) {
    if (!ctx) {
        rs_debug("CRITICAL: NULL rs_ctx");
        return -1;
    }
    
    if (ctx->error != RS_ERROR_NONE) {
        rs_debug("Context has error %u, reason %u", ctx->error, ctx->drop_reason);
        return -1;
    }
    
    return 0;
}
```

```bash
// Monitor context usage
bpftool map show pinned /sys/fs/bpf/rs_ctx_map
bpftool map dump pinned /sys/fs/bpf/rs_ctx_map  # Shows per-CPU context contents
```


## Conclusion

The per-CPU context management system provides a robust, efficient, and CO-RE compatible mechanism for sharing packet state across the entire BPF pipeline. By leveraging per-CPU maps and careful memory layout, rSwitch achieves high performance while maintaining strict safety guarantees and observability.</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/paperwork/Per-CPU_Context_Management.md