# Tail-Call Pipeline Architecture

## Overview

rSwitch implements a sophisticated tail-call pipeline that enables modular, stage-based packet processing. This document details how staged-based ordering maps into dynamic call-slots and the underlying mechanisms that make this system work.

## Stage-Based Ordering System

### Stage Numbering Convention

```c
// Ingress stages (10-99)
#define RS_HOOK_XDP_INGRESS     1

// Egress stages (100-199)
#define RS_HOOK_XDP_EGRESS      2

// Module stage assignments
RS_DECLARE_MODULE("vlan", RS_HOOK_XDP_INGRESS, 20, ...)
RS_DECLARE_MODULE("acl", RS_HOOK_XDP_INGRESS, 30, ...)
RS_DECLARE_MODULE("route", RS_HOOK_XDP_INGRESS, 50, ...)
RS_DECLARE_MODULE("l2learn", RS_HOOK_XDP_INGRESS, 80, ...)
RS_DECLARE_MODULE("afxdp_redirect", RS_HOOK_XDP_INGRESS, 85, ...)
RS_DECLARE_MODULE("lastcall", RS_HOOK_XDP_INGRESS, 90, ...)
```

### Stage Ordering Rules

1. **Ingress Processing**: Stages 10-99, processed in ascending order
2. **Egress Processing**: Stages 100-199, processed after ingress completion
3. **Deterministic Ordering**: Lower stage numbers execute before higher ones
4. **Gap Tolerance**: Stages don't need to be consecutive (allows future insertions)

## Dynamic Call-Slot Mapping

### Prog Array Structure

The tail-call pipeline uses a BPF program array (`rs_progs`) that maps stage numbers directly to program slots:

```c
// Maximum pipeline depth
#define RS_MAX_PROG_CHAIN 128

// Program array map
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROG_CHAIN);
    __type(key, __u32);
    __type(value, __u32);  // Program FD
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");
```

### Stage-to-Slot Mapping Algorithm

```c
// In loader: build_prog_array()
void build_prog_array(struct loader_ctx *ctx) {
    // Sort modules by stage number (ascending)
    qsort(ctx->modules, ctx->num_modules, sizeof(struct rs_module), compare_stages);

    // Map stage numbers directly to array indices
    for (int i = 0; i < ctx->num_modules; i++) {
        __u32 slot = ctx->modules[i].stage;  // Stage number = array index
        __u32 prog_fd = ctx->modules[i].prog_fd;

        // Update prog array: slot -> prog_fd
        bpf_map_update_elem(ctx->rs_progs_fd, &slot, &prog_fd, BPF_ANY);
    }
}
```

### Key Design Decisions

1. **Direct Mapping**: Stage number equals array index (stage 20 → index 20)
2. **Sparse Array**: Most indices unused, allowing flexible stage assignment
3. **Runtime Composition**: Pipeline built dynamically at load time
4. **Hot Reload**: Individual modules can be updated without rebuilding entire pipeline

## Tail-Call Execution Flow

### Pipeline Entry Point

```c
// dispatcher.bpf.c - Entry point
SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
    // Parse packet and setup context
    struct rs_ctx *rs_ctx = RS_GET_CTX();

    // Start pipeline at first stage
    RS_TAIL_CALL_FIRST(ctx, rs_ctx, RS_FIRST_STAGE);
    return XDP_PASS;  // Tail-call failed
}
```

### Module Tail-Call Macro

```c
// RS_TAIL_CALL_NEXT macro
#define RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx) \
    do { \
        __u32 next_stage = rs_ctx->next_stage; \
        if (next_stage < RS_MAX_PROG_CHAIN) { \
            bpf_tail_call(xdp_ctx, &rs_progs, next_stage); \
        } \
    } while (0)
```

### Stage Progression Logic

Each module determines the next stage:

```c
// Example: VLAN module (stage 20)
SEC("xdp")
int vlan_ingress(struct xdp_md *xdp_ctx) {
    struct rs_ctx *ctx = RS_GET_CTX();

    // Process VLAN logic...

    // Set next stage (30 = ACL)
    ctx->next_stage = 30;

    // Tail-call to next module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;  // Tail-call failed
}
```

## Pipeline Control Flow

### Normal Processing Path

```
Dispatcher (entry)
    ↓
Stage 20: VLAN processing
    ↓
Stage 30: ACL filtering
    ↓
Stage 50: Route lookup
    ↓
Stage 80: L2 learning
    ↓
Stage 85: AF_XDP redirect
    ↓
Stage 90: LastCall (forwarding)
    ↓
XDP_REDIRECT or XDP_PASS
```

### Conditional Branching

Modules can implement conditional logic:

```c
// ACL module - conditional drop
if (packet_should_drop) {
    return XDP_DROP;  // Terminate pipeline
}

// Continue to next stage
ctx->next_stage = 50;  // Route
RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
```

### Error Handling

```c
// Parse error - terminate pipeline
if (parse_failed) {
    ctx->error = RS_ERROR_PARSE_FAILED;
    return XDP_DROP;
}
```

## Performance Characteristics

### Tail-Call Overhead

- **Cost**: ~10-20ns per tail-call (negligible for networking)
- **Benefit**: Enables modular composition without function call overhead
- **Limit**: Maximum 33 tail-calls per program (Linux kernel limit)

### Pipeline Depth Optimization

- **Current Depth**: ~6-8 stages for typical configurations
- **Optimization**: Modules can skip stages by setting `next_stage` appropriately
- **Fallback**: Direct return to XDP runtime if tail-call fails

## Module Auto-Discovery Integration

### ELF Metadata Extraction

```c
// Module metadata structure
struct rs_module_desc {
    char name[32];
    __u32 hook_point;
    __u32 stage;
    __u32 flags;
    char description[128];
};

// Loader extracts from .rodata.mod section
static int read_module_metadata(struct bpf_object *obj, struct rs_module_desc *desc) {
    // Extract RS_DECLARE_MODULE data
}
```

### Dynamic Loading Sequence

1. **Discovery**: Scan BPF objects for modules
2. **Validation**: Check stage conflicts and dependencies
3. **Sorting**: Order modules by stage number
4. **Linking**: Populate prog array with stage->program mappings
5. **Attachment**: Load dispatcher and attach to interfaces

## Debugging and Observability

### Pipeline Tracing

```c
// Debug logging in each module
rs_debug("Module %s (stage %d): processing packet", MODULE_NAME, MODULE_STAGE);

// Event emission
RS_EMIT_EVENT(&trace_event, sizeof(trace_event));
```

### Pipeline Inspection

```bash
# Show loaded modules and stages
rswitchctl show-pipeline

# Inspect prog array contents
bpftool map dump pinned /sys/fs/bpf/rs_progs
```

## Future Extensions

### Conditional Pipeline Branches

```c
// Future: Conditional stage selection
if (ctx->needs_routing) {
    ctx->next_stage = 50;  // Route
} else {
    ctx->next_stage = 80;  // Skip to L2Learn
}
```

### Dynamic Stage Insertion

- Hot-pluggable modules
- Runtime pipeline reconfiguration
- A/B testing of pipeline variants

### Pipeline Metrics

- Per-stage latency tracking
- Drop statistics per module
- Pipeline throughput monitoring

## Conclusion

The tail-call pipeline architecture provides a flexible, efficient, and maintainable framework for modular packet processing. By mapping stage numbers directly to program array indices, rSwitch achieves deterministic ordering with minimal overhead while enabling dynamic composition and future extensibility.</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/paperwork/Tail-Call_Pipeline_Architecture.md