# rSwitch Core Headers

This directory contains the core header files that define the rSwitch plugin architecture and shared data structures.

## Header Files

### Module Development

- **`module_abi.h`** - Module plugin interface
  - `RS_DECLARE_MODULE()` macro for module metadata
  - `rs_module_desc` structure embedded in `.rodata.mod` section
  - Stage number conventions and capability flags
  - **Include this**: When creating a new module

- **`uapi.h`** - Unified kernel/user API
  - `rs_ctx` - Per-packet processing context
  - `rs_layers` - Parsed packet layer information
  - Core BPF maps (`rs_ctx_map`, `rs_progs`, `rs_events`)
  - Event types and helper macros
  - **Include this**: For context access and tail-call operations

- **`map_defs.h`** - Common map definitions
  - Port configuration (`rs_port_config_map`)
  - MAC forwarding table (`rs_mac_table`)
  - VLAN membership (`rs_vlan_map`)
  - Statistics counters (`rs_stats_map`)
  - Helper functions for map operations
  - **Include this**: When accessing shared state

### Convenience Headers

- **`../include/rswitch_common.h`** - All-in-one include
  - Includes all core headers plus kernel headers
  - Common macros and utilities
  - **Recommended**: Include this in your modules for everything

- **`../include/parsing_helpers.h`** - Packet parsing utilities
  - Copied from PoC (`src/inc/parsing_helpers.h`)
  - Layer parsing functions
  - **Include via**: `rswitch_common.h`

## Module Development Quick Reference

### Minimal Module Template

```c
#include "rswitch_common.h"

RS_DECLARE_MODULE("mymodule", RS_HOOK_XDP_INGRESS, 35, 
                  RS_FLAG_NEED_L2L3_PARSE, 
                  "My custom module description");

SEC("xdp")
int mymodule_ingress(struct xdp_md *ctx) {
    struct rs_ctx *rctx = RS_GET_CTX();
    if (!rctx)
        return XDP_DROP;
    
    // Your logic here
    rs_debug("Processing packet on port %u", rctx->ifindex);
    
    // Continue to next module
    RS_TAIL_CALL_NEXT(rctx, rctx->next_prog_id);
    
    return XDP_PASS; // Fallback if tail-call fails
}

char _license[] SEC("license") = "GPL";
```

### Context Access Pattern

```c
// Get shared context
struct rs_ctx *rctx = RS_GET_CTX();
if (!rctx)
    return XDP_DROP;

// Access parsed layers
if (rctx->parsed) {
    __u16 vlan = rctx->layers.vlan_ids[0];
    __be32 sip = rctx->layers.saddr;
}

// Update forwarding decision
rctx->egress_ifindex = target_port;
rctx->action = XDP_REDIRECT;

// Set error if needed
if (error_condition) {
    rctx->error = RS_ERROR_ACL_DENY;
    rctx->drop_reason = RS_DROP_ACL_BLOCK;
    return XDP_DROP;
}
```

### Map Access Pattern

```c
// Get port configuration
struct rs_port_config *cfg = rs_get_port_config(rctx->ifindex);
if (!cfg)
    return XDP_DROP;

// Lookup MAC entry
struct rs_mac_entry *entry = rs_mac_lookup(dmac, vlan);
if (entry) {
    rctx->egress_ifindex = entry->ifindex;
}

// Update statistics
rs_stats_update_rx(rctx, packet_len);
```

### Event Emission Pattern

```c
// Emit MAC learning event
struct rs_event_mac_learn learn = {
    .vlan = vlan_id,
    .port = rctx->ifindex,
};
__builtin_memcpy(learn.mac, smac, 6);

RS_EMIT_EVENT(RS_EVENT_MAC_LEARN, &learn, sizeof(learn));
```

## ABI Versioning

Current ABI version: **1**

Breaking changes require incrementing `RS_ABI_VERSION` in `module_abi.h`.
The loader checks module ABI compatibility during discovery.

## Stage Number Guidelines

**Ingress Pipeline** (ascending order):
- 10-19: Pre-processing
- 20-29: VLAN processing ← **vlan.bpf.c = 20**
- 30-39: Access control ← **acl.bpf.c = 30**
- 40-49: Routing ← **route.bpf.c = 40**
- 50-69: QoS marking
- 70-79: Mirroring ← **mirror.bpf.c = 70**
- 80-89: Learning ← **l2learn.bpf.c = 80**
- 90-99: Final decision ← **lastcall.bpf.c = 90**

**Egress Pipeline**:
- 20-29: VLAN tagging
- 30-49: QoS enforcement
- 70-89: Telemetry

## Total Lines of Code

Core headers: **545 lines** (excluding parsing_helpers.h)
