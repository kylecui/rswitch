# rSwitch Map Ownership Patterns

## Overview

BPF maps in rSwitch follow two distinct ownership patterns to avoid duplicate map creation and ensure proper resource management.

## Pattern 1: Shared Pinned Maps

**Use Case**: Maps that MUST be shared across multiple BPF programs.

**Characteristics**:
- Defined in `bpf/core/uapi.h` or `bpf/core/map_defs.h`
- Use `__uint(pinning, LIBBPF_PIN_BY_NAME);`
- Auto-pinned to `/sys/fs/bpf/<map_name>` by libbpf
- Multiple modules access the SAME map instance

**Examples**:

### `rs_ctx_map` (Per-CPU Context)
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ Pinned
} rs_ctx_map SEC(".maps");
```
- **Why pinned**: Dispatcher initializes context, all modules read/modify it
- **Shared by**: dispatcher.bpf.c, vlan.bpf.c, acl.bpf.c, l2learn.bpf.c, lastcall.bpf.c

### `rs_progs` (Tail-Call Program Array)
```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ Pinned
} rs_progs SEC(".maps");
```
- **Why pinned**: Loader populates it, all modules use it for tail-calls
- **Shared by**: All modules in the tail-call chain

### `rs_port_config_map` (Port Configuration)
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct rs_port_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ Pinned
} rs_port_config_map SEC(".maps");
```
- **Why pinned**: Loader configures it, multiple modules read port settings (VLAN, ACL, QoS)
- **Shared by**: vlan.bpf.c, acl.bpf.c, l2learn.bpf.c

### `rs_vlan_map` (VLAN Membership)
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_VLANS);
    __type(key, __u16);
    __type(value, struct rs_vlan_members);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ Pinned
} rs_vlan_map SEC(".maps");
```
- **Why pinned**: Loader initializes VLAN config, VLAN module validates membership
- **Shared by**: vlan.bpf.c, egress_vlan.bpf.c

### `rs_mac_table` (MAC Forwarding Table)
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ Pinned
} rs_mac_table SEC(".maps");
```
- **Why pinned**: L2learn writes, lastcall reads for unicast forwarding
- **Shared by**: l2learn.bpf.c, lastcall.bpf.c

### `rs_stats_map` (Per-Interface Statistics)
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ Pinned
} rs_stats_map SEC(".maps");
```
- **Why pinned**: Multiple modules update stats, user-space reads for telemetry
- **Shared by**: All modules, user-space telemetry tools

## Pattern 2: Single Owner Maps

**Use Case**: Maps used by ONLY ONE module, no cross-module sharing needed.

**Characteristics**:
- Defined in the owning module's `.bpf.c` file
- **NO** `pinning` directive
- Loader accesses via `bpf_object__find_map_by_name(module_obj, "map_name")`
- Only ONE instance created

**Examples**:

### `rs_xdp_devmap` (Egress Redirect Map)
```c
// Defined in: bpf/modules/lastcall.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
    // NO pinning - single owner
} rs_xdp_devmap SEC(".maps");
```
- **Why NOT pinned**: Only lastcall uses it for final packet redirection
- **Loader access**:
  ```c
  for (i = 0; i < ctx->num_modules; i++) {
      if (strcmp(ctx->modules[i].name, "lastcall") == 0) {
          map = bpf_object__find_map_by_name(ctx->modules[i].obj, "rs_xdp_devmap");
          xdp_devmap_fd = bpf_map__fd(map);
      }
  }
  ```

### `rs_events` (L2Learn MAC Learning Ringbuf)
```c
// Defined in: bpf/modules/l2learn.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    // NO pinning - single owner
} rs_events SEC(".maps");
```
- **Why NOT pinned**: Only l2learn emits MAC learning events
- **Loader access**:
  ```c
  for (i = 0; i < ctx->num_modules; i++) {
      if (strcmp(ctx->modules[i].name, "l2learn") == 0) {
          map = bpf_object__find_map_by_name(ctx->modules[i].obj, "rs_events");
          rs_events_fd = bpf_map__fd(map);
      }
  }
  ```

### `voq_ringbuf` (AF_XDP VOQ Metadata)
```c
// Defined in: bpf/modules/afxdp_redirect.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
    // NO pinning - single owner
} voq_ringbuf SEC(".maps");
```
- **Why NOT pinned**: Only afxdp_redirect module uses it for VOQ telemetry
- **Purpose**: Separate from rs_events to avoid mixing L2 learning and VOQ metadata

## Decision Tree: Pinned or Not?

```
Is the map accessed by multiple BPF programs?
│
├─ YES → Use Shared Pinned Map Pattern
│         - Define in uapi.h or map_defs.h
│         - Add __uint(pinning, LIBBPF_PIN_BY_NAME);
│         - Examples: rs_ctx_map, rs_progs, rs_mac_table
│
└─ NO  → Use Single Owner Pattern
          - Define in module's .bpf.c file
          - NO pinning directive
          - Loader accesses via module object
          - Examples: rs_xdp_devmap, rs_events, voq_ringbuf
```

## Common Mistakes

### ❌ Mistake 1: Defining single-owner map in uapi.h without pinning
```c
// In uapi.h - BAD!
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    // NO pinning
} rs_events SEC(".maps");
```
**Problem**: Every module including `uapi.h` creates its own `rs_events` instance!

**Solution**: Move to single owner module OR add pinning.

### ❌ Mistake 2: Pinning a map that only one module uses
```c
// In lastcall.bpf.c - Unnecessary!
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Not needed
} rs_xdp_devmap SEC(".maps");
```
**Problem**: Creates unnecessary BPF filesystem clutter, adds complexity.

**Solution**: Remove pinning if truly single owner.

### ❌ Mistake 3: Trying to share unpinned map across modules
```c
// In module_a.bpf.c
struct { ... } shared_map SEC(".maps");  // No pinning

// In module_b.bpf.c
#include "module_a_header.h"  // Oops, creates separate instance!
```
**Problem**: Each module gets its own map, data not shared.

**Solution**: Add pinning OR redesign ownership.

## Testing Map Instances

### Before Running Loader
```bash
sudo bpftool map show | grep rs_
# Should show nothing (clean state)
```

### After Loading (dumb.yaml - no l2learn)
```bash
sudo bpftool map show | grep rs_
# Should show:
# - rs_ctx_map (pinned)
# - rs_progs (pinned)
# - rs_port_config_map (pinned)
# - rs_vlan_map (pinned)
# - rs_mac_table (pinned)
# - rs_stats_map (pinned)
# - rs_xdp_devmap (NOT pinned, won't show via bpftool map show)
# - NO rs_events (not loaded with dumb profile)
```

### After Loading (l2.yaml - includes l2learn)
```bash
sudo bpftool map show | grep -E 'rs_|voq_'
# Additional map:
# - rs_events (NOT pinned, owned by l2learn)
```

### Check for Duplicates
```bash
# This should show ONLY ONE instance of each map
sudo bpftool map show | awk '{print $4}' | sort | uniq -c | grep -v "^   1"
# Empty output = no duplicates ✓
```

## Summary

| Pattern | When to Use | Pinning | Example |
|---------|-------------|---------|---------|
| **Shared Pinned** | Multiple modules access | ✓ Yes | `rs_ctx_map`, `rs_progs`, `rs_mac_table` |
| **Single Owner** | Only one module uses | ✗ No | `rs_xdp_devmap`, `rs_events`, `voq_ringbuf` |

**Golden Rule**: Pin if and only if multiple BPF programs need to access the same map instance. Otherwise, keep it local to avoid complexity and prevent duplicate creation.

## Future Considerations

### Shared Event Bus (Future)

If we later decide to create a unified event channel for multiple modules:

```c
// In uapi.h
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ✓ NOW pinned
} rs_unified_events SEC(".maps");
```

Modules would share with event type discrimination:
- `RS_EVENT_MAC_LEARN` (from l2learn)
- `RS_EVENT_ACL_DENY` (from acl)
- `RS_EVENT_ROUTE_MISS` (from route)
- `RS_EVENT_CONGESTION` (from afxdp_redirect)

User-space would consume one ringbuf and demux by event type.

**But**: Only do this when we ACTUALLY have multiple event producers. Current state (only l2learn) doesn't justify the complexity.
