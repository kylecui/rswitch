# BPF Map Sharing Patterns

## Overview

rSwitch implements sophisticated BPF map sharing patterns to enable efficient data sharing between modules while maintaining strict ownership semantics. This document details the map ownership model, sharing mechanisms, pinning strategies, and synchronization patterns used throughout the system.

## Map Ownership Model

### Actual Implementation Patterns

Based on code analysis, rSwitch uses three concrete map ownership patterns rather than the conceptual enum model:

1. **Core Infrastructure Maps**: Defined in core files (`uapi.h`, `map_defs.h`), shared across all modules and user-space
2. **Module-Owned Maps**: Defined in specific modules but accessible via extern declarations
3. **Single-Owner Maps**: Used exclusively within one module, no sharing

### Core Infrastructure Maps

These maps provide shared infrastructure and are defined in core header files:

## Core Maps

### Dispatcher-Owned Maps

```c
// rs_ctx_map - Per-CPU context storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

/* Ownership: CORE (dispatcher)
 * Access: All modules (read/write via RS_GET_CTX)
 * Pinning: Named pinning for persistence
 * Synchronization: Per-CPU (no locks needed)
 */

// rs_progs - Tail-call program array
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROG_CHAIN);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

/* Ownership: CORE (dispatcher)
 * Access: Dispatcher only (write), modules read via tail-call
 * Pinning: Named pinning for loader access
 * Synchronization: Atomic updates during loading
 */
```

### Core Infrastructure Maps

These maps are defined in core files and provide shared infrastructure:

```c
// rs_ctx_map - Per-CPU context storage (uapi.h)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_ctx_map SEC(".maps");

/* Access: All modules (read/write via RS_GET_CTX)
 * Pinning: Named pinning for persistence
 * Synchronization: Per-CPU (no locks needed)
 */

// rs_progs - Tail-call program array (uapi.h)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, RS_MAX_PROGS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_progs SEC(".maps");

/* Access: Dispatcher writes, modules read via tail-call
 * Pinning: Named pinning for loader access
 * Synchronization: Atomic updates during loading
 */

// rs_event_bus - Unified event ringbuf (uapi.h)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 1MB ring */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");

/* Access: All modules write events, user-space reads
 * Pinning: Named pinning for event collection
 * Synchronization: Ringbuf atomic operations
 */

// rs_port_config_map - Port configuration (map_defs.h)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct rs_port_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_port_config_map SEC(".maps");

/* Access: User-space writes configuration, all modules read
 * Pinning: Named pinning for cross-program access
 * Synchronization: Configuration updates via user-space
 */

// rs_stats_map - Per-interface statistics (map_defs.h)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct rs_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_stats_map SEC(".maps");

/* Access: Modules update counters, user-space reads telemetry
 * Pinning: Named pinning for monitoring
 * Synchronization: Per-CPU atomic operations
 */
```

## Key Maps Analysis: rs_ctx_map and rs_event_bus

### rs_ctx_map (Per-CPU Context Management)

**Ownership and Initialization:**
- **Dispatcher-owned and initialized**: The `rs_ctx_map` is owned and initialized by the dispatcher in `bpf/core/dispatcher.bpf.c`. The `rswitch_dispatcher()` function performs per-packet initialization using `bpf_map_lookup_elem(&rs_ctx_map, &key)` followed by `init_context()`.
- **Per-packet lifecycle**: Each packet gets a fresh context instance, ensuring clean state propagation through the pipeline.
- **Infrastructure management**: Loader handles pinning to `/sys/fs/bpf/rs_ctx_map` for persistence and cross-program access.

**Developer Usage in Modules:**
- **Critical attention required**: Modules must use `RS_GET_CTX()` macro for safe per-CPU access. Never access the map directly.
- **State management**: Read accumulated state from previous stages, update for subsequent modules, validate context integrity.
- **CPU-local semantics**: Each CPU has independent context instances - no cross-CPU sharing or synchronization needed.
- **Error handling**: Use `ctx->error` and `ctx->drop_reason` for proper pipeline error propagation.
- **Performance**: Fast per-CPU access, but minimize redundant updates and ensure efficient field usage.

### rs_event_bus (Event Bus Architecture)

**Ownership and Initialization:**
- **Not dispatcher-owned**: The `rs_event_bus` is a core infrastructure ringbuf defined in `uapi.h`, created once during BPF loading, not per-packet.
- **Infrastructure ownership**: Managed by loader (`rswitch_loader.c`) with pinning to `/sys/fs/bpf/rs_event_bus`.
- **User-space integration**: Consumed by `event_consumer.c` for real-time event processing and monitoring.

**Developer Usage in Modules:**
- **Moderate attention required**: Use `RS_EMIT_EVENT()` macro for type-safe emission, follow predefined event types and structures.
- **Metadata requirements**: Include proper event headers with timestamps, interface indices, and CPU IDs.
- **Sampling awareness**: Consider rate limiting for high-frequency events to avoid ringbuf overflow.
- **Best-effort delivery**: Events may drop if ringbuf full - modules must function without guaranteed delivery.
- **Performance impact**: ~50-200ns overhead per emission - use judiciously in performance-critical paths.

### Integration Between Key Maps

The `rs_ctx_map` and `rs_event_bus` work together closely:
- **Context-driven events**: `rs_ctx_map` provides rich packet metadata for comprehensive event emission to `rs_event_bus`
- **Observability pipeline**: Context state enables detailed event generation for monitoring and debugging
- **Performance balance**: Context provides fast per-CPU access, events enable asynchronous user-space visibility

### Other Key Maps Similar to rs_ctx_map and rs_event_bus

Based on the BPF map sharing patterns, here are other core infrastructure maps that follow similar patterns:

**Core Infrastructure Maps (Shared Across All Components):**
- `rs_progs`: Tail-call program array (dispatcher-owned, modules read via tail-call)
- `rs_port_config_map`: Port configuration hash map (user-space writes, all modules read)
- `rs_stats_map`: Per-interface statistics per-CPU array (modules update counters, user-space reads)
- `rs_vlan_map`: VLAN configuration (likely core infrastructure based on pinning patterns)

**Module-Owned Maps (Primary ownership with extern access):**
- `rs_mac_table`: MAC address learning table (owned by l2learn module, accessible to others)

**Single-Owner Maps (No sharing):**
- `rs_xdp_devmap`: XDP device map (owned exclusively by lastcall module)

These maps follow the same patterns of named pinning (`LIBBPF_PIN_BY_NAME`) for persistence and cross-program access, with clear ownership semantics to prevent conflicts. The core infrastructure maps like `rs_ctx_map` and `rs_event_bus` are particularly critical as they enable the fundamental pipeline operation and observability.

*Note: Some maps mentioned in planning documents (rs_acl_table, rs_route_table) are implemented in the current codebase. The ACL and ROUTE modules use sophisticated multi-map architectures optimized for their specific use cases.*

## Actual ACL and ROUTE Module Implementations

Rather than using single monolithic tables, the ACL and ROUTE modules implement advanced multi-map architectures:

### ACL Module: 7-Level Priority-Based Filtering

The ACL module uses multiple specialized maps for different matching granularities:

**Hash-based Exact/Wildcard Matches:**
- `acl_5tuple_map` (HASH) - Exact 5-tuple matches (proto, src_ip, dst_ip, sport, dport)
- `acl_pdp_map` (HASH) - Proto + destination IP + destination port
- `acl_psp_map` (HASH) - Proto + source IP + destination port  
- `acl_pp_map` (HASH) - Proto + destination port only

**Prefix-based Matches:**
- `acl_lpm_src_map` (LPM_TRIE) - Source IP longest prefix match
- `acl_lpm_dst_map` (LPM_TRIE) - Destination IP longest prefix match

**Configuration & Statistics:**
- `acl_config_map` (ARRAY) - Global ACL configuration (default action, enabled/disabled)
- `acl_stats_map` (PERCPU_ARRAY) - Per-CPU statistics counters

**Benefits:** Enables O(1) lookups for exact matches and O(log N) for prefix matches, with clear priority ordering from specific to general rules.

### ROUTE Module: IPv4 LPM Routing with ARP

The ROUTE module implements full Layer 3 forwarding using:

- `route_tbl` (LPM_TRIE) - IPv4 routing table with longest prefix match
- `arp_tbl` (HASH) - ARP table for next-hop MAC address resolution
- `iface_cfg` (ARRAY) - Per-interface configuration (MAC addresses, router flags)
- `route_stats` (PERCPU_ARRAY) - Per-CPU routing statistics
- `route_cfg` (ARRAY) - Global routing configuration

**Benefits:** Efficient longest prefix matching for routing decisions, separate ARP resolution for scalability, per-interface configuration for multi-port routing.

### Design Rationale for Multi-Map Approach

1. **Performance Optimization**: Different map types (HASH vs LPM_TRIE) provide optimal lookup performance for specific use cases
2. **Scalability**: Separate maps prevent one rule type from impacting others
3. **Functionality**: LPM_TRIE enables efficient prefix matching impossible with HASH maps
4. **Maintainability**: Modular design with clear separation of concerns
5. **Extensibility**: Easy to add new matching criteria without affecting existing maps

This multi-map approach represents a more mature and efficient implementation compared to the single-table design mentioned in early planning documents.

## Module-Owned Maps

### Module-Owned Maps

Maps defined in specific modules but accessible to others via extern declarations:

```c
// L2Learn module - rs_mac_table (defined in l2learn.bpf.c)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_mac_table SEC(".maps");

/* Primary Owner: l2learn module (defines and manages)
 * Access: l2learn (read/write), other modules via extern
 * Pinning: Named pinning for user-space inspection
 * Synchronization: Module-internal operations
 */

// Extern declaration in map_defs.h for cross-module access
#ifndef RS_MAC_TABLE_OWNER
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_mac_table SEC(".maps");
#endif

// Usage in other modules
static __always_inline struct rs_mac_entry *rs_mac_lookup(__u8 *mac, __u16 vlan) {
    struct rs_mac_key key = {};
    __builtin_memcpy(key.mac, mac, 6);
    key.vlan = vlan;
    return bpf_map_lookup_elem(&rs_mac_table, &key);
}
```

### Single-Owner Maps

Maps used exclusively within one module, no cross-module sharing:

```c
// rs_xdp_devmap - XDP device map (defined in lastcall.bpf.c only)
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_NONE);  // Not pinned, single owner
} rs_xdp_devmap SEC(".maps");

/* Owner: lastcall module only
 * Access: Internal to lastcall.bpf.c
 * Pinning: None needed (no sharing)
 * Rationale: Single-owner pattern reduces coupling
 */

## Pinning Strategies

### Named Pinning

```c
// LIBBPF_PIN_BY_NAME strategy
#define BPF_PIN_PATH "/sys/fs/bpf"

// Actual pinned maps in rSwitch:
/sys/fs/bpf/rs_ctx_map          // Core infrastructure
/sys/fs/bpf/rs_progs            // Core infrastructure  
/sys/fs/bpf/rs_event_bus        // Core infrastructure
/sys/fs/bpf/rs_port_config_map  // Core infrastructure
/sys/fs/bpf/rs_stats_map        // Core infrastructure
/sys/fs/bpf/rs_mac_table        // Module-owned (l2learn)
/sys/fs/bpf/rs_vlan_map         // Core infrastructure
```

### Pinning Benefits

Named pinning enables:
1. Cross-program map sharing between BPF modules
2. Persistence across program loads/unloads
3. User-space inspection and modification
4. Runtime reconfiguration
5. Debugging and monitoring

### Actual Pinning in Loader

The loader automatically pins maps using libbpf's named pinning. Maps are accessed via pinned paths or direct object references depending on ownership pattern.

## Synchronization Patterns

### Per-CPU Maps

```c
// Per-CPU maps provide lock-free access
struct rs_ctx *ctx = bpf_map_lookup_elem(&rs_ctx_map, &key);
// Each CPU has its own instance - no synchronization needed

// Per-CPU statistics (rs_stats_map)
static __always_inline void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes) {
    __u32 key = ctx->ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
}
```

### Ringbuf Synchronization

```c
// Event bus uses ringbuf atomic operations
#define RS_EMIT_EVENT(event_ptr, event_size) ({ \
    void *__evt = bpf_ringbuf_reserve(&rs_event_bus, (event_size), 0); \
    int __ret = -1; \
    if (__evt) { \
        __builtin_memcpy(__evt, (event_ptr), (event_size)); \
        bpf_ringbuf_submit(__evt, 0); \
        __ret = 0; \
    } \
    __ret; \
})
```

### Configuration Updates

```c
// User-space configuration updates (from loader code)
int update_port_config(int fd, __u32 ifindex, struct rs_port_config *config) {
    // Maps allow concurrent reads during updates
    return bpf_map_update_elem(fd, &ifindex, config, BPF_ANY);
}
```

## Map Access Patterns

### Read-Only Access

```c
// Configuration maps - read-only access from BPF
static __always_inline struct rs_port_config *rs_get_port_config(__u32 ifindex) {
    return bpf_map_lookup_elem(&rs_port_config_map, &ifindex);
}

// Safe for concurrent access, no synchronization needed for reads
```

### Read-Write Access

```c
// Statistics maps - atomic updates
static __always_inline void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes) {
    __u32 key = ctx->ifindex;
    struct rs_stats *stats = bpf_map_lookup_elem(&rs_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
}

// MAC table updates (module-owned)
static __always_inline int rs_mac_update(__u8 *mac, __u16 vlan, __u32 ifindex, __u64 timestamp) {
    struct rs_mac_key key = {};
    struct rs_mac_entry entry = {
        .ifindex = ifindex,
        .static_entry = 0,
        .last_seen = timestamp,
        .hit_count = 1,
    };
    __builtin_memcpy(key.mac, mac, 6);
    key.vlan = vlan;
    return bpf_map_update_elem(&rs_mac_table, &key, &entry, BPF_ANY);
}
```

### Conditional Updates

```c
// Conditional map operations
static __always_inline int conditional_update(struct bpf_map_def *map,
                                             void *key, void *value,
                                             enum bpf_map_update_flags flags) {
    // Use BPF_NOEXIST, BPF_EXIST flags for conditional operations
    return bpf_map_update_elem(map, key, value, flags);
}
```

## Memory Management

### Map Size Optimization

```c
// Actual size constants from uapi.h
#define RS_MAX_INTERFACES   64      // Maximum network interfaces
#define RS_MAX_VLANS        4096    // Maximum VLAN IDs
#define RS_MAX_ALLOWED_VLANS 128    // Maximum allowed VLANs per port

// Map sizes in code
#define RS_MAX_MAC_ENTRIES  65536   // MAC table size (l2learn)

// Map types used in rSwitch
BPF_MAP_TYPE_HASH        // rs_mac_table, rs_port_config_map, rs_vlan_map
BPF_MAP_TYPE_PERCPU_ARRAY // rs_ctx_map, rs_stats_map
BPF_MAP_TYPE_PROG_ARRAY  // rs_progs
BPF_MAP_TYPE_RINGBUF     // rs_event_bus
BPF_MAP_TYPE_DEVMAP      // rs_xdp_devmap (single-owner)
```

### Memory Efficiency

```c
// Per-CPU maps for CPU-local data
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct per_cpu_stats);
} per_cpu_stats_map;

// Reduces memory usage and eliminates false sharing
```

## Error Handling

### Map Access Error Handling

```c
// Robust error handling
static __always_inline struct rs_port_config *safe_get_port_config(__u32 ifindex) {
    struct rs_port_config *config = bpf_map_lookup_elem(&rs_port_config_map, &ifindex);

    if (!config) {
        // Log error and return default
        rs_debug("No config for ifindex %u", ifindex);
        return get_default_port_config();
    }

    return config;
}
```

### Fallback Mechanisms

```c
// Graceful degradation on map failures
static __always_inline int handle_map_failure(enum map_failure_reason reason) {
    switch (reason) {
    case MAP_NOT_FOUND:
        // Continue with default behavior
        return XDP_PASS;

    case MAP_FULL:
        // Implement LRU eviction or rate limiting
        return enforce_rate_limit();

    case MAP_CORRUPTED:
        // Trigger system recovery
        return trigger_recovery();
    }

    return XDP_DROP;
}
```

## User-Space Integration

### Map Inspection

```bash
# Inspect pinned maps (actual commands work with rSwitch)
bpftool map show pinned /sys/fs/bpf/rs_port_config_map
bpftool map dump pinned /sys/fs/bpf/rs_mac_table
bpftool map show pinned /sys/fs/bpf/rs_event_bus

# Real-time monitoring
bpftool map update pinned /sys/fs/bpf/rs_port_config_map key 1 value <config>
```

### Runtime Configuration

```c
// User-space map manipulation (from rswitch_loader.c)
int configure_port(int rs_port_config_map_fd, __u32 ifindex, struct rs_port_config *cfg) {
    return bpf_map_update_elem(rs_port_config_map_fd, &ifindex, cfg, BPF_ANY);
}

int read_port_stats(int rs_stats_map_fd, __u32 ifindex, struct rs_stats *stats) {
    return bpf_map_lookup_elem(rs_stats_map_fd, &ifindex, stats);
}

// Event bus consumption (from event_consumer.c)
int consume_events(int rs_event_bus_fd) {
    return bpf_map_lookup_elem(rs_event_bus_fd, NULL, NULL);  // Ringbuf interface
}
```

## Debugging and Monitoring

### Map Debugging

```c
// Debug map operations
static __always_inline void debug_map_access(const char *map_name,
                                           const char *operation,
                                           int result) {
    if (result < 0) {
        rs_debug("Map %s %s failed: %d", map_name, operation, result);
    }
}

// Usage
struct rs_port_config *config = bpf_map_lookup_elem(&rs_port_config_map, &ifindex);
debug_map_access("rs_port_config_map", "lookup", config ? 0 : -1);
```

### Map Metrics

```c
// Collect map usage statistics
struct map_metrics {
    __u64 lookups;
    __u64 hits;
    __u64 misses;
    __u64 updates;
    __u64 deletes;
    __u64 errors;
};

// Per-map metrics collection
static __always_inline void update_map_metrics(struct map_metrics *metrics,
                                             enum map_operation op,
                                             int result) {
    __sync_fetch_and_add(&metrics->lookups, 1);

    if (op == MAP_LOOKUP) {
        if (result == 0) {
            __sync_fetch_and_add(&metrics->hits, 1);
        } else {
            __sync_fetch_and_add(&metrics->misses, 1);
        }
    }
    // ... other operations
}
```

## Performance Optimization

### Map Lookup Optimization

```c
// Cache frequent lookups
static __always_inline struct rs_port_config *get_cached_port_config(__u32 ifindex) {
    // Per-CPU cache for hot path optimization
    static __percpu struct {
        __u32 ifindex;
        struct rs_port_config config;
        __u64 timestamp;
    } cache;

    struct cache_entry *entry = bpf_this_cpu_ptr(&cache);
    if (entry && entry->ifindex == ifindex) {
        // Cache hit
        return &entry->config;
    }

    // Cache miss - lookup and cache
    struct rs_port_config *config = bpf_map_lookup_elem(&rs_port_config_map, &ifindex);
    if (config && entry) {
        entry->ifindex = ifindex;
        memcpy(&entry->config, config, sizeof(*config));
        entry->timestamp = bpf_ktime_get_ns();
    }

    return config;
}
```

### Batch Operations

```c
// Batch map operations for efficiency
static __always_inline int batch_update_stats(struct port_stats_batch *batch) {
    // Update multiple counters in one operation
    for (int i = 0; i < batch->count; i++) {
        __u32 ifindex = batch->entries[i].ifindex;
        struct port_stats *stats = &batch->entries[i].stats;

        // Bulk update
        bpf_map_update_elem(&port_stats_map, &ifindex, stats, BPF_ANY);
    }

    return 0;
}
```

## Future Enhancements

### Advanced Map Types

```c
// Future: BPF_MAP_TYPE_BLOOM_FILTER for fast lookups
struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, 1000000);
    __type(key, struct flow_key);
} flow_filter;

// Future: BPF_MAP_TYPE_STACK for hierarchical processing
struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __uint(max_entries, 32);
    __type(value, struct processing_context);
} context_stack;
```

### Dynamic Map Resizing

```c
// Future: Runtime map resizing
int resize_map(int fd, __u32 new_max_entries) {
    // BPF map resizing support (future kernel feature)
    return bpf_map_resize(fd, new_max_entries);
}
```

### Map Replication

```c
// Future: Cross-switch map synchronization
struct map_replication {
    __u32 switch_id;
    __u64 sequence_number;
    __u8  operation;  // INSERT/UPDATE/DELETE
    void *key;
    void *value;
};
```

## Conclusion

BPF map sharing patterns in rSwitch are implemented through three concrete ownership models: core infrastructure maps (shared across all components), module-owned maps (primary ownership with extern access), and single-owner maps (no sharing). This design enables efficient inter-module communication while maintaining clear ownership boundaries. Through named pinning, per-CPU isolation, and atomic operations, rSwitch achieves high-performance data sharing with comprehensive observability and runtime configurability.</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/paperwork/BPF_Map_Sharing_Patterns.md