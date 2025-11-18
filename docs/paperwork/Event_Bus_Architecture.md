# Event Bus Architecture

## Overview

rSwitch implements a unified event bus architecture using BPF ringbuf for efficient kernel-user communication. This document details the event-driven design, ringbuf implementation, event types, and the observability patterns that enable comprehensive system monitoring.

## Event Bus Fundamentals

### Ringbuf Architecture

```c
// Unified event ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 << 20);  /* 16 MB ring buffer */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");
```

### Event Emission Macro

```c
// RS_EMIT_EVENT macro for type-safe emission
#define RS_EMIT_EVENT(event_ptr, event_size) \
    do { \
        void *ringbuf_ptr = bpf_ringbuf_reserve(&rs_event_bus, event_size, 0); \
        if (ringbuf_ptr) { \
            memcpy(ringbuf_ptr, event_ptr, event_size); \
            bpf_ringbuf_submit(ringbuf_ptr, 0); \
        } \
    } while (0)
```

## Event Type Hierarchy

### Core Event Categories

```c
// Event type enumeration
enum rs_event_type {
    // Packet processing events
    RS_EVENT_PACKET_RX = 1,
    RS_EVENT_PACKET_TX = 2,
    RS_EVENT_PACKET_DROP = 3,

    // Module-specific events
    RS_EVENT_VLAN_CHANGE = 10,
    RS_EVENT_MAC_LEARN = 11,
    RS_EVENT_ACL_HIT = 12,
    RS_EVENT_ROUTE_LOOKUP = 13,

    // State machine events
    RS_EVENT_VOQD_TRANSITION = 20,
    RS_EVENT_VOQD_HEARTBEAT = 21,

    // Error events
    RS_EVENT_ERROR_PARSE = 30,
    RS_EVENT_ERROR_NO_ROUTE = 31,
    RS_EVENT_ERROR_ACL_BLOCK = 32,

    // Performance events
    RS_EVENT_LATENCY_SAMPLE = 40,
    RS_EVENT_QUEUE_DEPTH = 41,
};
```

### Event Structure Template

```c
// Common event header
struct rs_event_header {
    __u32 event_type;           // Event classification
    __u64 timestamp_ns;         // High-precision timestamp
    __u32 ifindex;              // Interface index
    __u32 cpu_id;               // CPU that generated event
};

// Extended event with metadata
#define RS_EVENT_COMMON \
    struct rs_event_header header; \
    __u32 sequence_number;      // Per-CPU sequence for ordering
```

## Packet Processing Events

### Packet Reception Event

```c
// Packet RX event
struct rs_packet_rx_event {
    RS_EVENT_COMMON

    // Packet metadata
    __u16 eth_proto;
    __u32 pkt_len;
    __u8  vlan_present;
    __u16 vlan_id;

    // Processing context
    __u32 ingress_ifindex;
    __u8  prio;
    __u8  ecn;

    // Layer information
    struct rs_layers layers;
} __attribute__((packed));

// Emission in dispatcher
static __always_inline void emit_packet_rx(struct rs_ctx *ctx) {
    struct rs_packet_rx_event evt = {
        .header = {
            .event_type = RS_EVENT_PACKET_RX,
            .timestamp_ns = bpf_ktime_get_ns(),
            .ifindex = ctx->ifindex,
            .cpu_id = bpf_get_smp_processor_id(),
        },
        .sequence_number = get_cpu_sequence(),
        .eth_proto = ctx->layers.eth_proto,
        .pkt_len = ctx->layers.pkt_len,
        .vlan_present = ctx->layers.vlan_depth > 0,
        .vlan_id = ctx->layers.vlan_ids[0],
        .ingress_ifindex = ctx->ifindex,
        .prio = ctx->prio,
        .ecn = ctx->ecn,
        .layers = ctx->layers,
    };

    RS_EMIT_EVENT(&evt, sizeof(evt));
}
```

### Packet Drop Event

```c
// Packet drop event with reason
struct rs_packet_drop_event {
    RS_EVENT_COMMON

    // Drop classification
    __u32 drop_reason;          // Detailed drop reason
    __u32 drop_stage;           // Pipeline stage where dropped

    // Packet context
    __u16 eth_proto;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    // Module-specific data
    union {
        struct vlan_drop_data vlan;
        struct acl_drop_data acl;
        struct route_drop_data route;
    } module_data;
} __attribute__((packed));

// Drop reason enumeration
enum rs_drop_reason {
    RS_DROP_VLAN_FILTER = 1,
    RS_DROP_ACL_BLOCK = 2,
    RS_DROP_NO_FWD_ENTRY = 3,
    RS_DROP_TTL_EXCEEDED = 4,
    RS_DROP_PARSE_ERROR = 5,
    RS_DROP_RATE_LIMIT = 6,
};
```

## Module-Specific Events

### MAC Learning Events

```c
// MAC address learning event
struct rs_mac_learn_event {
    RS_EVENT_COMMON

    // MAC learning data
    __u8  mac[6];               // Learned MAC address
    __u32 ifindex;              // Interface where learned
    __u8  is_local;             // Locally learned vs remote

    // Learning context
    __u16 vlan_id;              // VLAN context
    __u32 flow_hash;            // Associated flow hash

    // Aging information
    __u64 learn_timestamp;      // When learned
    __u64 last_seen;            // Last activity
    __u32 packet_count;         // Packets seen
} __attribute__((packed));

// Emission in l2learn module
static __always_inline void emit_mac_learn(__u8 *mac, __u32 ifindex, __u16 vlan_id) {
    struct rs_mac_learn_event evt = {
        .header = {
            .event_type = RS_EVENT_MAC_LEARN,
            .timestamp_ns = bpf_ktime_get_ns(),
            .ifindex = ifindex,
        },
        .mac = {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]},
        .ifindex = ifindex,
        .vlan_id = vlan_id,
        .learn_timestamp = bpf_ktime_get_ns(),
    };

    RS_EMIT_EVENT(&evt, sizeof(evt));
}
```

### ACL Events

```c
// ACL rule hit event
struct rs_acl_hit_event {
    RS_EVENT_COMMON

    // Rule information
    __u32 rule_id;              // ACL rule identifier
    __u8  action;               // Action taken (PASS/DROP/REDIRECT)

    // Match details
    __u8  match_type;           // 5-tuple, LPM, etc.
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;

    // Performance data
    __u64 lookup_time_ns;       // Time spent in lookup
    __u32 rule_priority;        // Rule priority level
} __attribute__((packed));
```

## State Machine Events

### VOQd Transition Events

```c
// VOQd state transition event
struct rs_voqd_transition_event {
    RS_EVENT_COMMON

    // Transition details
    __u32 old_mode;             // Previous mode
    __u32 new_mode;             // New mode
    __u32 transition_type;      // Manual/auto/failover

    // Configuration changes
    __u32 old_prio_mask;        // Previous priority mask
    __u32 new_prio_mask;        // New priority mask

    // Failure context
    __u32 failover_count;       // Total failovers
    __u32 overload_drops;       // Overload events
    __u64 last_heartbeat_ns;    // Last heartbeat
} __attribute__((packed));

// Transition types
enum rs_transition_type {
    RS_TRANSITION_MANUAL = 1,
    RS_TRANSITION_AUTO_FAILOVER = 2,
    RS_TRANSITION_OVERLOAD = 3,
    RS_TRANSITION_RECOVERY = 4,
};
```

### Heartbeat Events

```c
// VOQd heartbeat event
struct rs_voqd_heartbeat_event {
    RS_EVENT_COMMON

    // Heartbeat data
    __u32 mode;                 // Current mode
    __u32 prio_mask;            // Active priority mask
    __u8  running;              // VOQd running status

    // Performance metrics
    __u64 packets_processed;    // Packets since last heartbeat
    __u64 bytes_processed;      // Bytes since last heartbeat
    __u32 queue_depth;          // Current queue depth

    // Health indicators
    __u32 overload_count;       // Overload events
    __u64 avg_latency_ns;       // Average packet latency
} __attribute__((packed));
```

## Performance Events

### Latency Sampling

```c
// Packet latency event
struct rs_latency_event {
    RS_EVENT_COMMON

    // Latency measurement
    __u64 queue_time_ns;        // Time spent in queue
    __u64 processing_time_ns;   // Processing time
    __u64 total_latency_ns;     // End-to-end latency

    // Packet characteristics
    __u32 pkt_len;              // Packet length
    __u8  prio;                 // Packet priority
    __u32 flow_hash;            // Flow identifier

    // Processing stages
    __u32 stages_executed;      // Number of stages
    __u32 tail_calls;           // Tail-call count
} __attribute__((packed));

// Latency measurement
static __always_inline void measure_latency(struct rs_ctx *ctx) {
    __u64 now_ns = bpf_ktime_get_ns();
    __u64 latency_ns = now_ns - ctx->timestamp_ns;

    struct rs_latency_event evt = {
        .header = {
            .event_type = RS_EVENT_LATENCY_SAMPLE,
            .timestamp_ns = now_ns,
            .ifindex = ctx->ifindex,
        },
        .total_latency_ns = latency_ns,
        .pkt_len = ctx->layers.pkt_len,
        .prio = ctx->prio,
        .flow_hash = compute_flow_hash(ctx),
    };

    RS_EMIT_EVENT(&evt, sizeof(evt));
}
```

### Queue Depth Events

```c
// Queue depth monitoring
struct rs_queue_depth_event {
    RS_EVENT_COMMON

    // Queue information
    __u32 port_idx;             // Port index
    __u32 prio;                 // Priority level
    __u32 current_depth;        // Current queue depth
    __u32 max_depth;            // Maximum allowed depth

    // Watermark tracking
    __u32 high_watermark;       // Peak depth seen
    __u32 low_watermark;        // Minimum depth seen

    // Congestion indicators
    __u8  congested;            // Currently congested
    __u32 drop_count;           // Drops due to overflow
} __attribute__((packed));
```

## User-Space Event Processing

### Ringbuf Consumer

```c
// User-space ringbuf consumer
struct event_consumer {
    int ringbuf_fd;
    void *ringbuf_ptr;
    size_t ringbuf_size;

    // Event handlers
    event_handler_t handlers[RS_EVENT_MAX];

    // Statistics
    uint64_t events_processed;
    uint64_t events_dropped;
    uint64_t bytes_processed;
};

// Event processing loop
void process_events(struct event_consumer *consumer) {
    while (running) {
        // Poll ringbuf
        int ret = bpf_ringbuf_poll(consumer->ringbuf_fd, 1000); // 1s timeout

        if (ret > 0) {
            // Process available events
            consume_ringbuf_events(consumer);
        }
    }
}
```

### Event Handler Registration

```c
// Event handler function type
typedef int (*event_handler_t)(const void *event, size_t size);

// Register event handlers
int register_event_handler(struct event_consumer *consumer,
                          enum rs_event_type type,
                          event_handler_t handler) {
    if (type >= RS_EVENT_MAX) return -1;
    consumer->handlers[type] = handler;
    return 0;
}

// Example handler
int handle_packet_drop(const struct rs_packet_drop_event *evt, size_t size) {
    // Log drop event
    log_drop_event(evt->header.ifindex, evt->drop_reason, evt->saddr, evt->daddr);

    // Update statistics
    update_drop_stats(evt->drop_reason);

    // Trigger alerts if needed
    if (evt->drop_reason == RS_DROP_NO_ROUTE) {
        alert_routing_issue(evt->header.ifindex);
    }

    return 0;
}
```

## Event Filtering and Sampling

### Sampling Configuration

```c
// Event sampling configuration
struct event_sampling_config {
    __u32 sample_rate;          // 1/N sampling ratio
    __u32 max_events_per_sec;   // Rate limiting
    __u32 enabled_events;       // Bitmask of enabled events
};

// Sampling decision
static __always_inline int should_emit_event(enum rs_event_type type,
                                           struct event_sampling_config *config) {
    // Check if event type is enabled
    if (!(config->enabled_events & (1 << type))) {
        return 0;
    }

    // Apply sampling
    if (config->sample_rate > 1) {
        __u32 rand = bpf_get_prandom_u32();
        if ((rand % config->sample_rate) != 0) {
            return 0;
        }
    }

    return 1;
}
```

### Dynamic Filtering

```c
// Runtime event filtering
static __always_inline int event_filter_enabled(const char *filter_name) {
    // Check filter map
    __u32 key = hash_filter_name(filter_name);
    __u32 *enabled = bpf_map_lookup_elem(&event_filters, &key);
    return enabled && *enabled;
}

// Usage
if (event_filter_enabled("debug_drops")) {
    emit_packet_drop(ctx);
}
```

## Event Serialization

### Binary Event Format

```c
// Event serialization header
struct event_record {
    __u32 magic;                // Magic number for validation
    __u32 version;              // Event format version
    __u32 size;                 // Total record size
    __u32 type;                 // Event type
    __u64 timestamp_ns;         // Event timestamp
    __u8  data[];               // Variable-sized event data
} __attribute__((packed));

// Magic number for validation
#define RS_EVENT_MAGIC 0x52534556  // "RSEV"
#define RS_EVENT_VERSION 1
```

### Event Persistence

```c
// Event logging to disk
int log_event_to_file(const void *event, size_t size) {
    struct event_record record = {
        .magic = RS_EVENT_MAGIC,
        .version = RS_EVENT_VERSION,
        .size = sizeof(record) + size,
        .type = get_event_type(event),
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    // Write header
    fwrite(&record, sizeof(record), 1, log_file);

    // Write event data
    fwrite(event, size, 1, log_file);

    return 0;
}
```

## Performance Considerations

### Ringbuf Sizing

```c
// Ringbuf size calculation
#define RINGBUF_SIZE_MB 16
#define RINGBUF_SIZE_BYTES (RINGBUF_SIZE_MB << 20)

// Size considerations:
// - Event rate: ~100K events/sec max
// - Event size: ~100-200 bytes average
// - Burst handling: 1M events in ringbuf
// - Memory impact: 16MB per ringbuf
```

### Event Emission Overhead

```c
// Measure emission cost
static __always_inline void measure_emit_overhead(void) {
    __u64 start_ns = bpf_ktime_get_ns();

    // Emit event
    struct rs_simple_event evt = {.type = RS_EVENT_TEST};
    RS_EMIT_EVENT(&evt, sizeof(evt));

    __u64 end_ns = bpf_ktime_get_ns();
    __u64 overhead_ns = end_ns - start_ns;

    // Track overhead statistics
    update_overhead_stats(overhead_ns);
}

// Typical overhead: 50-200ns per event
```

### Rate Limiting

```c
// Per-CPU rate limiting
struct event_rate_limit {
    __u64 last_emit_ns;
    __u32 emit_count;
    __u32 drop_count;
};

static __always_inline int check_rate_limit(struct event_rate_limit *limit,
                                          __u64 now_ns) {
    // Token bucket algorithm
    __u64 time_diff_ns = now_ns - limit->last_emit_ns;
    __u32 tokens_to_add = time_diff_ns / NS_PER_TOKEN;

    limit->emit_count += tokens_to_add;
    if (limit->emit_count > MAX_TOKENS) {
        limit->emit_count = MAX_TOKENS;
    }

    if (limit->emit_count > 0) {
        limit->emit_count--;
        limit->last_emit_ns = now_ns;
        return 1;  // Allow emit
    } else {
        limit->drop_count++;
        return 0;  // Rate limited
    }
}
```

## Debugging and Monitoring

### Event Tracing

```c
// Enable event tracing
#define EVENT_TRACE_ENABLED 1

#if EVENT_TRACE_ENABLED
#define TRACE_EVENT(evt) RS_EMIT_EVENT(evt, sizeof(*evt))
#else
#define TRACE_EVENT(evt) do {} while (0)
#endif

// Usage
TRACE_EVENT(&packet_rx_evt);
```

### Event Statistics

```c
// Per-event-type statistics
struct event_stats {
    __u64 emitted;
    __u64 dropped_ringbuf_full;
    __u64 dropped_rate_limit;
    __u64 dropped_filter;
    __u64 bytes_emitted;
};

// Global event statistics
static __always_inline void update_event_stats(enum rs_event_type type,
                                             enum event_drop_reason reason) {
    __u32 key = type;
    struct event_stats *stats = bpf_map_lookup_elem(&event_stats_map, &key);

    if (stats) {
        switch (reason) {
        case DROP_NONE:
            __sync_fetch_and_add(&stats->emitted, 1);
            break;
        case DROP_RINGBUF_FULL:
            __sync_fetch_and_add(&stats->dropped_ringbuf_full, 1);
            break;
        // ... other reasons
        }
    }
}
```

## Future Enhancements

### Structured Event Schema

```c
// Future: Protocol buffer-style events
message PacketEvent {
    Header header = 1;
    oneof payload {
        PacketRx rx = 2;
        PacketTx tx = 3;
        PacketDrop drop = 4;
    }
}

// Schema evolution support
struct event_schema {
    __u32 version;
    __u32 schema_hash;
    const char *schema_json;
};
```

### Event Correlation

```c
// Future: Event correlation engine
struct event_correlation {
    __u64 correlation_id;       // Link related events
    __u32 parent_event_id;      // Hierarchical relationships
    __u32 child_count;          // Number of child events
};

// Distributed tracing integration
struct trace_context {
    __u64 trace_id;
    __u64 span_id;
    __u64 parent_span_id;
};
```

### Real-time Analytics

```c
// Future: In-kernel event processing
static __always_inline void process_event_stream(const void *event, size_t size) {
    // Real-time analytics
    update_moving_average(event);
    check_anomaly_detection(event);
    trigger_automated_response(event);
}
```

## Ownership and Developer Usage

### Map Ownership

**rs_event_bus Ownership:**
- **Not owned/init'ed by dispatcher**: The `rs_event_bus` is a core infrastructure BPF ringbuf map defined in `uapi.h`, but not initialized per-packet like the context map. It's a persistent ring buffer created once during BPF program loading.
- **Infrastructure ownership**: Managed by the loader (`rswitch_loader.c`) which pins it to `/sys/fs/bpf/rs_event_bus` for cross-program access.
- **User-space integration**: Consumed by `event_consumer.c` for real-time event processing and monitoring.

### Developer Attention in Customized Modules

**Key considerations for module developers:**
- **Use RS_EMIT_EVENT macro**: Always use the `RS_EMIT_EVENT(event_ptr, event_size)` macro for type-safe emission rather than direct ringbuf operations.
- **Follow event type definitions**: Use predefined event types from `enum rs_event_type` (RS_EVENT_PACKET_RX, RS_EVENT_MAC_LEARN, etc.) and corresponding event structures.
- **Include proper metadata**: All events should include the common header with `event_type`, `timestamp_ns`, `ifindex`, and `cpu_id`.
- **Event sampling awareness**: Consider using sampling configurations to avoid overwhelming the ringbuf, especially for high-frequency events.
- **Best-effort delivery**: Events may be dropped if the ringbuf is full - design modules to function without guaranteed event delivery.
- **Performance impact**: Event emission has overhead (~50-200ns) - use judiciously and consider rate limiting for production deployments.

### Integration with Other Core Maps

The event bus works alongside other core infrastructure maps:
- **rs_ctx_map**: Provides packet context for rich event metadata
- **rs_stats_map**: Events can supplement statistical monitoring
- **rs_port_config_map**: Configuration changes can trigger events

### Debugging Event Issues

```c
// Check event emission success
if (RS_EMIT_EVENT(&event, sizeof(event)) < 0) {
    // Handle emission failure (ringbuf full, etc.)
    rs_debug("Event emission failed for type %u", event.header.event_type);
}
```

```bash
// Monitor ringbuf usage
bpftool map show pinned /sys/fs/bpf/rs_event_bus
bpftool map dump pinned /sys/fs/bpf/rs_event_bus  # Shows current events
```

## Conclusion

The event bus architecture provides a comprehensive observability framework with efficient kernel-user communication, rich event types, and flexible processing capabilities. Through careful design of event structures, emission patterns, and consumption mechanisms, rSwitch enables deep system visibility while maintaining high performance and low overhead.</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/paperwork/Event_Bus_Architecture.md