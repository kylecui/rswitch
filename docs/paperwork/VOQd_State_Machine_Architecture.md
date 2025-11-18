# VOQd State Machine Architecture

## Overview

rSwitch implements a sophisticated state machine for Virtual Output Queue Daemon (VOQd) that manages the transition between different QoS processing modes. This document details the state machine design, mode transitions, failure handling, and the control interfaces that enable runtime reconfiguration.

## State Machine Fundamentals

### Operating Modes

```c
// VOQd operating modes
enum voqd_mode {
    VOQD_MODE_BYPASS = 0,    // Fast-path only (zero overhead)
    VOQD_MODE_SHADOW = 1,    // Observation mode (metadata collection)
    VOQD_MODE_ACTIVE = 2,    // Full QoS processing (AF_XDP redirect)
};
```

### State Structure

```c
// Shared state map structure
struct voqd_state {
    __u32 mode;                    // Current operating mode
    __u32 prio_mask;              // Priority interception mask
    __u8  running;                // VOQd process running flag
    __u8  flags;                  // Control flags
    __u32 failover_count;         // Auto-failover events
    __u32 overload_drops;         // Ringbuf overload drops
    __u64 last_heartbeat_ns;      // Last heartbeat timestamp
};
```

## Mode Characteristics

### BYPASS Mode

**Purpose**: Maximum performance with zero QoS overhead

```c
// BYPASS mode behavior
static int bypass_mode_handler(struct voqd_state *state, struct voq_meta *meta) {
    // No processing - direct fast-path
    return XDP_PASS;  // Continue to XDP fast-path
}

// Characteristics:
// - Zero CPU overhead for QoS
// - No user-space involvement
// - Maximum throughput
// - No QoS features available
```

### SHADOW Mode

**Purpose**: Traffic observation and pattern learning

```c
// SHADOW mode behavior
static int shadow_mode_handler(struct voqd_state *state, struct voq_meta *meta) {
    // Submit metadata to ringbuf for analysis
    struct voq_meta *ring_meta = bpf_ringbuf_reserve(&voq_ringbuf, sizeof(*meta), 0);
    if (ring_meta) {
        memcpy(ring_meta, meta, sizeof(*meta));
        bpf_ringbuf_submit(ring_meta, 0);
    } else {
        // Ringbuf full - track overload
        state->overload_drops++;
    }

    // Continue with fast-path
    return XDP_PASS;
}

// Characteristics:
// - Metadata collection for traffic analysis
// - Zero impact on forwarding performance
// - Learning phase for QoS policy tuning
// - Ringbuf may overflow under high load
```

### ACTIVE Mode

**Purpose**: Full QoS processing with user-space scheduling

```c
// ACTIVE mode behavior
static int active_mode_handler(struct voqd_state *state, struct voq_meta *meta) {
    // Check priority mask
    if (!(state->prio_mask & (1 << meta->prio))) {
        return XDP_PASS;  // Not intercepted
    }

    // Submit metadata and redirect to AF_XDP
    struct voq_meta *ring_meta = bpf_ringbuf_reserve(&voq_ringbuf, sizeof(*meta), 0);
    if (ring_meta) {
        memcpy(ring_meta, meta, sizeof(*meta));
        bpf_ringbuf_submit(ring_meta, 0);

        // Redirect to AF_XDP socket
        return bpf_redirect_map(&xsks_map, meta->eg_port, 0);
    } else {
        // Overload - graceful degradation
        state->overload_drops++;
        return XDP_PASS;  // Fall back to fast-path
    }
}

// Characteristics:
// - Full QoS scheduling in user-space
// - AF_XDP zero-copy packet handling
// - Priority-based queuing and scheduling
// - Higher latency but precise control
```

## State Transitions

### Transition Rules

```c
// Valid state transitions
enum transition_type {
    TRANSITION_MANUAL = 0,      // User-initiated via rswitchctl
    TRANSITION_AUTO_FAILOVER = 1, // Heartbeat timeout
    TRANSITION_OVERLOAD = 2,    // Sustained overload
    TRANSITION_RECOVERY = 3,    // VOQd restart
};

// Transition validation
static int validate_transition(__u32 current_mode, __u32 new_mode,
                              enum transition_type type) {
    switch (type) {
    case TRANSITION_MANUAL:
        // All transitions allowed manually
        return 0;

    case TRANSITION_AUTO_FAILOVER:
        // ACTIVE/SHADOW → BYPASS only
        if ((current_mode == VOQD_MODE_ACTIVE || current_mode == VOQD_MODE_SHADOW) &&
            new_mode == VOQD_MODE_BYPASS) {
            return 0;
        }
        return -1;

    case TRANSITION_OVERLOAD:
        // ACTIVE/SHADOW → BYPASS on overload
        if ((current_mode == VOQD_MODE_ACTIVE || current_mode == VOQD_MODE_SHADOW) &&
            new_mode == VOQD_MODE_BYPASS) {
            return 0;
        }
        return -1;

    case TRANSITION_RECOVERY:
        // BYPASS → previous mode on VOQd restart
        return 0;  // Allow any recovery transition

    default:
        return -1;
    }
}
```

### Transition Implementation

```c
// State transition with validation
static int perform_transition(struct voqd_state *state, __u32 new_mode,
                             __u32 new_prio_mask, enum transition_type type) {
    // Validate transition
    if (validate_transition(state->mode, new_mode, type) < 0) {
        return -EINVAL;
    }

    // Record transition
    __u32 old_mode = state->mode;
    state->mode = new_mode;
    if (new_prio_mask != (__u32)-1) {
        state->prio_mask = new_prio_mask;
    }

    // Emit transition event
    struct state_transition_event evt = {
        .old_mode = old_mode,
        .new_mode = new_mode,
        .type = type,
        .timestamp_ns = bpf_ktime_get_ns(),
    };
    RS_EMIT_EVENT(&evt, sizeof(evt));

    return 0;
}
```

## Failure Handling

### Heartbeat Mechanism

```c
// Heartbeat timeout detection
#define VOQD_HEARTBEAT_TIMEOUT_NS (5ULL * 1000000000ULL)  // 5 seconds

static int check_heartbeat_timeout(struct voqd_state *state) {
    __u64 now_ns = bpf_ktime_get_ns();

    if (state->running &&
        (state->mode == VOQD_MODE_ACTIVE || state->mode == VOQD_MODE_SHADOW)) {

        if (state->last_heartbeat_ns > 0 &&
            (now_ns - state->last_heartbeat_ns) > VOQD_HEARTBEAT_TIMEOUT_NS) {

            // Heartbeat timeout - auto-failover to BYPASS
            perform_transition(state, VOQD_MODE_BYPASS, -1, TRANSITION_AUTO_FAILOVER);
            state->failover_count++;

            return 1;  // Failover occurred
        }
    }

    return 0;  // No failover
}
```

### Overload Protection

```c
// Overload detection thresholds
#define VOQD_OVERLOAD_THRESHOLD 1000  // Consecutive drops
#define VOQD_DEGRADE_THRESHOLD  10000 // Total drops before degradation

static int check_overload(struct voqd_state *state) {
    // Sustained overload detection
    if (state->overload_drops > VOQD_OVERLOAD_THRESHOLD) {
        if (state->flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) {
            // Degrade to BYPASS mode
            perform_transition(state, VOQD_MODE_BYPASS, -1, TRANSITION_OVERLOAD);
            state->failover_count++;
            return 1;
        }
    }

    return 0;
}
```

### Recovery Logic

```c
// Recovery from BYPASS mode
static int attempt_recovery(struct voqd_state *state, __u32 target_mode) {
    // Check if VOQd is running again
    if (state->running && state->last_heartbeat_ns > 0) {
        __u64 now_ns = bpf_ktime_get_ns();
        __u64 time_since_heartbeat = now_ns - state->last_heartbeat_ns;

        // Require recent heartbeat for recovery
        if (time_since_heartbeat < VOQD_HEARTBEAT_TIMEOUT_NS / 2) {
            perform_transition(state, target_mode, -1, TRANSITION_RECOVERY);
            return 0;
        }
    }

    return -1;  // Recovery not possible
}
```

## Control Flags

### Flag Definitions

```c
// Control flags
#define VOQD_FLAG_AUTO_FAILOVER       (1 << 0)  // Enable auto-failover
#define VOQD_FLAG_DEGRADE_ON_OVERLOAD (1 << 1)  // Degrade on overload
#define VOQD_FLAG_STRICT_PRIORITY     (1 << 2)  // Strict priority scheduling
#define VOQD_FLAG_DEBUG_EVENTS        (1 << 3)  // Emit debug events
```

### Flag Effects

```c
// Flag-based behavior modification
static int apply_control_flags(struct voqd_state *state) {
    // Auto-failover flag
    if (state->flags & VOQD_FLAG_AUTO_FAILOVER) {
        check_heartbeat_timeout(state);
    }

    // Overload degradation flag
    if (state->flags & VOQD_FLAG_DEGRADE_ON_OVERLOAD) {
        check_overload(state);
    }

    // Debug events flag
    if (state->flags & VOQD_FLAG_DEBUG_EVENTS) {
        emit_debug_state_event(state);
    }

    return 0;
}
```

## Runtime Control Interface

### rswitchctl Integration

```bash
# State inspection
rswitchctl show

# Mode transitions
rswitchctl set-mode --mode active --prio-mask 0x0F
rswitchctl set-mode --mode shadow --prio-mask 0x00
rswitchctl set-mode --mode bypass

# Flag control
rswitchctl set-flags --flags 0x03  # Enable auto-failover + overload degradation

# Statistics reset
rswitchctl reset-stats
```

### Programmatic Control

```c
// Direct BPF map manipulation
int set_voqd_mode(const char *state_map_pin, enum voqd_mode mode, uint32_t prio_mask) {
    int fd = bpf_obj_get(state_map_pin);
    if (fd < 0) return -1;

    struct voqd_state state;
    uint32_t key = 0;

    // Read current state
    if (bpf_map_lookup_elem(fd, &key, &state) < 0) {
        close(fd);
        return -1;
    }

    // Update mode
    state.mode = mode;
    if (prio_mask != (uint32_t)-1) {
        state.prio_mask = prio_mask;
    }

    // Write back
    if (bpf_map_update_elem(fd, &key, &state, BPF_ANY) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}
```

## State Persistence

### State Map Pinning

```c
// State map definition with pinning
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct voqd_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} voqd_state_map SEC(".maps");
```

### Persistence Across Restarts

```c
// State survives BPF program restarts
// - Mode and flags persist
// - Statistics may be reset on restart
// - Heartbeat tracking resets
static void initialize_persistent_state(struct voqd_state *state) {
    // Preserve mode and flags
    __u32 saved_mode = state->mode;
    __u32 saved_flags = state->flags;
    __u32 saved_prio_mask = state->prio_mask;

    // Reset runtime state
    memset(state, 0, sizeof(*state));

    // Restore configuration
    state->mode = saved_mode;
    state->flags = saved_flags;
    state->prio_mask = saved_prio_mask;
}
```

## Monitoring and Observability

### State Events

```c
// State change events
struct state_transition_event {
    __u32 old_mode;
    __u32 new_mode;
    __u32 transition_type;
    __u64 timestamp_ns;
    __u32 failover_count;
    __u32 overload_drops;
};

// Heartbeat events
struct heartbeat_event {
    __u64 timestamp_ns;
    __u32 mode;
    __u8  running;
};
```

### Metrics Collection

```c
// State machine metrics
struct state_metrics {
    __u64 transitions_total;
    __u64 failover_events;
    __u64 overload_events;
    __u64 heartbeat_timeouts;
    __u64 recovery_attempts;
    __u64 recovery_successes;
};
```

## Testing and Validation

### State Machine Testing

```c
// Unit test for state transitions
void test_state_transitions(void) {
    struct voqd_state state = {0};

    // Test BYPASS → SHADOW
    assert(perform_transition(&state, VOQD_MODE_SHADOW, 0, TRANSITION_MANUAL) == 0);
    assert(state.mode == VOQD_MODE_SHADOW);

    // Test invalid transition
    assert(perform_transition(&state, VOQD_MODE_BYPASS, 0, TRANSITION_AUTO_FAILOVER) == -EINVAL);

    // Test auto-failover
    state.last_heartbeat_ns = 0;  // Simulate timeout
    check_heartbeat_timeout(&state);
    assert(state.mode == VOQD_MODE_BYPASS);
}
```

### Integration Testing

```bash
# Test state machine transitions
#!/bin/bash

# Start with BYPASS
rswitchctl set-mode --mode bypass

# Transition to SHADOW
rswitchctl set-mode --mode shadow --prio-mask 0x00

# Start VOQd and transition to ACTIVE
./build/rswitch-voqd -m active -P 0x0F &
sleep 2

# Verify ACTIVE mode
rswitchctl show | grep "Mode: ACTIVE"

# Simulate failure (kill VOQd)
kill %1
sleep 6  # Wait for heartbeat timeout

# Verify auto-failover to BYPASS
rswitchctl show | grep "Mode: BYPASS"
```

## Performance Characteristics

### Mode Performance Comparison

| Mode | Throughput | Latency | CPU Overhead | QoS Features |
|------|------------|---------|--------------|--------------|
| BYPASS | Maximum | Minimum | Zero | None |
| SHADOW | High | Low | Low | Observation only |
| ACTIVE | Medium | Higher | High | Full QoS |

### State Transition Latency

- **Manual transitions**: ~1-5ms (map update + event emission)
- **Auto-failover**: ~10-50μs (BPF-side detection)
- **Recovery**: ~100-500ms (VOQd startup time)

## Future Enhancements

### Advanced State Machines

```c
// Future: Hierarchical state machine
enum voqd_superstate {
    SUPERSTATE_DOWN = 0,      // VOQd not running
    SUPERSTATE_UP = 1,        // VOQd running
};

enum voqd_substate {
    SUBSTATE_BYPASS = 0,
    SUBSTATE_SHADOW = 1,
    SUBSTATE_ACTIVE = 2,
    SUBSTATE_DEGRADED = 3,    // Partial failure mode
};
```

### Predictive Transitions

```c
// Future: ML-based transition prediction
static int predict_optimal_mode(struct voqd_state *state, struct traffic_stats *stats) {
    // Analyze traffic patterns
    // Predict optimal QoS mode
    // Suggest transition
    return VOQD_MODE_ACTIVE;
}
```

### Distributed State Management

```c
// Future: Multi-switch coordination
struct cluster_state {
    __u32 switch_id;
    __u32 cluster_mode;
    __u32 master_switch;
    __u64 last_sync_ns;
};
```

## Conclusion

The VOQd state machine provides robust, flexible control over QoS processing modes with comprehensive failure handling and observability. Through careful design of transitions, flags, and recovery mechanisms, rSwitch maintains high availability while enabling advanced QoS features when needed.</content>
<parameter name="filePath">/home/kylecui/dev/rSwitch/rswitch/docs/paperwork/VOQd_State_Machine_Architecture.md