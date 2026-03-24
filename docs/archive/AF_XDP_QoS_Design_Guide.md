> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch AF_XDP and QoS Design and Implementation Guide

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Design Philosophy](#design-philosophy)
3. [AF_XDP Integration](#af_xdp-integration)
4. [QoS System Design](#qos-system-design)
5. [Software Queues Implementation](#software-queues-implementation)
6. [Operating Modes](#operating-modes)
7. [Configuration Guide](#configuration-guide)
8. [Testing and Validation](#testing-and-validation)
9. [Troubleshooting](#troubleshooting)
10. [Performance Considerations](#performance-considerations)

## Architecture Overview

rSwitch is a modular, eBPF/XDP-based network switch that provides advanced networking features including QoS, ACLs, VLANs, and user-space data plane extensions via AF_XDP.

### Core Components

1. **eBPF/XDP Pipeline**: High-performance packet processing pipeline
2. **AF_XDP Integration**: User-space packet redirection for advanced processing
3. **VOQd (Virtual Output Queue Daemon)**: User-space QoS scheduler
4. **Software Queues**: Hardware-independent QoS implementation
5. **Control Plane**: Runtime configuration and monitoring

### Pipeline Flow

#### Complete Packet Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INGRESS TRAFFIC                               │
└─────────────────┬───────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           XDP INGRESS PIPELINE                             │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │  DISPATCHER │───▶│   MODULES   │───▶│AF_XDP REDIR│───▶│  LASTCALL   │   │
│  │             │    │   CHAIN     │    │             │    │             │   │
│  └─────────────┘    └─────────────┘    └──────┬──────┘    └──────┬──────┘   │
│                                               │                   │          │
│                                               │                   │          │
│                                               ▼                   ▼          │
│                                    ┌────────────────────┐    ┌─────────────┐ │
│                                    │   RINGBUF METADATA │───▶│   DEVMAP    │ │
│                                    │     → VOQd        │    │ REDIRECT    │ │
│                                    └────────────────────┘    └─────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           EGRESS TRAFFIC                                   │
└─────────────────┬───────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           XDP EGRESS PIPELINE                              │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │ EGRESS_HOOK │───▶│EGRESS MODULE│───▶│ EGRESS QoS │───▶│EGRESS_FINAL │   │
│  │             │    │   CHAIN     │    │             │    │             │   │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Mode-Specific Processing Paths

##### BYPASS Mode (Zero Overhead)
```
Packet → Dispatcher → VLAN/L2Learn → LastCall → Devmap Redirect → Egress Pipeline
```

##### SHADOW Mode (Observation Only)
```
Packet → Dispatcher → VLAN/L2Learn → AF_XDP Redirect → Ringbuf → VOQd → Continue Fast-Path
                                                            ↓
                                                    Metadata Analysis Only
```

##### ACTIVE Mode (Full QoS Processing)
```
Packet → Dispatcher → VLAN/L2Learn → AF_XDP Redirect → Ringbuf → VOQd → AF_XDP Socket
                              ↓                           ↓
                       Check Socket Available    Metadata Processing
                              ↓                           ↓
                       Socket Available? → YES → Packet Redirected to User-Space
                              ↓
                             NO → Continue Fast-Path (Hardware Queue Unavailable)
```

#### Key Pipeline Components

##### Ingress Pipeline Modules
- **Dispatcher**: Entry point, shared context initialization
- **VLAN**: VLAN processing and isolation
- **L2Learn**: MAC learning and forwarding table updates
- **AF_XDP Redirect**: QoS traffic interception and user-space redirection
- **LastCall**: Final forwarding decision and devmap lookup

##### Egress Pipeline Modules
- **Egress Hook**: Devmap-triggered egress processing
- **Egress VLAN**: VLAN tagging and egress isolation
- **Egress QoS**: Congestion control and rate limiting
- **Egress Final**: Final packet adjustments and transmission

##### User-Space Components
- **VOQd**: Virtual Output Queue daemon for QoS scheduling
- **Software Queues**: Hardware-independent queue management
- **AF_XDP Sockets**: User-space packet I/O interfaces

## Design Philosophy

### Zero-Overhead Fast Path
- **BYPASS Mode**: Pure XDP fast-path with minimal overhead
- **SHADOW Mode**: Metadata observation without packet redirection
- **ACTIVE Mode**: Full QoS processing with user-space integration

### Hardware Independence
- **Software Queues**: QoS fallback for NICs without hardware queue support
- **Adaptive Queue Detection**: Automatic fallback based on NIC capabilities
- **Graceful Degradation**: Maintains functionality even with limited hardware

### Modular Architecture
- **Plugin-based Modules**: Independent feature modules
- **Tail-call Pipeline**: Efficient module chaining
- **Runtime Reconfiguration**: Hot-swappable components

## AF_XDP Integration

### Purpose
AF_XDP enables user-space packet processing while maintaining kernel bypass performance, allowing complex QoS algorithms and traffic shaping that would be difficult or impossible in eBPF.

### Implementation Details

#### Socket Management
```c
// AF_XDP socket creation with queue mapping
int voqd_dataplane_add_port(struct voqd_dataplane *dp,
                           const char *ifname,
                           uint32_t port_idx,
                           uint32_t queue_id)
```

#### Queue Mapping
- **Single Queue NICs**: Use queue 0 for all traffic
- **Multi-Queue NICs**: Map priorities to different queues
- **Adaptive Detection**: Automatically detect available queues

#### Socket Registration
```c
// Register AF_XDP socket in xsks_map for kernel redirection
bpf_map_update_elem(xsks_map_fd, &queue_id, &socket_fd, BPF_ANY);
```

### Kernel-User Communication

#### Ringbuf Metadata Exchange
```c
struct voq_meta {
    __u64 ts_ns;        // Timestamp
    __u32 eg_port;      // Egress port index
    __u8 prio;          // Packet priority
    __u32 len;          // Packet length
    __u32 flow_hash;    // Flow identification
    __u8 ecn_hint;      // ECN marking hint
    __u8 drop_hint;     // Drop recommendation
};
```

#### State Synchronization
- **Heartbeat Mechanism**: Detect VOQd failures
- **Mode Transitions**: Runtime mode changes
- **Overload Protection**: Automatic fallback on congestion

## QoS System Design

### Priority Classification

#### DSCP-based Classification
```c
// Standard DiffServ mapping
DSCP 46 (EF)     → CRITICAL (3)
DSCP 32-38 (AF4x) → HIGH (2)
DSCP 16-22 (AF2x) → NORMAL (1)
DSCP 0-14 (AF1x) → LOW (0)
```

#### Multi-Source Priority
1. **Pre-classified**: From upstream modules (ACL, ingress QoS)
2. **DSCP Extraction**: Direct packet header inspection
3. **Default Priority**: Configurable fallback

### Queue Management

#### Hardware Queues (Preferred)
- **AF_XDP Queues**: Direct user-space access via AF_XDP sockets
- **NIC Hardware Queues**: Multiple TX queues for prioritization
- **Queue Mapping**: Priority-to-queue assignment
- **Performance**: Maximum throughput with minimal latency

#### Software Queues (Fallback)
- **Virtual Queues**: User-space queue simulation when hardware unavailable
- **Per-Port, Per-Priority**: Fine-grained traffic control
- **Dynamic Sizing**: Configurable queue depths
- **Overhead**: Additional processing and memory usage

### Scheduling Algorithms

#### Deficit Round Robin (DRR)
```c
struct queue_config {
    uint32_t quantum;      // DRR quantum
    uint32_t max_depth;    // Maximum queue depth
    uint32_t priority;     // Queue priority
};
```

#### Priority-based Scheduling
- **Strict Priority**: Higher priority queues served first
- **Weighted Fair Queuing**: Bandwidth allocation
- **Rate Limiting**: Token bucket implementation

## Software Queues Implementation

### Priority and Usage
**Software queues are used ONLY when NIC hardware cannot provide the required queue support.** The system always attempts to use hardware queues (AF_XDP) first for optimal performance. Software queues serve as a fallback mechanism to enable QoS functionality on commodity hardware.

### Purpose
Software queues provide QoS functionality as a fallback mechanism when NIC hardware does not support multiple queues or AF_XDP sockets. They enable QoS deployment on commodity hardware that lacks advanced networking features.

### When Software Queues Are Used

#### Hardware Limitations
- **Single Queue NICs**: Only have rx-0/tx-0 queues
- **No AF_XDP Support**: Older NICs without AF_XDP capability
- **Limited Queue Count**: Insufficient hardware queues for priority levels

#### Fallback Scenarios
- **AF_XDP Socket Creation Failure**: Cannot bind to required queues
- **Hardware Queue Exhaustion**: All available queues already in use
- **Configuration Constraints**: System limitations prevent hardware queue usage

### Architecture

#### Queue Structure
```c
struct sw_queue_mgr {
    struct sw_queue queues[MAX_PORTS][MAX_PRIORITIES];
    uint32_t num_ports;
    uint32_t num_priorities;
    uint32_t total_depth;
};

struct sw_queue {
    struct sw_queue_entry *head;
    struct sw_queue_entry *tail;
    uint32_t depth;
    uint64_t enqueued;
    uint64_t dequeued;
    uint64_t dropped;
};
```

#### Memory Management
- **Pre-allocated Pools**: Fixed-size packet buffers
- **Zero-copy Operation**: Minimize memory copies
- **Efficient Allocation**: Fast buffer management

### Integration with AF_XDP

#### Packet Flow (When Hardware Queues Available)
```
Kernel Packet → AF_XDP Socket → Hardware Queue → NIC Transmission
```

#### Packet Flow (Software Queues Fallback)
```
Kernel Packet → Ringbuf Metadata → VOQd → Software Queue → AF_XDP Socket → Transmission
```

#### Metadata Processing
- **Ringbuf Events**: Kernel metadata notifications
- **Queue Assignment**: Priority-based enqueue
- **Scheduling Decisions**: User-space QoS algorithms

## Operating Modes

### BYPASS Mode
- **Purpose**: Maximum performance, minimal overhead
- **Behavior**: Pure XDP fast-path, no user-space involvement
- **Use Case**: High-throughput scenarios without QoS requirements

### SHADOW Mode
- **Purpose**: Traffic observation and learning
- **Behavior**: Submit metadata to ringbuf, continue fast-path
- **Use Case**: Traffic analysis, QoS policy development

### ACTIVE Mode
- **Purpose**: Full QoS processing with user-space control
- **Behavior**: Redirect qualifying packets to AF_XDP sockets
- **Use Case**: Production QoS deployment

### Mode Transitions

#### Automatic Failover
```c
// Heartbeat timeout detection
if (now_ns - last_heartbeat > TIMEOUT) {
    mode = BYPASS;  // Automatic fallback
}
```

#### Manual Control
```bash
# Runtime mode changes
sudo ./build/rsvoqctl set-mode active
sudo ./build/rsvoqctl set-mode shadow
sudo ./build/rsvoqctl set-mode bypass
```

## Configuration Guide

### Profile-based Configuration

#### YAML Configuration Structure
```yaml
name: qos-voqd-test
ingress:
  - vlan
  - l2learn
  - afxdp_redirect
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final

voqd_config:
  mode: active
  enable_afxdp: true
  enable_sw_queues: true
  prio_mask: 0x0F
```

### Runtime Configuration

#### Priority Mask Control
```bash
# Enable HIGH and CRITICAL priorities
sudo ./build/rsvoqctl activate 0xC

# Enable all priorities
sudo ./build/rsvoqctl activate 0xF
```

#### Queue Configuration
```bash
# Set queue parameters
sudo ./build/rsvoqctl set-queue-params --port 0 --prio 3 --quantum 2048 --max-depth 8192
```

### Interface Configuration

#### Port Mapping
```c
// Automatic ifindex to port_idx mapping
__u32 port_idx = 0;  // Array index
bpf_map_update_elem(ifindex_to_port_map, &ifindex, &port_idx, BPF_ANY);
```

#### VLAN Configuration
```yaml
ports:
  - interface: ens34
    mode: access
    access_vlan: 1
    qos_config:
      enable_afxdp: true
      prio_mask: 0x0C
```

## Testing and Validation

### Test Scenarios

#### Basic Functionality Test
```bash
# Generate DSCP-marked traffic
ping -Q 0xb8 192.168.1.1  # EF (Critical)
ping -Q 0x80 192.168.1.1  # AF41 (High)
ping -Q 0x40 192.168.1.1  # AF21 (Normal)
ping 192.168.1.1          # BE (Low)
```

#### Performance Testing
```bash
# High-volume traffic generation
iperf -c 192.168.1.1 -u -b 100M -S 0xb8
```

### Monitoring and Statistics

#### Real-time Statistics
```bash
# VOQd statistics
watch -n 2 'sudo ./build/rsvoqctl show-stats'

# Data plane statistics
watch -n 2 'sudo ./build/rsvoqctl show-dataplane'
```

#### BPF Map Inspection
```bash
# Check ringbuf contents
sudo bpftool map dump name voq_ringbuf

# Inspect socket registration
sudo bpftool map dump id $(sudo bpftool map list | grep xsks_map | awk '{print $1}' | sed 's/://')
```

### Log Analysis

#### Debug Logging
```bash
# Enable detailed logging
bpf_printk("[AF_XDP] Processing priority %u in mode %d", prio, mode);
bpf_printk("[AF_XDP] Submitted metadata for prio %u", prio);
bpf_printk("[AF_XDP] No AF_XDP socket, continuing with fast-path");
```

#### Trace Analysis
```bash
# Capture eBPF trace events
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep rSwitch
```

## Troubleshooting

### Common Issues

#### AF_XDP Socket Creation Failure
**Symptoms**: "Invalid argument" error
**Cause**: Queue ID mismatch (queue doesn't exist)
**Solution**: Use queue 0 for single-queue NICs

#### No Packet Processing
**Symptoms**: Statistics show zero packets
**Cause**: Incorrect interface configuration or mode
**Solution**: Verify interface names and operating mode

#### Ringbuf Full
**Symptoms**: Packet drops due to ringbuf overflow
**Cause**: VOQd not consuming metadata fast enough
**Solution**: Increase ringbuf size or optimize VOQd performance

#### Mode Transition Failures
**Symptoms**: VOQd fails to change modes
**Cause**: State synchronization issues
**Solution**: Restart VOQd or check heartbeat mechanism

### Diagnostic Tools

#### Health Checks
```bash
# VOQd health check
sudo ./scripts/voqd_check.sh

# BPF map validation
sudo ./scripts/verify_pin_paths.sh
```

#### Performance Profiling
```bash
# CPU usage analysis
perf top -p $(pgrep rswitch-voqd)

# Memory usage
sudo pmap $(pgrep rswitch-voqd)
```

## Performance Considerations

### Throughput Expectations

#### Hardware Queues (AF_XDP)
- **Single Queue**: 1-5 Gbps (NIC dependent)
- **Multiple Queues**: 5-10 Gbps with QoS
- **Zero Copy**: Minimal CPU overhead
- **Latency**: < 10μs additional processing

#### Software Queues (Fallback)
- **Throughput**: 500 Mbps - 2 Gbps (CPU limited)
- **CPU Usage**: 20-60% (traffic dependent)
- **Latency**: 50-200μs additional processing
- **Memory**: Higher memory usage for queue buffers

### Optimization Strategies

#### Kernel Bypass
- **XDP Native Mode**: Maximum performance
- **Batch Processing**: Reduce per-packet overhead
- **Memory Alignment**: Optimize cache performance

#### User Space Efficiency
- **Thread Affinity**: Pin threads to CPU cores
- **Batch Operations**: Process multiple packets together
- **Memory Pools**: Pre-allocated buffer management

### Scalability Limits

#### Port Count
- **Hardware Queues**: Limited by NIC capabilities
- **Software Queues**: Limited by CPU and memory

#### Priority Levels
- **Standard**: 4 priorities (Low, Normal, High, Critical)
- **Extended**: Up to 8 priorities with custom mapping

#### Queue Depths
- **Minimum**: 512 packets per queue
- **Maximum**: 8192 packets per queue
- **Default**: 2048 packets per queue

## Future Enhancements

### Planned Features
1. **Hardware Offload Integration**: Utilize NIC QoS features when available
2. **Machine Learning Classification**: AI-powered traffic classification
3. **Distributed QoS**: Multi-switch coordination
4. **Real-time Analytics**: Advanced telemetry and monitoring

### Research Areas
1. **Congestion Control**: Advanced ECN and RED algorithms
2. **Traffic Shaping**: Complex bandwidth allocation schemes
3. **Quality Metrics**: MOS scoring and user experience monitoring

---

## Conclusion

The rSwitch AF_XDP and QoS implementation provides a flexible, high-performance networking solution that adapts to various hardware capabilities while maintaining software-defined control. The modular architecture enables easy extension and customization for specific use cases.

Key design principles:
- **Hardware Optimization**: Leverages NIC hardware queues when available
- **Software Fallback**: Provides QoS on commodity hardware through software queues
- **Zero Performance Impact**: BYPASS mode provides native XDP performance
- **Graceful Degradation**: Maintains functionality even with limited hardware
- **Runtime Flexibility**: Dynamic mode changes and configuration

This design enables QoS deployment on any hardware while providing optimal performance on capable NICs.