> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch Software Queues Test Guide

This guide explains how to test the new software queue simulation feature in rSwitch, which allows QoS functionality on NICs without multiple hardware queues.

## Overview

The software queues feature enables rSwitch to provide QoS capabilities on inexpensive NICs by simulating virtual output queues in user space, eliminating the dependency on hardware queue count.

## Quick Start

### 1. Build the Project
```bash
make all
```

### 2. Run Basic Test
```bash
sudo ./test-software-queues.sh
```

### 3. Manual Testing

#### Option A: Shadow Mode (Recommended for Testing)
```bash
# Terminal 1: Load rSwitch
sudo ./build/rswitch_loader -p qos-software-queues-test

# Terminal 2: Start VOQd with software queues
sudo ./build/rswitch-voqd -m shadow -q -Q 2048 -p 2 -P 0x0F -s -S 5

# Terminal 3: Monitor statistics
watch -n 2 'sudo ./build/rsvoqctl show-stats'
```

#### Option B: Active Mode (Requires AF_XDP Capable Interface)
```bash
# Create dummy interface for testing
sudo modprobe dummy
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up

# Start VOQd in active mode
sudo ./build/rswitch-voqd -m active -q -Q 2048 -p 2 -P 0x0F -i lo,dummy0 -s -S 5
```

## Test Scenarios

### 1. Basic Functionality Test
- **Purpose**: Verify software queues initialize correctly
- **Command**: `./test-software-queues.sh --shadow-only`
- **Expected**: VOQd starts with "Software queue simulation enabled" message

### 2. Active Mode Test
- **Purpose**: Test full QoS processing with software queues
- **Command**: `./test-software-queues.sh --active-only`
- **Expected**: Packets are processed through software queues

### 3. Full Pipeline Test
- **Purpose**: Test complete rSwitch + VOQd integration
- **Command**: `./test-software-queues.sh --full-only`
- **Expected**: Both rSwitch loader and VOQd run successfully

### 4. Performance Test
- **Purpose**: Measure performance impact of software queues
- **Command**: `./test-software-queues.sh --perf-only`
- **Expected**: Packet processing statistics and resource usage

## Configuration Options

### VOQd Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-m mode` | Operating mode | `-m shadow` or `-m active` |
| `-q` | Enable software queues | `-q` |
| `-Q depth` | Queue depth per port/priority | `-Q 2048` |
| `-p ports` | Number of ports | `-p 2` |
| `-P mask` | Priority mask | `-P 0x0F` (all priorities) |
| `-i interfaces` | Interface list (active mode) | `-i eth0,eth1` |
| `-s` | Enable scheduler | `-s` |
| `-S interval` | Stats interval (seconds) | `-S 5` |

### Priority Masks

| Mask | Priorities | Description |
|------|------------|-------------|
| `0x01` | LOW | Best Effort traffic |
| `0x02` | NORMAL | Standard traffic |
| `0x04` | HIGH | Important traffic |
| `0x08` | CRITICAL | Mission-critical traffic |
| `0x0F` | ALL | All priority levels |

## Generating Test Traffic

### DSCP Traffic Generation
```bash
# Expedited Forwarding (EF) - Critical priority
ping -Q 0xb8 192.168.1.1

# Assured Forwarding 41 (AF41) - High priority
ping -Q 0x80 192.168.1.1

# Assured Forwarding 21 (AF21) - Normal priority
ping -Q 0x40 192.168.1.1

# Best Effort (BE) - Low priority
ping 192.168.1.1
```

### High Volume Traffic (for performance testing)
```bash
# Flood ping with specific DSCP
sudo ping -f -Q 0xb8 192.168.1.1

# Use iperf with DSCP marking
iperf -c 192.168.1.1 -u -b 100M -S 0xb8
```

## Monitoring and Validation

### Real-time Statistics
```bash
# VOQd statistics
watch -n 2 'sudo ./build/rsvoqctl show-stats'

# System resources
watch -n 2 'ps aux | grep rswitch-voqd'
```

### Log Analysis
```bash
# Check for software queue initialization
grep "Software queue simulation enabled" /var/log/rswitch.log

# Monitor packet processing
tail -f /tmp/rswitch-software-queues-test.log
```

### BPF Map Inspection
```bash
# Check ringbuf contents
sudo bpftool map dump name voq_ringbuf

# List all rSwitch BPF maps
sudo bpftool map list | grep rs
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
**Error**: `Failed to open state_map: Permission denied`
**Solution**: Run with sudo, ensure BPF filesystem is mounted

#### 2. Interface Not Found
**Error**: `Invalid interface name`
**Solution**: Use `ip link show` to verify interface names

#### 3. AF_XDP Not Supported
**Error**: `AF_XDP socket creation failed`
**Solution**: Use shadow mode or check NIC AF_XDP support

#### 4. No Packet Processing
**Issue**: Statistics show zero packets
**Solution**: Generate traffic and ensure interfaces are configured

### Debug Mode
Enable debug logging for detailed information:
```bash
# Set log level to debug in the profile
# Or use environment variable
export RSWITCH_LOG_LEVEL=debug
```

### Cleanup
```bash
# Stop all processes
sudo pkill rswitch-voqd
sudo pkill rswitch_loader

# Clean up BPF maps
sudo ./scripts/unpin_maps.sh

# Remove test interfaces
sudo ip link delete dummy0 2>/dev/null || true
```

## Performance Expectations

### Shadow Mode (Observation Only)
- **CPU Usage**: < 15%
- **Memory Usage**: ~50MB
- **Latency**: Minimal impact on data plane

### Active Mode (Full Processing)
- **CPU Usage**: 20-60% (depends on traffic)
- **Memory Usage**: 50-200MB
- **Throughput**: Limited by software queue performance

## Advanced Testing

### Custom Profile Creation
Create your own test profile by copying `qos-software-queues-test.yaml` and modifying:

- Interface configurations
- Queue depths and priorities
- DSCP mappings
- Performance parameters

### Integration Testing
Test with real applications:
```bash
# VoIP traffic (EF)
sudo ./build/rswitch-voqd -m active -q -Q 1024 -p 4 -P 0x08 -i eth0,eth1,eth2,eth3

# Video streaming (AF4x)
sudo ./build/rswitch-voqd -m active -q -Q 2048 -p 4 -P 0x04 -i eth0,eth1,eth2,eth3
```

## Support

For issues or questions:
1. Check the test logs: `/tmp/rswitch-software-queues-test.log`
2. Run diagnostic: `sudo ./scripts/voqd_check.sh`
3. Review documentation: `docs/Module_Developer_Guide.md`

---

**Note**: Software queues provide QoS functionality but may have lower performance than hardware queues. Use hardware queues when available for optimal performance.