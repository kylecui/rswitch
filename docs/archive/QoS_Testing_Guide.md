# QoS Testing Guide for rSwitch

## Quick Test Overview

This guide provides step-by-step instructions to verify QoS functionality in rSwitch.

## Prerequisites

1. rSwitch loader running with QoS profile:
   ```bash
   sudo ./build/rswitch_loader --profile etc/profiles/qos-voqd-test.yaml --ifaces ens33,ens34,ens35,ens36 --verbose
   ```

2. Required tools:
   - `bpftool` - BPF map inspection
   - `ping` or `hping3` - Generate test traffic with DSCP marking
   - `tcpdump` - Packet capture (optional)
   - `iperf3` - Bandwidth testing (optional)

## Test 1: Verify QoS Maps are Loaded

Check if QoS BPF maps are present:

```bash
# List all BPF maps
sudo bpftool map list | grep qos

# Expected output:
# - qos_class_map    (classification rules)
# - qos_rate_map     (rate limiters)
# - qos_qdepth_map   (queue depths)
# - qos_config_map   (per-port config)
```

Inspect a map:

```bash
# Show rate limiter configuration
sudo bpftool map dump name qos_rate_map

# Show queue depths
sudo bpftool map dump name qos_qdepth_map
```

## Test 2: Priority Classification (DSCP → Priority)

### Enable Debug Output

First, rebuild with debug enabled to see classification in action:

```bash
cd /home/kylecui/dev/rSwitch/rswitch
make clean
DEBUG=1 make

# Reload the loader
sudo pkill rswitch_loader
sudo ./build/rswitch_loader --profile etc/profiles/qos-voqd-test.yaml --ifaces ens33,ens34,ens35,ens36 --verbose
```

### Monitor BPF Trace Output

In one terminal, monitor the trace:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep QoS
```

### Send Test Packets

In another terminal, send packets with different DSCP values:

```bash
# Test CRITICAL priority (DSCP 46 = ToS 184)
# EF (Expedited Forwarding) - highest priority
ping -I ens33 -Q 184 -c 5 10.174.29.100

# Test HIGH priority (DSCP 32 = ToS 128)
# AF41 (Assured Forwarding Class 4)
ping -I ens33 -Q 128 -c 5 10.174.29.100

# Test NORMAL priority (DSCP 0 = ToS 0)
# Best Effort
ping -I ens33 -Q 0 -c 5 10.174.29.100

# Test LOW priority (DSCP 8 = ToS 32)
# CS1 (Class Selector 1)
ping -I ens33 -Q 32 -c 5 10.174.29.100
```

### Expected Trace Output

You should see classification messages like:

```
[rSwitch] QoS: Classified proto=1 dport=0 dscp=46 → priority=3
[rSwitch] QoS: processed priority=3 egress=2
```

Priority mapping from `qos-voqd-test.yaml`:
- DSCP 46 (EF) → Priority 3 (CRITICAL)
- DSCP 32-38 (AF4x) → Priority 2 (HIGH)
- DSCP 16-22 (AF2x) → Priority 1 (NORMAL)
- DSCP 0-14 (BE/AF1x) → Priority 0 (LOW)

## Test 3: Rate Limiting

Rate limiting drops packets when traffic exceeds configured rates.

### Check Current Rate Limits

```bash
sudo bpftool map dump name qos_rate_map
```

Output shows per-priority rate limiters with fields:
- `rate_bps` - Rate in bytes per second
- `burst_bytes` - Burst allowance
- `tokens` - Current token count
- `total_bytes` - Total bytes processed
- `dropped_bytes` - Bytes dropped due to rate limiting
- `dropped_packets` - Packets dropped

### Generate High-Bandwidth Traffic

Use `iperf3` for controlled bandwidth testing:

```bash
# On target machine (e.g., 10.174.29.100), start server:
iperf3 -s

# On switch interface, generate traffic exceeding rate limit:
# Assuming LOW priority (DSCP 0) has 10 Mbps limit
iperf3 -c 10.174.29.100 -t 10 -b 50M -S 0x00

# Check drops in real-time
watch -n 1 "sudo bpftool map dump name qos_rate_map | grep -A5 'key: 00 00 00 00'"
```

### Expected Behavior

- Traffic **below** rate limit: No drops, `dropped_packets` stays 0
- Traffic **above** rate limit: `dropped_packets` increases

### Monitor with Script

```bash
sudo ./tools/qos_monitor.sh
```

This displays real-time QoS statistics including:
- Rate limiter status per priority
- Drop counts and percentages
- Queue depths
- Port statistics

## Test 4: Queue Depth and Congestion

Queue depth monitoring detects congestion and can trigger:
- ECN marking (if enabled)
- Selective drops
- AF_XDP redirection to VOQd

### Monitor Queue Depths

```bash
# Continuous monitoring
watch -n 1 "sudo bpftool map dump name qos_qdepth_map"
```

### Generate Congestion

```bash
# Flood traffic to trigger queue buildup
# Use multiple flows simultaneously
for i in {1..5}; do
    ping -f -I ens33 10.174.29.10$i &
done

# Wait a few seconds, then check queue depths
sudo bpftool map dump name qos_qdepth_map

# Stop flood
pkill ping
```

### Expected Output

During congestion:
```
key: 00 00 00 00  value: XX XX 00 00  # Priority 0 queue depth
key: 01 00 00 00  value: YY YY 00 00  # Priority 1 queue depth
```

If queue depth > threshold (typically 1000-2000), QoS may:
- Mark packets with ECN (Explicit Congestion Notification)
- Drop lower-priority packets first
- Redirect high-priority traffic to VOQd for better scheduling

## Test 5: AF_XDP Redirection (Advanced)

This test requires VOQd (user-space scheduler) running.

### Check VOQd Status

```bash
sudo bpftool map dump name voqd_state_map
```

Output fields:
- `running`: 1 = VOQd alive, 0 = dead
- `mode`: 0 = BYPASS, 1 = SHADOW, 2 = ACTIVE
- `prio_mask`: Which priorities to intercept (bitmask)

### VOQd Modes

- **BYPASS**: All traffic stays in XDP fast-path (VOQd not involved)
- **SHADOW**: VOQd observes traffic but doesn't intercept (testing mode)
- **ACTIVE**: High-priority traffic redirected to VOQd for sophisticated scheduling

### Test AF_XDP Redirect

1. **Start VOQd** (if not running):
   ```bash
   sudo ./build/rswitch-voqd -p 4 -m active -P 0x0C -i ens33,ens34,ens35,ens36
   ```

2. **Verify VOQd is active**:
   ```bash
   sudo bpftool map dump name voqd_state_map
   # Should show: running=1, mode=2 (ACTIVE)
   ```

3. **Send high-priority traffic**:
   ```bash
   # CRITICAL priority (should be intercepted if prio_mask includes bit 3)
   ping -I ens33 -Q 184 -c 10 10.174.29.100
   ```

4. **Check AF_XDP statistics**:
   ```bash
   sudo bpftool map dump name afxdp_stats_map
   ```

### Expected Behavior

- **BYPASS mode**: All traffic processed by XDP, no AF_XDP redirection
- **SHADOW mode**: VOQd observes, XDP still forwards (zero impact)
- **ACTIVE mode**: High-priority packets (matching `prio_mask`) redirected to VOQd

## Test 6: Port Statistics

Verify that QoS is updating port statistics correctly.

```bash
# Dump port statistics
sudo bpftool map dump name rs_stats_map

# Fields per port:
# - rx_packets / rx_bytes (ingress)
# - tx_packets / tx_bytes (egress, after QoS)
# - tx_drops (QoS drops)
# - rx_drops
```

Generate traffic and observe counters incrementing:

```bash
# In terminal 1: Monitor stats
watch -n 1 "sudo bpftool map dump name rs_stats_map"

# In terminal 2: Generate traffic
ping -c 100 -i 0.01 10.174.29.100
```

## Automated Test Suite

Run comprehensive tests:

```bash
# Make scripts executable
chmod +x tools/test_qos.sh tools/qos_monitor.sh

# Run all tests
sudo ./tools/test_qos.sh --test all --verbose

# Run specific test
sudo ./tools/test_qos.sh --test priority
sudo ./tools/test_qos.sh --test ratelimit

# Enable debug output during tests
sudo ./tools/test_qos.sh --debug --test all
```

## Troubleshooting

### No QoS trace output

**Problem**: No "QoS: Classified" messages in trace_pipe

**Solutions**:
1. Rebuild with `DEBUG=1 make`
2. Check if QoS module is loaded: `sudo bpftool prog list | grep qos`
3. Verify egress pipeline is executing (see earlier fix for afxdp_redirect)

### No rate limiting drops

**Problem**: `dropped_packets` stays 0 even with high traffic

**Causes**:
1. Rate limit not configured (default is unlimited)
2. Traffic rate below limit
3. Token bucket burst absorbing all traffic

**Solutions**:
1. Check rate limit config: `sudo bpftool map dump name qos_rate_map`
2. Generate sustained high-bandwidth traffic (>10 seconds)
3. Reduce burst size to trigger drops faster

### QoS maps not found

**Problem**: `bpftool map list` doesn't show qos_* maps

**Solutions**:
1. Check if QoS module is in profile: `cat etc/profiles/qos-voqd-test.yaml | grep qos`
2. Verify loader loaded QoS: Check loader output for "qos (fd=XX)"
3. Check for pinned maps: `ls /sys/fs/bpf/ | grep qos`

### VOQd not intercepting traffic

**Problem**: AF_XDP redirect not working

**Causes**:
1. VOQd not running (`running=0` in voqd_state_map)
2. Mode is BYPASS or SHADOW (not ACTIVE)
3. Priority mask doesn't match packet priority

**Solutions**:
1. Start VOQd: `sudo ./build/rswitch-voqd -m active`
2. Check mode: `sudo bpftool map dump name voqd_state_map`
3. Verify prio_mask matches test traffic priority

## Performance Metrics

Expected QoS overhead:
- Priority classification: ~20-50 ns/packet
- Rate limiting check: ~30-100 ns/packet
- Queue depth lookup: ~10-20 ns/packet
- Total QoS overhead: <200 ns/packet (~5 million PPS max)

Measure with:
```bash
# Before enabling QoS
iperf3 -c <target> -t 10

# After enabling QoS
iperf3 -c <target> -t 10

# Compare throughput (should be <5% difference for fast-path)
```

## Next Steps

Once basic QoS is working:

1. **Fine-tune rate limits**: Adjust per-priority rates in YAML profile
2. **Test congestion control**: Generate simultaneous flows to trigger drops
3. **AF_XDP integration**: Start VOQd for advanced scheduling
4. **Telemetry export**: Enable Prometheus/Kafka for monitoring
5. **ML-based tuning**: Use telemetry for adaptive policy (future)

## References

- QoS module: `bpf/modules/qos.bpf.c`
- AF_XDP redirect: `bpf/modules/afxdp_redirect.bpf.c`
- Profile: `etc/profiles/qos-voqd-test.yaml`
- Data plane design: `docs/data_plane_desgin_with_af_XDP.md`
