# VOQd Usage Guide

## Quick Start

### 1. Build

```bash
cd rswitch/
make clean && make
```

**Output**:
- `build/rswitch-voqd` - VOQd daemon (115K)
- `build/rsvoqctl` - VOQ control tool (29K)

### 2. Basic Usage

#### Metadata-Only Mode (SHADOW)

```bash
# Run without AF_XDP (metadata from ringbuf only)
sudo ./build/rswitch-voqd -p 4 -m shadow -s -S 10
```

**Features**:
- Consumes metadata from XDP ringbuf
- Enqueues into VOQ with `xdp_frame_addr=0`
- Tests VOQ scheduling logic
- No actual packet forwarding
- Works without AF_XDP support

#### AF_XDP Mode (ACTIVE)

```bash
# Run with AF_XDP data plane
sudo ./build/rswitch-voqd \
    -p 4 \
    -m active \
    -P 0x0F \
    -i ens33,ens34,ens35,ens36 \
    -s \
    -S 10
```

**Features**:
- Full user-space packet processing
- AF_XDP RX/TX sockets
- RX thread: Poll → Extract priority → VOQ enqueue
- TX thread: DRR scheduler → AF_XDP transmit
- Token bucket rate limiting

## Command-Line Options

### Core Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --ports NUM` | Number of ports | 4 |
| `-m, --mode MODE` | Operating mode: bypass/shadow/active | bypass |
| `-P, --prio-mask MASK` | Priority interception mask (bitmask) | 0x00 |
| `-S, --stats INTERVAL` | Stats print interval (seconds) | 10 |

### AF_XDP Options

| Option | Description | Required in ACTIVE |
|--------|-------------|-------------------|
| `-i, --interfaces IFLIST` | Comma-separated interface names | **Yes** |
| `-z, --zero-copy` | Enable zero-copy mode (requires driver support) | No |

### Scheduler Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --scheduler` | Enable VOQ scheduler thread | Disabled |

**Note**: In ACTIVE mode with AF_XDP, scheduler is handled by data plane TX thread.

## Operating Modes

### BYPASS Mode

**State**: Fail-safe, no VOQd involvement

```bash
sudo ./build/rswitch-voqd -p 4 -m bypass
```

**Behavior**:
- XDP devmap redirect only
- No user-space processing
- Guaranteed connectivity (even if VOQd crashes)
- Heartbeat sent to prevent auto-failover

**Use Case**: Default safe state, recovery from failures

### SHADOW Mode

**State**: Observation, no takeover

```bash
sudo ./build/rswitch-voqd -p 4 -m shadow -s -S 5
```

**Behavior**:
- Consumes ringbuf metadata events
- VOQ enqueue with metadata only
- Scheduler builds queues (simulation)
- XDP still handles all forwarding
- Zero risk, pure telemetry

**Use Case**:
- Validate configuration
- Calibrate DRR weights
- Measure baseline performance
- Test VOQ logic without affecting traffic

### ACTIVE Mode

**State**: Full control, high-priority traffic redirected

```bash
sudo ./build/rswitch-voqd \
    -p 4 \
    -m active \
    -P 0x08 \
    -i ens33,ens34,ens35,ens36 \
    -s
```

**Behavior**:
- High-priority flows (`prio_mask`) redirected via CPUMAP
- AF_XDP RX/TX sockets process packets
- VOQ scheduler with DRR + token bucket
- Low-priority flows remain in XDP fast-path
- Full user-space control over specified priorities

**Use Case**:
- Production traffic management
- Per-priority QoS enforcement
- Rate limiting with token buckets
- Policy-based forwarding

## Priority Mask

Bitmask controlling which priorities are intercepted in ACTIVE mode:

| Mask | Priority | Description |
|------|----------|-------------|
| `0x01` | LOW (0) | Best-effort traffic |
| `0x02` | NORMAL (1) | Standard traffic |
| `0x04` | HIGH (2) | Priority traffic |
| `0x08` | CRITICAL (3) | Time-sensitive traffic |
| `0x0F` | ALL | All priorities |

**Examples**:

```bash
# Only critical traffic
-P 0x08

# High and critical
-P 0x0C

# All priorities
-P 0x0F
```

## Configuration with rsvoqctl

### Port Rate Limiting

```bash
# Set port 0: 100 Mbps with 64KB burst
sudo ./build/rsvoqctl set-port-rate \
    --port 0 \
    --rate 100000000 \
    --burst 65536

# Set port 1: 1 Gbps with 128KB burst
sudo ./build/rsvoqctl set-port-rate \
    --port 1 \
    --rate 1000000000 \
    --burst 131072
```

**Parameters**:
- `--rate`: Bits per second (token refill rate)
- `--burst`: Burst bytes (maximum token bucket size)

### Per-Priority Queue Parameters

```bash
# Configure critical priority (prio=3)
sudo ./build/rsvoqctl set-queue-params \
    --port 0 \
    --prio 3 \
    --quantum 2048 \
    --max-depth 8192

# Configure low priority (prio=0)
sudo ./build/rsvoqctl set-queue-params \
    --port 0 \
    --prio 0 \
    --quantum 512 \
    --max-depth 2048
```

**Parameters**:
- `--quantum`: Deficit counter increment (bytes per round)
- `--max-depth`: Maximum queue depth (packets)

**DRR Quantum Guidelines**:
- Higher priority → larger quantum
- Typical: `quantum = 1500 * (prio + 1)`
- Critical (3): 2048 bytes
- High (2): 1536 bytes
- Normal (1): 1024 bytes
- Low (0): 512 bytes

### Statistics

```bash
# Show all port/priority statistics
sudo ./build/rsvoqctl show-stats

# Example output:
# Port 0:
#   Priority 3: enq=10000, deq=9990, drop=10, latency_p99=25us
#   Priority 2: enq=50000, deq=49500, drop=500, latency_p99=150us
#   ...
```

**Metrics**:
- `enq`: Enqueued packets
- `deq`: Dequeued packets
- `drop`: Dropped packets (queue full)
- `latency_p99`: 99th percentile latency (microseconds)

## Complete Deployment Example

### Environment Setup

```bash
# Check interface names
ip link show

# Example: ens33, ens34, ens35, ens36

# Check NIC queue support (need ≥4 combined queues for isolation)
ethtool -l ens33

# Enable huge pages (optional, for better AF_XDP performance)
sudo sysctl -w vm.nr_hugepages=256

# Set IRQ affinity (optional, for CPU isolation)
# Map queue 0 IRQ to CPU 2 (VOQd RX thread)
cat /proc/interrupts | grep ens33
echo 04 > /proc/irq/<IRQ_NUM>/smp_affinity
```

### Step 1: Load BPF Modules

```bash
# Load with L3 profile (includes AF_XDP redirect)
sudo ./build/rswitch_loader -p l3 -c etc/profiles/l3.yaml
```

**Modules loaded**:
- `dispatcher.bpf.o` - Ingress entry point
- `afxdp_redirect.bpf.o` - AF_XDP/CPUMAP redirect
- `qos.bpf.o` - QoS classification
- `route.bpf.o` - L3 routing
- `vlan.bpf.o` - VLAN processing
- `lastcall.bpf.o` - Final forwarding

### Step 2: Configure QoS

```bash
# Enable AF_XDP for critical priority on port 0
sudo ./build/rsqosctl set-config \
    --port 0 \
    --prio-mask 0x08 \
    --enable-afxdp \
    --cpu-map-id 0 \
    --cpu-core 2
```

**Parameters**:
- `--prio-mask 0x08`: Only critical (prio=3) redirected
- `--cpu-map-id 0`: CPUMAP index
- `--cpu-core 2`: Target CPU for AF_XDP processing

### Step 3: Start VOQd

```bash
# Start in SHADOW mode first (safe observation)
sudo ./build/rswitch-voqd \
    -p 4 \
    -m shadow \
    -P 0x08 \
    -i ens33,ens34,ens35,ens36 \
    -s \
    -S 10 &

# Wait 30 seconds, observe statistics
sleep 30

# Upgrade to ACTIVE mode (if stats look good)
sudo ./build/rsvoqctl set-mode active
```

### Step 4: Configure Rate Limiting

```bash
# Port 0: 500 Mbps
sudo ./build/rsvoqctl set-port-rate \
    --port 0 \
    --rate 500000000 \
    --burst 65536

# Port 1: 1 Gbps
sudo ./build/rsvoqctl set-port-rate \
    --port 1 \
    --rate 1000000000 \
    --burst 131072

# Configure queue parameters
for prio in 3 2 1 0; do
    quantum=$((1500 * (prio + 1)))
    max_depth=$((8192 / (4 - prio)))
    
    sudo ./build/rsvoqctl set-queue-params \
        --port 0 \
        --prio $prio \
        --quantum $quantum \
        --max-depth $max_depth
done
```

### Step 5: Monitor

```bash
# Watch VOQd output (statistics every 10 seconds)
# Ctrl+C to stop

# Or query stats manually
watch -n 2 "sudo ./build/rsvoqctl show-stats"
```

## Statistics Interpretation

### VOQd Output

```
=== VOQd Statistics (mode=ACTIVE, prio_mask=0x08) ===
Ringbuf: received=1000, processed=1000, dropped=0
VOQ Port 0:
  Priority 3: depth=0/8192, enq=1000, deq=995, drop=5, lat_avg=150us, p99=500us
  Priority 2: depth=0/4096, enq=5000, deq=5000, drop=0, lat_avg=80us, p99=200us
  Priority 1: depth=0/2048, enq=20000, deq=19500, drop=500, lat_avg=200us, p99=800us
  Priority 0: depth=0/1024, enq=50000, deq=45000, drop=5000, lat_avg=500us, p99=2000us
State: heartbeats=12, transitions=2

=== Data Plane Statistics ===
RX: 76000 packets, 114000000 bytes (avg batch: 128.5)
TX: 70495 packets, 105742500 bytes (avg batch: 64.3)
Errors: enqueue=5505, tx=0
Scheduler: 1100 rounds
AF_XDP: RX=4, TX=4 sockets
```

**Key Insights**:

1. **Ringbuf**: Should show no drops (if drops occur, increase ringbuf size)
2. **VOQ depth**: Current queue depth should be low (<10% of max_depth in steady state)
3. **Drops**: 
   - Critical (3) drops = **BAD** (increase `max_depth` or reduce load)
   - Low (0) drops = **OK** (expected under congestion)
4. **Latency**:
   - Critical: p99 <100us = **Excellent**, <500us = **Good**
   - Low: p99 <5ms = **Acceptable**
5. **Data plane**:
   - `avg batch >100` = **Excellent** throughput
   - `enqueue_errors` = Packets dropped (compare with VOQ drops)
   - `tx_errors` = TX ring full (should be 0)

## Troubleshooting

### AF_XDP Not Working

**Symptom**: `AF_XDP not supported` error

```bash
# Check libbpf version (need ≥1.0)
pkg-config --modversion libbpf

# Verify xsk.h exists
ls /usr/local/bpf/include/bpf/xsk.h

# Rebuild with AF_XDP support
cd external/libbpf/src
make install BUILD_STATIC_ONLY=1 PREFIX=/usr/local/bpf
cd ../../../rswitch
make clean && make
```

**Fallback**: Use SHADOW mode (metadata-only)

### Zero-Copy Mode Fails

**Symptom**: `xsk_socket_create` returns error

**Cause**: Driver doesn't support `XDP_ZEROCOPY`

**Solution**: Remove `-z` flag (use copy mode)

**Supported drivers**: i40e, ixgbe, mlx5

### Interface Not Found

**Symptom**: `Interface ens33 does not exist`

```bash
# List available interfaces
ip link show

# Use correct names
sudo ./build/rswitch-voqd -i enp2s0,enp2s1,enp2s2,enp2s3 ...
```

### High Enqueue Errors

**Symptom**: `enqueue_errors` high in data plane stats

**Cause**: VOQ queue full

**Solution**:
```bash
# Increase max_depth for affected priority
sudo ./build/rsvoqctl set-queue-params \
    --port 0 --prio 3 --quantum 2048 --max-depth 16384
```

### Low Throughput

**Symptom**: <1 Mpps with high CPU

**Solutions**:
1. Enable busy poll (recompile with `busy_poll=true`)
2. Increase batch size (recompile with `batch_size=512`)
3. Enable huge pages: `sudo sysctl -w vm.nr_hugepages=512`
4. Set CPU affinity: modify `cpu_affinity` in `voqd_dataplane_config`
5. Check IRQ affinity: `cat /proc/interrupts | grep <interface>`

### High Latency

**Symptom**: p99 >1ms for critical priority

**Solutions**:
1. Reduce batch size (recompile with `batch_size=64`)
2. Enable busy poll (eliminate 100us sleep)
3. Reduce queue depth: `--max-depth 1024`
4. Check token bucket settings (ensure not rate-limited)

## Performance Tuning

### CPU Isolation

```bash
# Isolate CPUs 2-3 for VOQd
# Add to kernel boot parameters (GRUB):
isolcpus=2,3

# Restart and verify
cat /proc/cmdline | grep isolcpus
```

**Modify** `voqd_dataplane.c`:
```c
struct voqd_dataplane_config dp_config = {
    .cpu_affinity = 2,  // RX on CPU 2, TX on CPU 3
    .busy_poll = true,  // No sleep (lowest latency)
};
```

### Huge Pages

```bash
# Enable huge pages
sudo sysctl -w vm.nr_hugepages=512

# Verify
cat /proc/meminfo | grep Huge

# Permanent (add to /etc/sysctl.conf)
echo "vm.nr_hugepages=512" | sudo tee -a /etc/sysctl.conf
```

**Benefit**: ~10% throughput improvement, -5us latency

### NIC Queue Isolation

```bash
# Verify queue support
ethtool -l ens33

# Enable 4 queues
sudo ethtool -L ens33 combined 4

# Map IRQs to CPUs
# Queue 0 → CPU 2 (AF_XDP high-priority)
# Queues 1-3 → CPU 0-1 (XDP fast-path)
```

**XDP devmap configuration** (in BPF):
```c
// Low-priority: redirect to queues 1-3
tx_devmap[port] = ifindex:queue=1;

// High-priority: cpumap → AF_XDP → TX queue 0
```

## Testing

### Automated Test Suite

```bash
# Run all tests
sudo ./tools/test_voqd.sh ens33,ens34,ens35,ens36

# Tests:
# 1. Metadata-only mode (SHADOW)
# 2. AF_XDP mode (ACTIVE)
# 3. Zero-copy mode (if supported)
```

### Manual Testing

**Test 1: Metadata mode**
```bash
sudo ./build/rswitch-voqd -p 4 -m shadow -s -S 5 &
sleep 15
sudo pkill -INT rswitch-voqd
```

**Test 2: AF_XDP mode**
```bash
sudo ./build/rswitch-voqd -p 4 -m active -P 0x0F \
    -i ens33,ens34,ens35,ens36 -s -S 5 &
sleep 30
sudo ./build/rsvoqctl show-stats
sudo pkill -INT rswitch-voqd
```

**Test 3: Rate limiting**
```bash
# Start VOQd
sudo ./build/rswitch-voqd -p 4 -m active -P 0x08 \
    -i ens33,ens34,ens35,ens36 -s &

# Set 10 Mbps limit
sudo ./build/rsvoqctl set-port-rate --port 0 --rate 10000000 --burst 16384

# Generate traffic and observe rate limiting
# (use iperf3 or similar)
```

## Integration with Control Plane

### State Machine Transitions

```bash
# Start in BYPASS (safe)
sudo ./build/rswitch-voqd -p 4 -m bypass -i ens33,ens34

# Upgrade to SHADOW (observe)
sudo ./build/rsvoqctl set-mode shadow

# Wait 60s, check stats
sudo ./build/rsvoqctl show-stats

# Upgrade to ACTIVE (full control)
sudo ./build/rsvoqctl set-mode active

# Downgrade if needed (safe fallback)
sudo ./build/rsvoqctl set-mode bypass
```

### Auto-Failover

**Trigger**: Heartbeat timeout (5 seconds)

**Behavior**: ACTIVE/SHADOW → BYPASS automatically

**Recovery**:
```bash
# VOQd detects degradation and logs:
# "Failover: count=1, overload_drops=0 [DEGRADED]"

# Restart VOQd to re-enable ACTIVE mode
sudo pkill -INT rswitch-voqd
sudo ./build/rswitch-voqd -p 4 -m active ...
```

## Best Practices

1. **Always start in SHADOW mode** for new deployments
2. **Set rate limits** before enabling ACTIVE mode
3. **Monitor enqueue errors** - indicates queue tuning needed
4. **Use priority mask carefully** - start with critical-only (0x08)
5. **Enable huge pages** in production
6. **Set CPU affinity** for dedicated cores
7. **Test zero-copy mode** but fallback to copy if unsupported
8. **Keep stats interval ≥10s** to reduce overhead

## Next Steps

- [ ] Implement IP TOS/DSCP priority extraction
- [ ] Add WFQ (Weighted Fair Queueing) scheduler
- [ ] Integrate telemetry export (Prometheus/Kafka)
- [ ] Add dynamic reconfiguration (hot-reload)
- [ ] Performance testing with pktgen-dpdk/TRex

## See Also

- [VOQd Data Plane Implementation](./VOQd_DataPlane_Implementation.md)
- [Data Plane Design](../../../docs/data_plane_desgin_with_af_XDP.md)
- [Milestone 1 Plan](../../../docs/Milestone1_plan.md)
