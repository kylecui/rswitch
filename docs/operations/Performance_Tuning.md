# Performance Tuning Guide

Optimize rSwitch for maximum throughput, minimum latency, or balanced production workloads.

## NIC Tuning

### XDP Mode Selection

The XDP attach mode has the largest single impact on performance:

| Mode | Command | Performance | Compatibility |
|------|---------|-------------|---------------|
| **Native** (`xdp`) | Default for supported drivers | Best — driver-level processing | i40e, mlx5, ice, ixgbe |
| **Generic** (`xdpgeneric`) | `--xdp-mode skb` | 3-5x slower — goes through network stack | All NICs |

```bash
# Check current XDP mode
ip -d link show ens34 | grep xdp

# Native mode (recommended)
sudo ./build/rswitch_loader --profile ... --ifaces ens34,ens35

# Generic mode (fallback for unsupported NICs like hv_netvsc)
sudo ./build/rswitch_loader --profile ... --ifaces ens34,ens35 --xdp-mode skb
```

> **Important**: All interfaces (including `mgmt-br`) must use the same XDP mode for `BPF_F_BROADCAST` redirect to work.

### NIC Queue Configuration

Match NIC queues to CPU cores for optimal interrupt distribution:

```bash
# Check current queue count
ethtool -l ens34

# Set combined queues (match to available CPUs)
sudo ethtool -L ens34 combined 4

# Verify
ethtool -l ens34
```

### IRQ Affinity

Pin NIC interrupts to specific CPUs to reduce cache thrashing:

```bash
# Find IRQ numbers for the NIC
grep ens34 /proc/interrupts

# Pin each queue IRQ to a dedicated CPU
# Queue 0 → CPU 0
echo 1 | sudo tee /proc/irq/<irq0>/smp_affinity
# Queue 1 → CPU 1
echo 2 | sudo tee /proc/irq/<irq1>/smp_affinity

# Or use the helper script
sudo scripts/setup_nic_queues.sh ens34 4
```

### Ring Buffer Sizes

Increase NIC ring buffers for bursty traffic:

```bash
# Check current/max ring sizes
ethtool -g ens34

# Increase (reduces drops under burst)
sudo ethtool -G ens34 rx 4096 tx 4096
```

### Offload Settings

rSwitch requires specific offload settings:

```bash
# MUST disable: hardware VLAN strip (breaks rSwitch VLAN processing)
sudo ethtool -K ens34 rx-vlan-offload off

# MUST enable: promiscuous mode (switch needs all packets)
sudo ip link set dev ens34 promisc on

# Optional: disable GRO/LRO (reduces latency, may reduce throughput)
sudo ethtool -K ens34 gro off lro off

# Optional: enable XDP-specific features (driver dependent)
sudo ethtool -K ens34 xdp on 2>/dev/null || true
```

## CPU and Memory Tuning

### CPU Isolation

For dedicated switching performance, isolate CPUs from the Linux scheduler:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3"
```

Then pin rSwitch components:

```bash
# Pin VOQd to isolated CPU
sudo taskset -c 2 ./build/rswitch-voqd -m active -i ens34,ens35 ...

# Or via profile YAML
voqd_config:
  cpu_affinity: 2
```

### NUMA Awareness

On multi-socket systems, ensure NICs and CPUs are on the same NUMA node:

```bash
# Check NIC NUMA node
cat /sys/class/net/ens34/device/numa_node

# Check CPU NUMA mapping
lscpu | grep NUMA

# Pin rSwitch to matching NUMA node
sudo numactl --cpunodebind=0 --membind=0 ./build/rswitch_loader ...
```

### Huge Pages

BPF maps and AF_XDP use locked memory. Huge pages reduce TLB pressure:

```bash
# Allocate 2MB huge pages
echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Make persistent
echo "vm.nr_hugepages = 256" >> /etc/sysctl.d/99-rswitch.conf
```

### Memory Locking

Ensure sufficient locked memory for BPF maps:

```bash
# Systemd service (already set)
# LimitMEMLOCK=infinity

# Manual / shell
ulimit -l unlimited
```

## VOQd Tuning

### Mode Selection

| Mode | Throughput | Latency | Use Case |
|------|-----------|---------|----------|
| BYPASS | Maximum | Lowest | Pure L2/L3 switching, no QoS needed |
| SHADOW | Maximum (no packet redirect) | Lowest | QoS monitoring without affecting traffic |
| ACTIVE | High (AF_XDP path) | Higher (user-space scheduling) | Production QoS with priority scheduling |

### Ring Sizes

Larger rings buffer more packets, increasing throughput at the cost of latency:

```yaml
voqd_config:
  rx_ring_size: 2048    # Default. Increase to 4096 for high throughput
  tx_ring_size: 2048    # Match rx_ring_size
  frame_size: 2048      # 2048 for standard frames, 4096 for jumbo
  batch_size: 256       # Packets processed per poll cycle
  poll_timeout_ms: 100  # Reduce to 10 for lower latency, increase to 500 for efficiency
```

| Workload | rx/tx_ring | batch_size | poll_timeout_ms |
|----------|-----------|------------|-----------------|
| Low latency | 1024 | 64 | 10 |
| Balanced | 2048 | 256 | 100 |
| High throughput | 4096 | 512 | 500 |

### Software Queues

For NICs without hardware multi-queue support:

```yaml
voqd_config:
  software_queues:
    enabled: true
    queue_depth: 2048    # Per port/priority. Increase for bursty traffic
    num_priorities: 8
```

```bash
# CLI equivalent
sudo ./build/rswitch-voqd -m active -q -Q 2048 -i ens34,ens35
```

### Priority Mask

Only intercept traffic priorities that need QoS scheduling:

```yaml
voqd_config:
  prio_mask: 0x0C    # Only HIGH (0x04) + CRITICAL (0x08)
```

Intercepting fewer priorities reduces AF_XDP load:

| Mask | Priorities | AF_XDP Load |
|------|-----------|-------------|
| `0x0C` | HIGH + CRITICAL only | Low — most traffic stays on XDP fast-path |
| `0xFF` | All priorities | High — all traffic goes through user-space |
| `0x08` | CRITICAL only | Minimal |

### Zero-Copy AF_XDP

For maximum AF_XDP performance with supported NICs (i40e, mlx5):

```yaml
voqd_config:
  zero_copy: true
```

Requirements:
- NIC driver must support XDP zero-copy
- Exclusive queue access (no other applications on those queues)
- Kernel 5.4+

## Pipeline Optimization

### Module Selection

Each module in the pipeline adds processing cost. Only load what you need:

```yaml
# Minimal L2 — fewest modules, maximum speed
ingress:
  - vlan
  - l2learn
  - lastcall
egress:
  - egress_vlan
  - egress_final

# Full L3 + QoS — more modules, more features
ingress:
  - vlan
  - acl
  - route
  - afxdp_redirect
  - l2learn
  - lastcall
egress:
  - egress_qos
  - egress_vlan
  - egress_final
```

### Profile Selection Guide

| Profile | Modules | Relative Performance |
|---------|---------|---------------------|
| `dumb.yaml` | Minimal | Fastest |
| `l2.yaml` | L2 switching | Fast |
| `l2-vlan.yaml` | L2 + VLAN | Fast |
| `l3.yaml` | L3 routing + ACL | Moderate |
| `firewall.yaml` | Security-focused | Moderate |
| `qos-voqd-minimal.yaml` | L2 + minimal QoS | Moderate |
| `qos-voqd.yaml` | Full QoS | Moderate-High |
| `all-modules.yaml` | Everything loaded | Slowest (testing only) |

### ACL Optimization

ACL rules use LPM (Longest Prefix Match) BPF maps. Performance tips:

- Fewer rules = faster lookups
- Use broader prefixes where possible
- Place most-matched rules at tighter prefixes for LPM efficiency

## Benchmarking

### Built-in Performance Testing

rSwitch includes `BPF_PROG_TEST_RUN`-based benchmarks:

```bash
# Run performance tests
make test-perf

# Specific module benchmark
sudo ./build/test/perf_test --module vlan --iterations 1000000
```

See [Performance Testing](../development/Performance_Testing.md) for details.

### External Tools

```bash
# pktgen (kernel packet generator)
sudo modprobe pktgen
# Configure via /proc/net/pktgen/

# iperf3 (throughput)
iperf3 -s  # on receiver
iperf3 -c <receiver-ip> -t 30 -P 4  # on sender through rSwitch

# Prometheus metrics (continuous monitoring)
curl -s http://localhost:9417/metrics | grep rswitch_port
```

### Key Metrics for Benchmarking

| Metric | Source | What It Measures |
|--------|--------|-----------------|
| Packets per second | `rswitchctl show-stats` | Raw forwarding throughput |
| Drop rate | `rswitch_port_drop_packets_total` | Packet loss under load |
| Module processing time | `rsdiag start` (L2 probes) | Per-module latency |
| VOQd queue depth | `rswitch_voqd_queue_depth` | QoS scheduling backpressure |
| AF_XDP stats | `bpftool map dump name afxdp_stats_map` | Zero-copy throughput |

## Quick Reference: Tuning Profiles

### Maximum Throughput

```bash
# Use native XDP, minimal modules, BYPASS mode
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --ifaces ens34,ens35

# NIC tuning
sudo ethtool -L ens34 combined 4
sudo ethtool -G ens34 rx 4096 tx 4096
sudo ethtool -K ens34 rx-vlan-offload off gro off

# CPU isolation
taskset -c 2,3 ./build/rswitch_loader ...
```

### Minimum Latency

```yaml
# Small rings, small batches, fast polling
voqd_config:
  rx_ring_size: 1024
  tx_ring_size: 1024
  batch_size: 64
  poll_timeout_ms: 10
  cpu_affinity: 2
```

### Balanced Production

```yaml
# Default ring sizes, moderate batching
voqd_config:
  mode: active
  rx_ring_size: 2048
  tx_ring_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  prio_mask: 0x0C
  software_queues:
    enabled: true
    queue_depth: 2048
```

## See Also

- [NIC Configuration](../deployment/NIC_Configuration.md) — NIC-specific setup
- [VOQd Setup](../deployment/VOQd_Setup.md) — QoS scheduler configuration
- [Operations Guide](Operations_Guide.md) — capacity planning and monitoring
- [Performance Testing](../development/Performance_Testing.md) — BPF_PROG_TEST_RUN benchmarks
- [Architecture](../development/Architecture.md) — pipeline architecture
