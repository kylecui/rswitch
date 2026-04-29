# VOQd Setup

VOQd (Virtual Output Queue daemon) is rSwitch's user-space QoS scheduler that uses AF_XDP sockets for high-priority traffic processing with DRR/WFQ scheduling.

## Overview

VOQd provides three operating modes:

| Mode | Value | Behavior | Use Case |
|------|-------|----------|----------|
| **BYPASS** | 0 | All traffic uses XDP fast-path; VOQd does not intercept | Failsafe mode, maximum performance |
| **SHADOW** | 1 | VOQd observes traffic via ringbuf, does not intercept | Testing configuration, zero impact |
| **ACTIVE** | 2 | High-priority traffic redirected to VOQd via AF_XDP | Production QoS with fine-grained scheduling |

## Architecture

```
Ingress → dispatcher → ... → afxdp_redirect (stage 85)
                                    │
                         ┌──────────┴──────────┐
                         │  Check prio_mask    │
                         │  & VOQd state       │
                         └──────────┬──────────┘
                              │            │
                    prio matched      prio not matched
                    mode=ACTIVE       (or mode=BYPASS)
                              │            │
                              ▼            ▼
                    ┌──────────────┐   XDP fast-path
                    │   AF_XDP     │   (normal pipeline)
                    │   socket     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │    VOQd      │
                    │  scheduler   │
                    │  (DRR/WFQ)   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  TX via      │
                    │  AF_XDP      │
                    └──────────────┘
```

## Automatic Setup (Recommended)

The loader starts VOQd automatically when the profile includes `voqd_config` with `enabled: true`.

### 1. Create a QoS Profile

Use an existing QoS profile or add `voqd_config` to your profile:

```yaml
name: "L3 with QoS"
version: "1.0"

ingress:
  - vlan
  - acl
  - route
  - afxdp_redirect    # Required for VOQd
  - l2learn
  - lastcall

egress:
  - egress_qos         # QoS enforcement
  - egress_vlan
  - egress_final

voqd_config:
  enabled: true
  mode: active
  num_ports: 4
  prio_mask: 0x0C       # Intercept HIGH (0x04) + CRITICAL (0x08)
  enable_afxdp: true
  zero_copy: false
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  enable_scheduler: true
  cpu_affinity: 2
```

### 2. Start the Loader

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/all.yaml \
    --ifaces ens33,ens34,ens35,ens36 \
    --verbose
```

Expected output:
```
[... XDP loading ...]

Starting VOQd (user-space scheduler)...
  Command: ./build/rswitch-voqd -i ens33,ens34,ens35,ens36 -p 4 -m active -P 0x0c -s -S 10
  Mode: ACTIVE
  Priority Mask: 0x0c
  Ports: 4
  ✓ VOQd started (PID: 12345)
  ✓ Log: /tmp/rswitch-voqd.log

rSwitch running. Press Ctrl+C to exit.
```

### 3. Verify

```bash
# Quick verification
sudo ./tools/qos_verify.sh

# Real-time monitoring
sudo ./tools/qos_monitor.sh

# Check VOQd state map
sudo bpftool map dump name voqd_state_map
```

Expected state:
```json
{
    "running": 1,
    "mode": 2,
    "prio_mask": 12
}
```

### 4. Shutdown

Press `Ctrl+C`. The loader automatically:
1. Sends SIGTERM to VOQd (graceful stop)
2. Waits up to 5 seconds
3. Sends SIGKILL if still running
4. Cleans up XDP programs and BPF maps

## Manual Setup

If you need independent control of VOQd (e.g., for debugging):

### 1. Disable Auto-Start in Profile

```yaml
voqd_config:
  enabled: false    # Loader won't start VOQd
```

### 2. Start Loader Without VOQd

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/qos-voqd-test.yaml \
    --ifaces ens33,ens34
```

### 3. Start VOQd Separately

```bash
sudo ./build/rswitch-voqd \
    -i ens33,ens34 \
    -p 2 \
    -m active \
    -P 0x0c \
    -s \
    -S 10
```

### VOQd CLI Flags

| Flag | Description |
|------|-------------|
| `-i <interfaces>` | Comma-separated interface list |
| `-m <mode>` | `bypass`, `shadow`, or `active` |
| `-p <num_ports>` | Number of ports |
| `-P <prio_mask>` | Priority bitmask (hex) |
| `-q` | Enable software queues |
| `-Q <depth>` | Software queue depth |
| `-s` | Enable scheduler |
| `-S <interval>` | Stats reporting interval (seconds) |

## Configuration Tuning

### CPU Affinity

Pin VOQd to a dedicated CPU core to reduce context switches:

```yaml
voqd_config:
  cpu_affinity: 2    # Run on CPU 2
```

Choose a CPU core not used by NIC IRQ handlers for best results.

### Ring Sizes

Larger rings increase throughput at the cost of latency:

```yaml
voqd_config:
  rx_ring_size: 4096    # Larger receive ring
  tx_ring_size: 4096    # Larger transmit ring
  batch_size: 512       # Larger batch processing
```

### Zero-Copy Mode (Experimental)

Requires NIC driver support (Intel i40e, Mellanox mlx5):

```yaml
voqd_config:
  zero_copy: true
```

> Zero-copy mode requires exclusive NIC queue access. Ensure no other application uses the same queues.

### Software Queues

For NICs without hardware multi-queue support:

```yaml
voqd_config:
  software_queues:
    enabled: true
    queue_depth: 1024
    num_priorities: 8
```

## Priority Mask

The `prio_mask` bitmask controls which priority levels are intercepted by VOQd:

| Bit | Priority | Typical Use |
|-----|----------|-------------|
| 0x01 | 0 (Best Effort) | Background traffic |
| 0x02 | 1 | Spare |
| 0x04 | 2 (HIGH) | Important traffic |
| 0x08 | 3 (CRITICAL) | Real-time / control |
| 0x0C | 2+3 | High + Critical (common default) |
| 0xFF | All | All priorities through VOQd |

## Monitoring

### VOQd Statistics

```bash
# If started with -S flag
tail -f /tmp/rswitch-voqd.log
```

### BPF Map Statistics

```bash
# AF_XDP redirect statistics
sudo bpftool map dump name afxdp_stats_map

# VOQd state
sudo bpftool map dump name voqd_state_map

# QoS statistics
sudo ./build/rsqosctl stats
```

## Troubleshooting

### VOQd Fails to Start

**Check the log**:
```bash
cat /tmp/rswitch-voqd.log
```

**Common causes**:
1. **Binary not built**: Run `make` to compile
2. **Interfaces don't exist**: Verify interface names
3. **Insufficient permissions**: Must run as root
4. **AF_XDP unsupported**: Kernel too old (requires 5.3+) or NIC doesn't support XDP

### VOQd Running But Not Intercepting

**Check state map**:
```bash
sudo bpftool map dump name voqd_state_map
```

- `running=0` → VOQd crashed. Check log and restart.
- `mode=0` (BYPASS) → Auto-degraded. Check `failover_count` for cause.
- `prio_mask=0` → No priorities selected. Check profile config.

### State Transitions

VOQd may automatically transition between modes:

| Transition | Trigger | Recovery |
|------------|---------|----------|
| ACTIVE → BYPASS | VOQd heartbeat timeout | Auto-recovery when VOQd restarts |
| ACTIVE → BYPASS | Ringbuf overflow | Auto-recovery when load decreases |
| Any → BYPASS | VOQd process crash | Restart loader to restart VOQd |

## See Also

- [Configuration](Configuration.md) — YAML reference for voqd_config
- [NIC Configuration](NIC_Configuration.md) — NIC setup for AF_XDP
- [Troubleshooting](../usage/Troubleshooting.md) — general troubleshooting
- [Architecture](../development/Architecture.md) — VOQd in the system architecture
