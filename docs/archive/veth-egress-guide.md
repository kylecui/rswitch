> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Veth Egress Path for VOQd

## Overview

This document describes the veth egress path implementation that enables XDP egress processing for packets transmitted by VOQd (Virtual Output Queue daemon).

### Problem Statement

When VOQd sends packets via AF_XDP TX, they bypass the XDP devmap egress hook:

```
Standard AF_XDP TX path (BROKEN for egress processing):
  VOQd AF_XDP TX → NIC driver → Wire
                   ↑
                   Skips devmap egress program!
                   No VLAN tagging, no QoS marking
```

### Solution

Route VOQd TX through a veth pair to re-enter the XDP path:

```
Veth egress path (CORRECT):
  VOQd AF_XDP TX → veth_voq_in → veth_voq_out (XDP) → devmap redirect → NIC
                                      ↑
                                      Egress modules run here:
                                      - VLAN tagging
                                      - QoS marking
                                      - Statistics
```

### Performance

Native XDP on veth is zero-copy (pointer transfer only):
- Throughput: ~194 Gbps (benchmark on 200G NIC)
- Latency overhead: ~15μs

---

## Architecture

### Components

| Component | File | Purpose |
|-----------|------|---------|
| BPF Module | `bpf/modules/veth_egress.bpf.c` | XDP program for veth_voq_out |
| Shared Header | `bpf/core/veth_egress_common.h` | `voq_tx_meta` structure definition |
| Setup Script | `scripts/setup_veth_egress.sh` | Creates/destroys veth pair |
| VOQd Dataplane | `user/voqd/voqd_dataplane.c` | TX path with veth support |
| Loader | `user/loader/rswitch_loader.c` | Loads veth egress XDP program |
| Profile Parser | `user/loader/profile_parser.c` | Parses veth config from YAML |

### Packet Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User Space (VOQd)                             │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  1. Dequeue packet from VOQ                                      │ │
│  │  2. Prepend voq_tx_meta header (12 bytes)                        │ │
│  │  3. AF_XDP TX to veth_voq_in                                     │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ↓ AF_XDP TX
┌─────────────────────────────────────────────────────────────────────┐
│  veth_voq_in                                                         │
│  (No XDP program, just receives packets)                             │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ↓ veth peer transfer (zero-copy)
┌─────────────────────────────────────────────────────────────────────┐
│  veth_voq_out                                                        │
│  XDP Program: veth_egress_redirect                                   │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  1. Parse voq_tx_meta header                                     │ │
│  │  2. Strip header (bpf_xdp_adjust_head)                           │ │
│  │  3. Restore rs_ctx for egress modules                            │ │
│  │  4. bpf_redirect_map() to voq_egress_devmap                      │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ↓ devmap redirect (triggers egress program)
┌─────────────────────────────────────────────────────────────────────┐
│  Physical NIC (eth0, eth1, ...)                                      │
│  Devmap Egress Program: rswitch_egress                               │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  1. Run egress_qos module (QoS marking)                          │ │
│  │  2. Run egress_vlan module (VLAN tagging)                        │ │
│  │  3. Run egress_final module (statistics)                         │ │
│  │  4. Transmit to wire                                             │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Metadata Header

VOQd prepends a 16-byte metadata header to each packet:

```c
struct voq_tx_meta {
    __u32 egress_ifindex;    // Target physical interface
    __u32 ingress_ifindex;   // Original ingress interface
    __u8  prio;              // QoS priority (0-3)
    __u8  flags;             // Processing flags
    __u16 vlan_id;           // VLAN ID (if applicable)
    __u32 reserved;          // Future use
} __attribute__((packed));   // Total: 16 bytes
```

Flags:
- `VOQ_TX_FLAG_SKIP_VLAN (0x01)`: Skip VLAN tagging
- `VOQ_TX_FLAG_SKIP_QOS (0x02)`: Skip QoS processing
- `VOQ_TX_FLAG_FROM_VOQ (0x80)`: Marker for VOQ-originated packets

---

## Configuration

### YAML Profile

```yaml
voqd_config:
  enabled: true
  mode: active
  enable_afxdp: true
  
  # Veth egress configuration
  use_veth_egress: true           # Enable veth egress path
  veth_in_ifname: veth_voq_in     # Interface for VOQd TX (default)
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `use_veth_egress` | bool | true (when VOQd enabled) | Enable veth egress path |
| `veth_in_ifname` | string | "veth_voq_in" | Interface name for VOQd TX target |

---

## Files Modified/Created

### New Files

1. **`bpf/core/veth_egress_common.h`**
   - Shared header with `voq_tx_meta` structure
   - Flag definitions
   - Used by both BPF and userspace

2. **`bpf/modules/veth_egress.bpf.c`**
   - XDP program `veth_egress_redirect`
   - Parses metadata, strips header, redirects to devmap
   - Maps: `veth_egress_config_map`, `veth_egress_stats`, `voq_egress_devmap`

3. **`scripts/setup_veth_egress.sh`**
   - Creates veth pair with XDP-compatible settings
   - Disables offloads (GRO, GSO, TSO)
   - Sets appropriate queue lengths

### Modified Files

1. **`user/voqd/voqd_dataplane.h`**
   - Added `use_veth_egress`, `veth_in_ifname`, `veth_in_ifindex` to config
   - Added `veth_xsk_mgr` to dataplane struct

2. **`user/voqd/voqd_dataplane.c`**
   - `voqd_dataplane_init()`: Initialize veth XSK manager
   - `voqd_dataplane_tx_process()`: Prepend metadata, TX to veth
   - `voqd_dataplane_destroy()`: Cleanup veth resources

3. **`user/loader/rswitch_loader.c`**
   - Added `setup_veth_egress()` function
   - Loads veth_egress BPF program
   - Attaches XDP to veth_voq_out
   - Populates voq_egress_devmap

4. **`user/loader/profile_parser.h`**
   - Added `use_veth_egress`, `veth_in_ifname` to `rs_profile_voqd`

5. **`user/loader/profile_parser.c`**
   - Parse new config options from YAML

6. **`etc/profiles/qos-voqd-test.yaml`**
   - Added veth egress configuration section
   - Added deployment commands for veth setup

7. **`etc/profiles/l3-qos-voqd-simple.yaml`**
   - Added veth egress configuration

---

## Requirements

### Kernel
- Linux 4.19+ for native veth XDP
- Linux 5.8+ recommended for full XDP features

### Dependencies
- libbpf
- libxdp (for AF_XDP)
- clang/LLVM (for BPF compilation)

### Hardware
- Network interfaces supporting XDP
- Sufficient CPU for VOQd processing

---

## Troubleshooting

### Veth XDP Attachment Fails

```bash
# Check if veth pair exists
ip link show veth_voq_in veth_voq_out

# Check for existing XDP programs
ip link show veth_voq_out | grep xdp

# Try generic mode (slower, for testing)
ip link set veth_voq_out xdpgeneric obj build/bpf/veth_egress.bpf.o sec xdp
```

### Packets Not Reaching Physical NIC

```bash
# Check devmap is populated
sudo bpftool map dump name voq_egress_devmap

# Check veth egress stats
sudo bpftool map dump name veth_egress_stats

# Enable tracing
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect/enable
cat /sys/kernel/debug/tracing/trace_pipe
```

### Performance Issues

1. Ensure native XDP mode (not generic):
   ```bash
   ip link show veth_voq_out | grep xdp
   # Should show: prog/xdp (not xdpgeneric)
   ```

2. Check offloads are disabled:
   ```bash
   ethtool -k veth_voq_in | grep -E "generic|tcp"
   ethtool -k veth_voq_out | grep -E "generic|tcp"
   ```

3. Verify sufficient UMEM headroom in VOQd config

---

## References

- [XDP on veth - Loophole Labs](https://loopholelabs.io/blog/xdp-redirect-veth)
- [AF_XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
