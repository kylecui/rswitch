# Troubleshooting

Common issues and solutions when running rSwitch.

## Module Loading

### "Failed to load module X" — BPF Verifier Rejection

**Symptoms**: Loader fails with verifier error messages.

**Diagnosis**:
```bash
sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml --verbose
dmesg | grep bpf
```

**Common Causes**:
- Bounds check missing before packet data access
- Unbounded loop in BPF code
- Accessing map value without null check
- CO-RE field not available on current kernel

**Solutions**:
- Review verifier output for the specific instruction causing rejection
- Add bounds checks: `if ((void *)(hdr + 1) > data_end) return XDP_DROP;`
- Use offset masks: `offset & RS_L3_OFFSET_MASK`
- Check null returns: `if (!val) return XDP_DROP;`

### "Map not found" or "No such file" Errors

**Symptoms**: Errors accessing `/sys/fs/bpf/rs_*` maps.

**Causes**:
- Maps not yet initialized (loader still starting up)
- Previous unclean shutdown left stale maps

**Solutions**:
```bash
# Wait for initialization (3–5 seconds after start)
sleep 5 && ls /sys/fs/bpf/ | grep rs_

# Clean stale maps and restart
sudo rm -rf /sys/fs/bpf/rs_*
sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml
```

### Module ABI Version Mismatch

**Symptoms**: Loader reports "incompatible module" or ABI version error.

**Solutions**:
```bash
# Rebuild everything from clean state
make clean && make
```

## VLAN Issues

### VLAN Traffic Not Forwarded

**Symptoms**: Tagged traffic between trunk and access ports doesn't work.

**Diagnosis**:
```bash
# Check VLAN offload (must be OFF)
ethtool -k ens34 | grep rx-vlan-offload

# Check BPF trace for VLAN depth
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "vlan_depth"
```

If `vlan_depth=0` for traffic that should be tagged, hardware VLAN offload is stripping tags.

**Solution**:
```bash
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens35 rx-vlan-offload off
# Restart rSwitch
```

### Promiscuous Mode Not Enabled

**Symptoms**: Only traffic destined to the NIC's own MAC is received.

**Diagnosis**:
```bash
ip link show ens34
# Look for PROMISC flag in the output
```

**Solution**:
```bash
sudo ip link set dev ens34 promisc on
```

> rSwitch loader v1.1+ handles this automatically.

## VOQd Issues

### VOQd Fails to Start

**Symptoms**: `VOQd process exited prematurely`

**Diagnosis**:
```bash
# Check the VOQd log
cat /tmp/rswitch-voqd.log

# Check binary exists
ls -la ./build/rswitch-voqd

# Test VOQd manually
sudo ./build/rswitch-voqd --help
```

**Common Causes**:
1. VOQd binary not compiled — run `make`
2. Interfaces don't exist — verify `--ifaces` parameter
3. Insufficient permissions — run with `sudo`
4. AF_XDP not supported — kernel too old (requires 5.3+)

### VOQd Running But Not Intercepting Traffic

**Diagnosis**:
```bash
sudo bpftool map dump name voqd_state_map
```

Expected output:
```json
{
    "running": 1,
    "mode": 2,           // 2 = ACTIVE
    "prio_mask": 12       // 0x0C = HIGH + CRITICAL
}
```

**If `running=0`**: VOQd crashed. Check `/tmp/rswitch-voqd.log` and restart.

**If `mode=0` (BYPASS)**: VOQd auto-degraded. Check `failover_count` and logs for the cause.

### Profile YAML Parsing Error

**Symptoms**: `Failed to load profile: voqd_config not found`

**Solutions**:
- Ensure YAML indentation uses 2 spaces (not tabs)
- Check field name spelling (case-sensitive)
- Verify `voqd_config:` section exists and is properly indented

Minimal valid VOQd config:
```yaml
voqd_config:
  enabled: true
  mode: active
  prio_mask: 0x0C
```

## Performance Issues

### Low Throughput

**Diagnosis**:
```bash
sudo ./build/rswitchctl show-stats
sudo ./build/rsqosctl stats
```

**Common Causes**:
- XDP running in generic mode (software) instead of native (driver)
- NIC doesn't support native XDP (e.g., `hv_netvsc` on Azure VMs)
- CPU affinity not configured — all queues on same core
- Too many heavy modules in the pipeline

**Solutions**:
- Verify XDP mode: use `--xdp-mode native` (requires supported NIC)
- Configure CPU affinity: `sudo scripts/setup_nic_queues.sh ens34 2`
- Reduce pipeline length — remove unused modules from profile
- For VOQd: increase batch size and ring sizes

### Supported NICs for Native XDP

| NIC | Driver | Native XDP | AF_XDP Zero-Copy |
|-----|--------|-----------|------------------|
| Intel X710 | i40e | Yes | Yes |
| Mellanox CX-5 | mlx5 | Yes | Yes |
| VMware vmxnet3 | vmxnet3 | Yes | No |
| Hyper-V | hv_netvsc | No (generic only) | No |

## Map Inspection

### Dump Any rSwitch Map

```bash
# MAC table
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table

# Port configuration
sudo bpftool map dump pinned /sys/fs/bpf/rs_port_config_map

# Statistics
sudo bpftool map dump pinned /sys/fs/bpf/rs_stats_map

# Context (per-CPU)
sudo bpftool map dump pinned /sys/fs/bpf/rs_ctx_map
```

### List All rSwitch Resources

```bash
# Programs
sudo bpftool prog list | grep rswitch

# Maps
sudo bpftool map list | grep rs_

# Pinned paths
ls /sys/fs/bpf/ | grep rs_
```

## Build Issues

### vmlinux.h Generation Fails

**Error**: `bpftool not found`

```bash
sudo apt install linux-tools-$(uname -r)
# Or specify bpftool path:
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### BTF Not Available

**Error**: `/sys/kernel/btf/vmlinux not found`

Your kernel doesn't have BTF enabled. Options:
- Upgrade to a kernel with `CONFIG_DEBUG_INFO_BTF=y`
- Use a distribution kernel 5.8+ (most modern distros enable BTF)

### Compilation Errors (vmlinux.h Conflicts)

**Error**: `typedef redefinition with different types`

This usually means system headers and vmlinux.h are conflicting. BPF programs should only include `rswitch_bpf.h` (which includes vmlinux.h), not system headers like `<linux/if_ether.h>`.

## Cleanup

### Full Reset

```bash
# Stop everything
sudo pkill rswitch_loader
sudo pkill rswitch-voqd

# Remove all pinned maps
sudo rm -rf /sys/fs/bpf/rs_*

# Verify clean
ls /sys/fs/bpf/ | grep rs_    # Should return empty
sudo bpftool prog list | grep rswitch  # Should return empty
```

## Getting Help

- Check loader verbose output: `--verbose` or `--debug` flags
- Check kernel logs: `dmesg | tail -50`
- Check VOQd logs: `cat /tmp/rswitch-voqd.log`
- Run diagnostics: `sudo scripts/rswitch_diag.sh`
- Review [Architecture](../development/Architecture.md) for understanding the pipeline

## See Also

- [Quick Start](Quick_Start.md) — basic setup
- [NIC Configuration](../deployment/NIC_Configuration.md) — NIC-specific requirements
- [VOQd Setup](../deployment/VOQd_Setup.md) — VOQd troubleshooting
