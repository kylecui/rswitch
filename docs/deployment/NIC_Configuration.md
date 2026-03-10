# NIC Configuration

rSwitch operates at the XDP layer, which runs in the NIC driver before packets reach the Linux network stack. This requires specific NIC configuration.

## Critical Requirements

### 1. Disable Hardware VLAN Offload

Modern NICs strip VLAN tags in hardware before XDP programs see them. This **breaks** rSwitch VLAN processing.

**Check status**:
```bash
ethtool -k <interface> | grep rx-vlan-offload
```

**Disable** (required for each interface):
```bash
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens35 rx-vlan-offload off
sudo ethtool -K ens36 rx-vlan-offload off
```

**Or use the helper script**:
```bash
sudo ./tools/scripts/all/disable_vlan_offload.sh ens34 ens35 ens36
```

### 2. Enable Promiscuous Mode

Switch operation requires receiving **all** packets on the network segment, not just those addressed to the NIC's own MAC.

```bash
sudo ip link set dev ens34 promisc on
sudo ip link set dev ens35 promisc on
sudo ip link set dev ens36 promisc on
```

> **Note**: rSwitch loader v1.1+ automatically applies both settings when attaching XDP programs. Manual configuration is only needed for older versions or troubleshooting.

## NIC Compatibility

### Supported NICs

| NIC | Driver | Native XDP | AF_XDP Zero-Copy | Notes |
|-----|--------|-----------|------------------|-------|
| Intel X710 | i40e | Yes | Yes | Recommended for production |
| Intel X520/X540 | ixgbe | Yes | Yes | Older but well-supported |
| Mellanox CX-5 | mlx5 | Yes | Yes | Recommended for production |
| Intel E810 | ice | Yes | Yes | Latest Intel XDP support |
| Broadcom | bnxt_en | Yes | Limited | Check driver version |
| VMware | vmxnet3 | Yes | No | Lab/testing use |
| Hyper-V | hv_netvsc | **Generic only** | No | Significantly lower performance |
| Realtek | r8169 | Limited | No | Some models don't support VLAN offload disable |

### Check Your NIC

```bash
# Check driver
ethtool -i ens34 | grep driver

# Check if VLAN offload can be disabled (look for [fixed])
ethtool -k ens34 | grep "rx-vlan-offload:"
# If [fixed], the setting cannot be changed

# Check XDP support
ip link set dev ens34 xdp obj /dev/null 2>&1
# "No such file" is expected; "not supported" means no XDP
```

## Verification

### VLAN Offload

```bash
ethtool -k ens34 | grep -i vlan
```

Expected:
```
rx-vlan-offload: off        ← Must be OFF
tx-vlan-offload: on [fixed]
rx-vlan-filter: on [fixed]
```

### Promiscuous Mode

```bash
ip link show ens34
```

Expected (look for `PROMISC`):
```
3: ens34: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> ...
```

### VLAN Tag Visibility

After loading rSwitch, check that VLAN tags are visible:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "vlan_depth"
```

Tagged traffic should show `vlan_depth=1`:
```
[rSwitch] Packet received on ifindex 3, vlan_depth=1, vlan_id=10
```

If you see `vlan_depth=0` for traffic that should be tagged (verified with Wireshark), VLAN offload is still enabled.

## Queue Configuration

### IRQ Affinity and Queue Isolation

For best performance, isolate NIC queues and set CPU affinity:

```bash
# Configure NIC queues (interface, num_queues)
sudo scripts/setup_nic_queues.sh ens34 2
```

This script:
1. Sets the number of combined queues
2. Configures IRQ affinity to spread across CPUs
3. Isolates queues for XDP processing

### Manual Queue Setup

```bash
# Set number of queues
sudo ethtool -L ens34 combined 4

# Set IRQ affinity for each queue
# Find IRQ numbers
grep ens34 /proc/interrupts

# Set affinity (e.g., queue 0 → CPU 0)
echo 1 | sudo tee /proc/irq/<irq_num>/smp_affinity
```

## Persistence Across Reboots

Loader auto-configuration is **not persistent**. For production, configure at boot time.

### Using systemd (Recommended)

Create `/etc/systemd/system/rswitch-nic.service`:

```ini
[Unit]
Description=rSwitch NIC Configuration
Before=rswitch.service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -K ens34 rx-vlan-offload off
ExecStart=/usr/sbin/ethtool -K ens35 rx-vlan-offload off
ExecStart=/usr/sbin/ethtool -K ens36 rx-vlan-offload off
ExecStart=/usr/sbin/ip link set dev ens34 promisc on
ExecStart=/usr/sbin/ip link set dev ens35 promisc on
ExecStart=/usr/sbin/ip link set dev ens36 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable rswitch-nic.service
```

### Using udev Rules

For interface-specific configuration that survives reboots and hotplug:

```bash
# /etc/udev/rules.d/99-rswitch-nic.rules
ACTION=="add", SUBSYSTEM=="net", KERNEL=="ens34", RUN+="/usr/sbin/ethtool -K %k rx-vlan-offload off"
ACTION=="add", SUBSYSTEM=="net", KERNEL=="ens34", RUN+="/usr/sbin/ip link set dev %k promisc on"
```

## Troubleshooting

### VLAN Traffic Not Working

**Symptom**: VLAN 10 traffic not forwarded between trunk and access ports.

**Diagnosis**:
1. Wireshark on physical link shows VLAN 10 tags → Hardware sees tags
2. BPF trace shows `vlan_depth=0` → XDP doesn't see tags
3. Conclusion: Hardware VLAN offload is stripping tags

**Fix**:
```bash
sudo ethtool -K ens34 rx-vlan-offload off
# Restart rSwitch
```

### Loader Warning Messages

```
Warning: Failed to disable VLAN offload on ens34
Warning: Failed to enable promiscuous mode on ens35
```

**Causes**:
- `ethtool` or `ip` not in PATH
- Not running as root
- NIC driver doesn't support the operation (`[fixed]` flag)

**Fix**:
- Run loader with `sudo`
- Install `ethtool`: `sudo apt install ethtool`
- For NIC limitations, configure manually before starting rSwitch

## See Also

- [Installation](Installation.md) — build from source
- [VOQd Setup](VOQd_Setup.md) — AF_XDP requirements
- [Troubleshooting](../usage/Troubleshooting.md) — general troubleshooting
