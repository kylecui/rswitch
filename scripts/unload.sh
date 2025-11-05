#!/bin/bash
# Unload rSwitch from all interfaces

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "=== Unloading rSwitch ==="

# Find all interfaces with XDP programs attached
IFACES=$(ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':')

for iface in $IFACES; do
    # Check if XDP program is attached
    if ip link show "$iface" | grep -q "xdp"; then
        echo "  Detaching XDP from $iface..."
        ip link set dev "$iface" xdp off 2>/dev/null || true
    fi
done

# Clean up pinned maps
echo "  Cleaning up rSwitch pinned BPF objects..."
for map in rs_ctx_map rs_progs rs_port_config_map rs_vlan_map rs_stats_map \
           rs_event_bus rs_mac_table acl_rules acl_rule_order acl_config_map \
           acl_stats mirror_config_map port_mirror_map mirror_stats \
           voq_ringbuf voqd_state_map qos_config_map; do
    if [ -e "/sys/fs/bpf/$map" ]; then
        rm -f "/sys/fs/bpf/$map"
    fi
done

echo "✓ rSwitch unloaded"
