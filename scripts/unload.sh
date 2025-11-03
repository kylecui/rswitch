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
if [ -d /sys/fs/bpf/rswitch ]; then
    echo "  Cleaning up pinned maps..."
    rm -rf /sys/fs/bpf/rswitch
fi

echo "✓ rSwitch unloaded"
