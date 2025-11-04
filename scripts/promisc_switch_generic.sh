#!/bin/bash
#
# Generic promiscuous mode setup script for rSwitch
# Usage: ./promisc_switch.sh <interface1> [interface2] [interface3] ...
#

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <interface1> [interface2] [interface3] ..."
    echo "Example: $0 enp2s0 enp3s0 enp4s0"
    exit 1
fi

echo "Setting promiscuous mode on interfaces: $@"

for iface in "$@"; do
    echo "  Setting $iface UP and PROMISC..."
    sudo ip link set dev "$iface" up
    sudo ip link set dev "$iface" promisc on

    # Verify
    if ip link show "$iface" | grep -q PROMISC; then
        echo "  ✓ $iface: PROMISC enabled"
    else
        echo "  ❌ $iface: PROMISC failed"
        exit 1
    fi
done

echo "All interfaces configured successfully!"