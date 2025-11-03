#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# NIC Queue Isolation Cleanup Script
# 
# Restores default NIC queue configuration.
# 
# Usage:
#   sudo ./cleanup_nic_queues.sh <interface>
#   
# Example:
#   sudo ./cleanup_nic_queues.sh eth0

set -e

IFACE="$1"

if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface>"
    echo ""
    echo "Example: $0 eth0"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

echo "=========================================="
echo "NIC Queue Isolation Cleanup"
echo "=========================================="
echo "Interface: $IFACE"
echo ""

# Check if interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "Error: Interface $IFACE does not exist"
    exit 1
fi

# Find IRQ for queue 0
echo "[1/2] Finding IRQ for queue 0..."

IRQ=$(grep "$IFACE" /proc/interrupts | head -1 | awk -F: '{print $1}' | tr -d ' ')

if [ -z "$IRQ" ]; then
    MSI_DIR="/sys/class/net/$IFACE/device/msi_irqs"
    if [ -d "$MSI_DIR" ]; then
        IRQ=$(ls "$MSI_DIR" | sort -n | head -1)
    fi
fi

if [ -z "$IRQ" ]; then
    echo "Warning: Could not find IRQ for $IFACE"
    echo "Nothing to clean up"
    exit 0
fi

echo "  Queue 0 IRQ: $IRQ"
echo ""

# Restore IRQ affinity to all CPUs
echo "[2/2] Restoring default IRQ affinity..."
AFFINITY_FILE="/proc/irq/$IRQ/smp_affinity"

if [ ! -f "$AFFINITY_FILE" ]; then
    echo "Warning: Affinity file $AFFINITY_FILE not found"
    exit 0
fi

# Set to all CPUs (0xFFFFFFFF for up to 32 cores)
echo "ffffffff" > "$AFFINITY_FILE"

CURRENT_MASK=$(cat "$AFFINITY_FILE")
echo "  IRQ $IRQ affinity restored to: 0x$CURRENT_MASK (all CPUs)"
echo ""

echo "✓ Queue isolation cleanup complete!"
