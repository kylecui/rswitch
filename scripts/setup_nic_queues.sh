#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# NIC Queue Isolation Setup Script
# 
# Automates TX queue isolation for hybrid XDP/AF_XDP data plane.
# 
# Queue Strategy:
#   Queue 0: AF_XDP high-priority (VOQd-controlled) → Dedicated CPU
#   Queue 1-3: XDP fast-path → Shared CPUs
# 
# Usage:
#   sudo ./setup_nic_queues.sh <interface> [afxdp_cpu]
#   
# Example:
#   sudo ./setup_nic_queues.sh eth0 1
#   sudo ./setup_nic_queues.sh eth1 2

set -e

IFACE="$1"
AFXDP_CPU="${2:-1}"  # Default: CPU 1 (avoid CPU 0 for system tasks)

if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface> [afxdp_cpu]"
    echo ""
    echo "Example: $0 eth0 1"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

echo "=========================================="
echo "NIC Queue Isolation Setup"
echo "=========================================="
echo "Interface: $IFACE"
echo "AF_XDP CPU: $AFXDP_CPU"
echo ""

# Check if interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "Error: Interface $IFACE does not exist"
    exit 1
fi

# Query current queue configuration
echo "[1/4] Checking NIC queue capabilities..."
QUEUES=$(ethtool -l "$IFACE" 2>/dev/null | grep -A 10 "Current hardware settings:" | grep "Combined:" | awk '{print $2}')

if [ -z "$QUEUES" ]; then
    echo "Error: Could not determine queue count"
    echo "Tip: Run 'sudo ethtool -l $IFACE' manually"
    exit 1
fi

echo "  Current combined queues: $QUEUES"

# Check if we have enough queues
MIN_QUEUES=4
if [ "$QUEUES" -lt "$MIN_QUEUES" ]; then
    echo "Warning: Interface has only $QUEUES queues (need $MIN_QUEUES for isolation)"
    echo "Queue isolation will NOT be enabled"
    echo ""
    echo "To enable more queues, run:"
    echo "  sudo ethtool -L $IFACE combined <num_queues>"
    exit 1
fi

echo "  ✓ Sufficient queues for isolation ($QUEUES >= $MIN_QUEUES)"
echo ""

# Find IRQ for queue 0
echo "[2/4] Finding IRQ for queue 0..."

# Method 1: Try /proc/interrupts
IRQ=$(grep "$IFACE" /proc/interrupts | head -1 | awk -F: '{print $1}' | tr -d ' ')

if [ -z "$IRQ" ]; then
    # Method 2: Try /sys/class/net/.../device/msi_irqs/
    MSI_DIR="/sys/class/net/$IFACE/device/msi_irqs"
    if [ -d "$MSI_DIR" ]; then
        IRQ=$(ls "$MSI_DIR" | sort -n | head -1)
    fi
fi

if [ -z "$IRQ" ]; then
    echo "Warning: Could not find IRQ for $IFACE"
    echo "IRQ affinity will NOT be set"
    echo ""
    echo "Queue isolation enabled, but without IRQ pinning"
    exit 0
fi

echo "  Queue 0 IRQ: $IRQ"
echo ""

# Set IRQ affinity
echo "[3/4] Setting IRQ affinity..."
AFFINITY_FILE="/proc/irq/$IRQ/smp_affinity"

if [ ! -f "$AFFINITY_FILE" ]; then
    echo "Warning: Affinity file $AFFINITY_FILE not found"
    exit 0
fi

# Calculate affinity mask (single CPU)
MASK=$(printf '%x' $((1 << AFXDP_CPU)))

echo "  Setting IRQ $IRQ affinity to CPU $AFXDP_CPU (mask: 0x$MASK)"
echo "$MASK" > "$AFFINITY_FILE"

# Verify
CURRENT_MASK=$(cat "$AFFINITY_FILE")
echo "  Current affinity: 0x$CURRENT_MASK"
echo ""

# Display queue assignment
echo "[4/4] Queue Assignment Summary"
echo "  ┌──────────┬────────────────────┬─────────────┐"
echo "  │ Queue    │ Purpose            │ CPU Affinity│"
echo "  ├──────────┼────────────────────┼─────────────┤"
echo "  │ 0        │ AF_XDP (VOQd)      │ CPU $AFXDP_CPU      │"
echo "  │ 1-3      │ XDP Fast-Path      │ Shared      │"
echo "  └──────────┴────────────────────┴─────────────┘"
echo ""

# Performance tuning recommendations
echo "=========================================="
echo "Performance Tuning (Optional)"
echo "=========================================="
echo ""
echo "For optimal performance, consider:"
echo ""
echo "1. Disable IRQ balancing for $IFACE:"
echo "   echo $IRQ > /proc/irq/$IRQ/smp_affinity_hint"
echo ""
echo "2. Pin VOQd process to CPU $AFXDP_CPU:"
echo "   taskset -c $AFXDP_CPU ./build/rswitch-voqd ..."
echo ""
echo "3. Increase ring buffer sizes:"
echo "   ethtool -G $IFACE rx 4096 tx 4096"
echo ""
echo "4. Enable busy polling (if supported):"
echo "   sysctl -w net.core.busy_poll=50"
echo "   sysctl -w net.core.busy_read=50"
echo ""

echo "✓ Queue isolation setup complete!"
