#!/bin/bash
# Test script to verify loader cleanup functionality

echo "========== Cleanup Test =========="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Function to check pinned maps
check_pinned_maps() {
    echo "Checking pinned BPF maps:"
    ls -la /sys/fs/bpf/ 2>/dev/null | grep "^-" || echo "  (no pinned maps found)"
    echo ""
}

# Function to check loaded XDP programs
check_xdp_progs() {
    echo "Checking loaded XDP programs:"
    bpftool prog show type xdp 2>/dev/null || echo "  (no XDP programs loaded)"
    echo ""
}

# Function to check interface XDP attachments
check_xdp_attachments() {
    echo "Checking XDP attachments on interfaces:"
    for iface in ens34 ens35 ens36; do
        if ip link show $iface &>/dev/null; then
            xdp_info=$(ip link show $iface | grep xdp || echo "")
            if [ -n "$xdp_info" ]; then
                echo "  $iface: XDP attached"
            else
                echo "  $iface: no XDP"
            fi
        fi
    done
    echo ""
}

echo "=== BEFORE Loader Run ==="
check_pinned_maps
check_xdp_progs
check_xdp_attachments

echo "=== Starting Loader (will run for 5 seconds) ==="
timeout 5s ./build/rswitch_loader -i ens34,ens35,ens36 -m dumb -v || true
echo ""

echo "=== AFTER Loader Exit ==="
check_pinned_maps
check_xdp_progs
check_xdp_attachments

echo "========== Cleanup Test Complete =========="
echo ""
echo "Expected result: All maps unpinned, all XDP programs detached"
