#!/bin/bash
# Add ARP entries for inter-VLAN routing test
# This script helps add ARP entries for known hosts in both VLANs

set -e

ROUTECTL="./build/rsroutectl"

echo "=== Adding ARP Entries for Inter-VLAN Routing Test ==="
echo
echo "This script will help you add ARP entries for hosts in both VLANs."
echo "You need to know the MAC addresses of the test hosts."
echo

# Function to get MAC from IP on a specific interface
get_mac_from_arp() {
    local ip=$1
    local iface=$2
    # Try to get MAC from system ARP table
    arp -n | grep "^${ip} " | awk '{print $3}' | head -1
}

# VLAN 10 host (10.174.129.196)
echo "=== VLAN 10 Host ==="
echo "Detected from trace: 10.174.129.196"
read -p "Enter MAC address for 10.174.129.196 (or press Enter to skip): " mac_10
if [ ! -z "$mac_10" ]; then
    echo "Adding ARP entry: 10.174.129.196 -> $mac_10 on ifindex 4 (ens35)"
    sudo $ROUTECTL arp-add --ip 10.174.129.196 --mac $mac_10 --ifindex 4
    echo "  ✓ Added"
else
    echo "  ⊘ Skipped"
fi
echo

# VLAN 1 host (10.174.29.155)
echo "=== VLAN 1 Host ==="
echo "Detected from trace: 10.174.29.155"
read -p "Enter MAC address for 10.174.29.155 (or press Enter to skip): " mac_1
if [ ! -z "$mac_1" ]; then
    echo "Adding ARP entry: 10.174.29.155 -> $mac_1 on ifindex 5 (ens36)"
    sudo $ROUTECTL arp-add --ip 10.174.29.155 --mac $mac_1 --ifindex 5
    echo "  ✓ Added"
else
    echo "  ⊘ Skipped"
fi
echo

# Show current ARP table
echo "=== Current ARP Table ==="
sudo $ROUTECTL arp-show

echo
echo "=== How to Find MAC Addresses ==="
echo
echo "Method 1: From the host itself"
echo "  On 10.174.129.196: ip link show"
echo "  On 10.174.29.155: ip link show"
echo
echo "Method 2: From rSwitch system ARP table (if hosts communicated recently)"
echo "  arp -n | grep 10.174.129.196"
echo "  arp -n | grep 10.174.29.155"
echo
echo "Method 3: Check switch MAC learning table (if L2 learning is working)"
echo "  sudo ./build/rswitch-events  # Monitor MAC learning events"
echo
echo "Method 4: Ping first, then check ARP"
echo "  ping -c 1 10.174.129.196"
echo "  arp -n | grep 10.174.129.196"
echo
