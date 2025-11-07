#!/bin/bash
# Configure inter-VLAN routing between VLAN 1 and VLAN 10
# VLAN 1: 10.174.29.0/24 (ens36=ifindex5, ens37=ifindex6)
# VLAN 10: 10.174.129.0/24 (ens35=ifindex4)

set -e

ROUTECTL="./build/rsroutectl"

echo "=== Configuring Inter-VLAN Routing ==="
echo

# Step 1: Configure router interfaces
echo "Step 1: Configuring router interfaces..."

# Configure ens35 (ifindex 4) for VLAN 10 (10.174.129.0/24)
# Use a virtual MAC for the router interface
echo "  - Configuring ens35 (ifindex 4) as router for VLAN 10..."
sudo $ROUTECTL iface-set --ifindex 4 --mac 02:00:00:00:01:0a --router

# Configure ens36 (ifindex 5) for VLAN 1 (10.174.29.0/24)
echo "  - Configuring ens36 (ifindex 5) as router for VLAN 1..."
sudo $ROUTECTL iface-set --ifindex 5 --mac 02:00:00:00:01:01 --router

echo

# Step 2: Add direct (connected) routes
echo "Step 2: Adding direct routes..."

# Route for VLAN 1 network (10.174.29.0/24) via ens36
echo "  - Adding route for 10.174.29.0/24 via ens36 (ifindex 5)..."
sudo $ROUTECTL route-add --dest 10.174.29.0/24 --nexthop 0.0.0.0 --ifindex 5

# Route for VLAN 10 network (10.174.129.0/24) via ens35
echo "  - Adding route for 10.174.129.0/24 via ens35 (ifindex 4)..."
sudo $ROUTECTL route-add --dest 10.174.129.0/24 --nexthop 0.0.0.0 --ifindex 4

echo

# Step 3: Add ARP entries for known hosts (optional, for testing)
echo "Step 3: Adding ARP entries..."
echo "  (Skipping - will be learned dynamically)"
echo "  To add static ARP entries, use:"
echo "    sudo $ROUTECTL arp-add --ip <HOST_IP> --mac <HOST_MAC> --ifindex <IFINDEX>"

echo

# Step 4: Enable routing
echo "Step 4: Enabling routing..."
sudo $ROUTECTL enable

echo
echo "=== Configuration Complete ==="
echo
echo "Routing table (routes):"
sudo $ROUTECTL route-show || echo "  (LPM trie cannot be iterated)"
echo
echo "ARP table:"
sudo $ROUTECTL arp-show
echo
echo "Router interfaces:"
echo "  - ens35 (ifindex 4): 02:00:00:00:01:0a [VLAN 10 gateway]"
echo "  - ens36 (ifindex 5): 02:00:00:00:01:01 [VLAN 1 gateway]"
echo
echo "To test:"
echo "  1. Set gateway on VLAN 1 host: ip route add 10.174.129.0/24 via 10.174.29.1"
echo "  2. Set gateway on VLAN 10 host: ip route add 10.174.29.0/24 via 10.174.129.1"
echo "  3. Ping across VLANs"
echo
echo "To view statistics:"
echo "  sudo $ROUTECTL stats"
