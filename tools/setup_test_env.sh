#!/bin/bash
#
# rSwitch Proper Test Environment Setup
# 
# Problem: Linux bridge itself is a L2 switch, making tests unreliable
# Solution: Use veth pairs WITHOUT bridge, force traffic through XDP
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  rSwitch Test Environment Setup (No Bridge)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Cleanup old environment
echo -e "${YELLOW}[1/5] Cleaning up old environment...${NC}"
sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo ip link del veth-ns1 2>/dev/null || true
sudo ip link del veth-ns2 2>/dev/null || true
sudo ip link del br0 2>/dev/null || true
echo "  ✓ Old interfaces removed"

# Create namespaces
echo -e "${YELLOW}[2/5] Creating network namespaces...${NC}"
sudo ip netns add ns1
sudo ip netns add ns2
echo "  ✓ ns1, ns2 created"

# Create veth pairs
echo -e "${YELLOW}[3/5] Creating veth pairs...${NC}"
sudo ip link add veth-ns1 type veth peer name veth-host1
sudo ip link add veth-ns2 type veth peer name veth-host2
echo "  ✓ veth pairs created"

# Move one end to namespaces
echo -e "${YELLOW}[4/5] Configuring interfaces...${NC}"
sudo ip link set veth-ns1 netns ns1
sudo ip link set veth-ns2 netns ns2

# Configure ns1
sudo ip netns exec ns1 ip addr add 192.168.100.10/24 dev veth-ns1
sudo ip netns exec ns1 ip link set veth-ns1 up
sudo ip netns exec ns1 ip link set lo up

# Configure ns2
sudo ip netns exec ns2 ip addr add 192.168.100.20/24 dev veth-ns2
sudo ip netns exec ns2 ip link set veth-ns2 up
sudo ip netns exec ns2 ip link set lo up

# Configure host-side veth interfaces
sudo ip link set veth-host1 up
sudo ip link set veth-host2 up

# CRITICAL: Do NOT add IP addresses to host-side veths
# They should only forward packets via XDP
echo "  ✓ IP addresses configured"
echo ""
echo -e "${GREEN}Topology:${NC}"
echo "  ns1 [veth-ns1: 192.168.100.10/24] ←→ [veth-host1] (host, no IP)"
echo "  ns2 [veth-ns2: 192.168.100.20/24] ←→ [veth-host2] (host, no IP)"
echo ""
echo -e "${YELLOW}  ⚠️  WITHOUT XDP: ns1 and ns2 CANNOT communicate${NC}"
echo -e "${GREEN}  ✓  WITH XDP rSwitch: veth-host1 ↔ veth-host2 forwarding${NC}"

# Test connectivity (should FAIL without XDP)
echo ""
echo -e "${YELLOW}[5/5] Testing connectivity WITHOUT XDP...${NC}"
if sudo ip netns exec ns1 ping -c 1 -W 1 192.168.100.20 &>/dev/null; then
    echo -e "${RED}  ✗ UNEXPECTED: Ping succeeded without XDP!${NC}"
    echo -e "${RED}    This means the environment is still broken.${NC}"
    exit 1
else
    echo -e "${GREEN}  ✓ Ping fails as expected (no XDP program loaded)${NC}"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Environment Ready!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
echo "  1. Load rSwitch with: veth-host1 and veth-host2"
echo "     Example: sudo ./build/rswitch_loader --iface veth-host1,veth-host2 --profile etc/profiles/l2.yaml"
echo ""
echo "  2. Test connectivity:"
echo "     sudo ip netns exec ns1 ping -c 5 192.168.100.20"
echo ""
echo "  3. Monitor XDP actions:"
echo "     sudo bpftool prog tracelog"
echo ""
echo -e "${YELLOW}Critical difference from bridge setup:${NC}"
echo "  • No Linux bridge = No automatic L2 forwarding"
echo "  • XDP program MUST work for any connectivity"
echo "  • True validation of rSwitch functionality"
echo ""
