#!/bin/bash
# Test script for multi-level ACL architecture

set -e

RSACLCTL="./build/rsaclctl"
LOADER="./build/rswitch_loader"

echo "═══════════════════════════════════════════════════════"
echo "  rSwitch ACL Multi-Level Index Architecture Test"
echo "═══════════════════════════════════════════════════════"
echo ""

# Check if loader is running
if ! sudo $RSACLCTL list &>/dev/null; then
    echo "⚠ Warning: ACL maps not found. Make sure rSwitch is loaded first:"
    echo "  sudo $LOADER --profile etc/profiles/l3.yaml"
    echo ""
    exit 1
fi

echo "Step 1: Clear existing rules"
echo "────────────────────────────────────────"
sudo $RSACLCTL clear
echo ""

echo "Step 2: Set default action to PASS (allow all by default)"
echo "────────────────────────────────────────"
sudo $RSACLCTL set-default --action pass
echo ""

echo "Step 3: Add Level 1 (5-tuple exact match) rules"
echo "────────────────────────────────────────"
echo "  Block SSH from specific host to specific server"
sudo $RSACLCTL add-5t \
    --proto tcp \
    --src 10.1.2.3 \
    --dst 192.168.1.100 \
    --dport 22 \
    --action drop \
    --log

echo ""
echo "  Block HTTPS traffic from attacker to web server"
sudo $RSACLCTL add-5t \
    --proto tcp \
    --src 10.10.10.10 \
    --sport 0 \
    --dst 192.168.1.80 \
    --dport 443 \
    --action drop

echo ""

echo "Step 4: Add Level 2 (LPM prefix) rules"
echo "────────────────────────────────────────"
echo "  Block entire source subnet 10.0.0.0/8"
sudo $RSACLCTL add-lpm-src \
    --prefix 10.0.0.0/8 \
    --action drop \
    --log

echo ""
echo "  Allow traffic to management subnet 192.168.100.0/24"
sudo $RSACLCTL add-lpm-dst \
    --prefix 192.168.100.0/24 \
    --action pass

echo ""

echo "Step 5: Enable ACL processing"
echo "────────────────────────────────────────"
sudo $RSACLCTL enable
echo ""

echo "Step 6: List all rules"
echo "────────────────────────────────────────"
sudo $RSACLCTL list
echo ""

echo "Step 7: Monitor statistics (run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' in another terminal)"
echo "────────────────────────────────────────"
echo "Send test traffic and watch for ACL debug messages:"
echo ""
echo "  # From another host, test Level 1 (5-tuple) match:"
echo "  ssh user@192.168.1.100  # Should be blocked if source is 10.1.2.3"
echo ""
echo "  # Test Level 2 (LPM src) match:"
echo "  ping 192.168.1.1  # Should be blocked if source is in 10.0.0.0/8"
echo ""
echo "  # Test default PASS:"
echo "  ping 192.168.1.1  # Should pass if source not in blocked ranges"
echo ""

echo "Step 8: View statistics after traffic"
echo "────────────────────────────────────────"
echo "(Press Ctrl+C after sending test traffic, then run:)"
echo "  sudo $RSACLCTL stats"
echo ""

echo "═══════════════════════════════════════════════════════"
echo "  ACL Architecture Summary"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Matching Order (priority):"
echo "  1. Level 1: 5-tuple exact match (HASH)"
echo "     - O(1) lookup, highest priority"
echo "     - Specific flows (proto + src_ip:port + dst_ip:port)"
echo ""
echo "  2. Level 2a: Source IP prefix (LPM TRIE)"
echo "     - O(log N) longest prefix match"
echo "     - Entire source subnets"
echo ""
echo "  3. Level 2b: Destination IP prefix (LPM TRIE)"
echo "     - O(log N) longest prefix match"
echo "     - Entire destination subnets"
echo ""
echo "  4. Level 3: Default policy"
echo "     - Global PASS or DROP if no match above"
echo ""
echo "Performance:"
echo "  ✓ No linear iteration over rules"
echo "  ✓ Scales to thousands of rules with map-based indexing"
echo "  ✓ Per-CPU statistics (lock-free)"
echo "  ✓ Debug logging for verification"
echo ""
echo "Control Plane:"
echo "  rsaclctl add-5t       - Add exact match rule"
echo "  rsaclctl add-lpm-src  - Add source prefix rule"
echo "  rsaclctl add-lpm-dst  - Add destination prefix rule"
echo "  rsaclctl list         - Show all rules"
echo "  rsaclctl stats        - Show per-level statistics"
echo "  rsaclctl clear        - Clear all rules"
echo "  rsaclctl enable/disable - Toggle ACL processing"
echo ""
