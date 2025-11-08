#!/bin/bash
# ARP Learning Helper for rSwitch
#
# This script monitors ARP traffic on router interfaces and populates
# the rSwitch ARP table automatically.
#
# Usage: sudo ./arp_learn_helper.sh

set -e

RSROUTECTL="./build/rsroutectl"

# Router interfaces (from your config)
IFACES="ens34 ens35 ens36"

echo "=== rSwitch ARP Learning Helper ==="
echo "Monitoring interfaces: $IFACES"
echo "Learning ARP entries and adding to rSwitch..."
echo ""

# Get ifindex for an interface
get_ifindex() {
    local iface=$1
    ip link show "$iface" | head -1 | awk -F: '{print $1}'
}

# Monitor ARP traffic and extract IP-MAC mappings
# tcpdump output format: "ARP, Request who-has 10.174.129.196 tell 10.174.29.155"
#                        "ARP, Reply 10.174.129.196 is-at aa:bb:cc:dd:ee:ff"
for iface in $IFACES; do
    ifindex=$(get_ifindex "$iface")
    echo "Monitoring $iface (ifindex=$ifindex)..."
    
    # Run tcpdump in background, parse ARP replies
    sudo tcpdump -i "$iface" -l -n arp 2>/dev/null | while read line; do
        # Parse ARP reply: "10.174.129.196 is-at aa:bb:cc:dd:ee:ff"
        if echo "$line" | grep -q "is-at"; then
            ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
            mac=$(echo "$line" | grep -oP '([0-9a-f]{2}:){5}[0-9a-f]{2}')
            
            if [ -n "$ip" ] && [ -n "$mac" ]; then
                echo "[$(date '+%H:%M:%S')] Learned: $ip -> $mac on $iface"
                
                # Add to rSwitch ARP table
                $RSROUTECTL arp-add --ip "$ip" --mac "$mac" --ifindex "$ifindex" 2>/dev/null && \
                    echo "  ✓ Added to rSwitch ARP table" || \
                    echo "  ✗ Failed to add (may already exist)"
            fi
        fi
    done &
done

echo ""
echo "ARP learning started. Press Ctrl+C to stop."
echo "Tip: Generate some traffic to populate ARP table:"
echo "  - Ping from hosts in VLAN 1: ping 10.174.129.1"
echo "  - Ping from hosts in VLAN 10: ping 10.174.29.1"
echo ""

# Wait for background jobs
wait
