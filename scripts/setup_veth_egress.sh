#!/bin/bash
# Setup veth pair for VOQd egress path
# Creates veth_voq_in <-> veth_voq_out pair with XDP-compatible settings

set -e

VETH_IN="${VETH_IN:-veth_voq_in}"
VETH_OUT="${VETH_OUT:-veth_voq_out}"
MTU="${MTU:-1500}"
TXQUEUELEN="${TXQUEUELEN:-10000}"
XDP_MODE="${XDP_MODE:-native}"

usage() {
    echo "Usage: $0 [create|destroy|status]"
    echo ""
    echo "Environment variables:"
    echo "  VETH_IN      - Inside veth name (default: veth_voq_in)"
    echo "  VETH_OUT     - Outside veth name (default: veth_voq_out)"
    echo "  MTU          - MTU size (default: 1500)"
    echo "  TXQUEUELEN   - TX queue length (default: 10000)"
    echo "  XDP_MODE     - XDP mode: native or generic (default: native)"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: Must run as root"
        exit 1
    fi
}

veth_exists() {
    ip link show "$1" &>/dev/null
}

create_veth() {
    check_root
    
    if veth_exists "$VETH_IN"; then
        echo "Veth pair already exists, destroying first..."
        destroy_veth
    fi
    
    echo "Creating veth pair: $VETH_IN <-> $VETH_OUT"
    ip link add "$VETH_IN" type veth peer name "$VETH_OUT"
    
    ip link set "$VETH_IN" up
    ip link set "$VETH_OUT" up
    
    ethtool -K "$VETH_IN" gro off gso off tso off rx off tx off 2>/dev/null || true
    ethtool -K "$VETH_OUT" gro off gso off tso off rx off tx off 2>/dev/null || true
    
    ip link set "$VETH_IN" txqueuelen "$TXQUEUELEN"
    ip link set "$VETH_OUT" txqueuelen "$TXQUEUELEN"
    
    ip link set "$VETH_IN" mtu "$MTU"
    ip link set "$VETH_OUT" mtu "$MTU"
    
    VETH_IN_IDX=$(cat /sys/class/net/"$VETH_IN"/ifindex)
    VETH_OUT_IDX=$(cat /sys/class/net/"$VETH_OUT"/ifindex)
    
    echo "Veth pair created successfully:"
    echo "  $VETH_IN (ifindex: $VETH_IN_IDX) - VOQd TX target"
    echo "  $VETH_OUT (ifindex: $VETH_OUT_IDX) - XDP attach point"
    echo ""
    echo "XDP mode: $XDP_MODE"
    if [ "$XDP_MODE" = "generic" ]; then
        echo "WARNING: Generic XDP mode has worse performance than native."
        echo "         Use for testing only."
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Attach veth_egress XDP to $VETH_OUT"
    echo "  2. Create AF_XDP socket on $VETH_IN for VOQd TX"
    echo "  3. Populate voq_egress_devmap with physical NIC entries"
}

destroy_veth() {
    check_root
    
    if ! veth_exists "$VETH_IN"; then
        echo "Veth pair does not exist"
        return 0
    fi
    
    if ip link show "$VETH_OUT" | grep -q "xdp"; then
        echo "Detaching XDP from $VETH_OUT..."
        ip link set "$VETH_OUT" xdp off 2>/dev/null || true
    fi
    
    echo "Destroying veth pair..."
    ip link delete "$VETH_IN" 2>/dev/null || true
    
    echo "Veth pair destroyed"
}

show_status() {
    echo "=== Veth Egress Status ==="
    echo ""
    
    if ! veth_exists "$VETH_IN"; then
        echo "Status: NOT CONFIGURED"
        echo ""
        echo "Run '$0 create' to create the veth pair"
        return 0
    fi
    
    echo "Status: CONFIGURED"
    echo ""
    
    echo "--- $VETH_IN ---"
    ip -d link show "$VETH_IN" 2>/dev/null | head -5
    echo ""
    
    echo "--- $VETH_OUT ---"
    ip -d link show "$VETH_OUT" 2>/dev/null | head -5
    
    if ip link show "$VETH_OUT" 2>/dev/null | grep -q "xdp"; then
        echo ""
        echo "XDP Program: ATTACHED"
        ip link show "$VETH_OUT" | grep xdp || true
    else
        echo ""
        echo "XDP Program: NOT ATTACHED"
    fi
    
    echo ""
    echo "--- Interface Statistics ---"
    echo "$VETH_IN:"
    cat /sys/class/net/"$VETH_IN"/statistics/tx_packets 2>/dev/null | xargs echo "  TX packets:"
    cat /sys/class/net/"$VETH_IN"/statistics/tx_bytes 2>/dev/null | xargs echo "  TX bytes:"
    echo "$VETH_OUT:"
    cat /sys/class/net/"$VETH_OUT"/statistics/rx_packets 2>/dev/null | xargs echo "  RX packets:"
    cat /sys/class/net/"$VETH_OUT"/statistics/rx_bytes 2>/dev/null | xargs echo "  RX bytes:"
}

case "${1:-}" in
    create)
        create_veth
        ;;
    destroy)
        destroy_veth
        ;;
    status)
        show_status
        ;;
    *)
        usage
        ;;
esac
