#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

require_root
require_build

NS_A="rs-vlan-a"
NS_B="rs-vlan-b"
VETH_A="veth-vlan-a"
VETH_B="veth-vlan-b"
PIN_DIR="$BPF_PIN_PATH/rs_it_vlan"
PCAP_ALLOW="/tmp/rs_vlan_allow.pcap"
PCAP_DENY="/tmp/rs_vlan_deny.pcap"

teardown() {
    ip netns exec "$NS_A" bpftool net detach xdpgeneric dev "$VETH_A" 2>/dev/null || true
    teardown_veth_pair "$NS_A" "$NS_B" "$VETH_A"
    rm -rf "$PIN_DIR" "$PCAP_ALLOW" "$PCAP_DENY" 2>/dev/null || true
    cleanup_bpf
}

trap teardown EXIT

echo "========================================="
echo "VLAN Filtering Integration Tests"
echo "========================================="
echo ""

cleanup_bpf
setup_veth_pair "$NS_A" "$NS_B" "$VETH_A" "$VETH_B" "10.10.10.1/24" "10.10.10.2/24"
mkdir -p "$PIN_DIR"

echo "=== Test 1: Load profile context ==="
if [ -f "$PROFILE_DIR/l2.yaml" ]; then
    pass "profile exists: l2.yaml"
else
    skip "l2.yaml profile missing"
fi
echo ""

echo "=== Test 2: Load and attach VLAN module ==="
load_out="$(bpftool prog loadall "$BPF_DIR/vlan.bpf.o" "$PIN_DIR" type xdp 2>&1)"
if [ "$?" -ne 0 ]; then
    if printf "%s" "$load_out" | grep -Eqi 'operation not permitted|permission denied|not supported'; then
        skip "BPF load not permitted in this environment"
        print_summary "VLAN Filtering Integration Tests"
        exit 0
    fi
    fail "failed to load vlan.bpf.o"
    print_summary "VLAN Filtering Integration Tests"
    exit 1
fi
prog_pin="$PIN_DIR/vlan_ingress"
if [ ! -e "$prog_pin" ]; then
    prog_pin="$(ls "$PIN_DIR" 2>/dev/null | awk 'NR==1{print}' )"
    [ -n "$prog_pin" ] && prog_pin="$PIN_DIR/$prog_pin"
fi
if [ -e "$prog_pin" ] && ip netns exec "$NS_A" bpftool net attach xdpgeneric pinned "$prog_pin" dev "$VETH_A" 2>/dev/null; then
    pass "vlan program attached to $VETH_A"
else
    skip "could not attach VLAN program"
fi
echo ""

echo "=== Test 3: VLAN tagged traffic path ==="
capture_packet "$NS_B" "$VETH_B" "$PCAP_ALLOW" 3 &
cap_pid=$!
sleep 0.2
send_packet "$NS_A" "$VETH_A" "10.10.10.1" "10.10.10.2" tcp 443 100
wait "$cap_pid"
assert_forwarded "$PCAP_ALLOW" "tagged VLAN traffic forwarded"
echo ""

echo "=== Test 4: Non-member VLAN traffic path ==="
capture_packet "$NS_B" "$VETH_B" "$PCAP_DENY" 3 &
cap_pid=$!
sleep 0.2
send_packet "$NS_A" "$VETH_A" "10.10.10.1" "10.10.10.2" tcp 443 4094
wait "$cap_pid"
assert_dropped "$PCAP_DENY" "non-member VLAN traffic dropped"
echo ""

print_summary "VLAN Filtering Integration Tests"
exit $?
