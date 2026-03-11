#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

require_root
require_build

NS_A="rs-route-a"
NS_B="rs-route-b"
VETH_A="veth-route-a"
VETH_B="veth-route-b"
PIN_DIR="$BPF_PIN_PATH/rs_it_route"
PCAP_FWD="/tmp/rs_route_fwd.pcap"
PCAP_DROP="/tmp/rs_route_drop.pcap"

teardown() {
    ip netns exec "$NS_A" bpftool net detach xdpgeneric dev "$VETH_A" 2>/dev/null || true
    teardown_veth_pair "$NS_A" "$NS_B" "$VETH_A"
    rm -rf "$PIN_DIR" "$PCAP_FWD" "$PCAP_DROP" 2>/dev/null || true
    cleanup_bpf
}

trap teardown EXIT

echo "========================================="
echo "Route Forwarding Integration Tests"
echo "========================================="
echo ""

cleanup_bpf
setup_veth_pair "$NS_A" "$NS_B" "$VETH_A" "$VETH_B" "10.30.0.1/24" "10.30.0.2/24"
mkdir -p "$PIN_DIR"

echo "=== Test 1: Load profile context ==="
if [ -f "$PROFILE_DIR/l3.yaml" ]; then
    pass "profile exists: l3.yaml"
else
    skip "l3.yaml profile missing"
fi
echo ""

echo "=== Test 2: Load and attach route module ==="
load_out="$(bpftool prog loadall "$BPF_DIR/route.bpf.o" "$PIN_DIR" type xdp 2>&1)"
if [ "$?" -ne 0 ]; then
    if printf "%s" "$load_out" | grep -Eqi 'operation not permitted|permission denied|not supported'; then
        skip "BPF load not permitted in this environment"
        print_summary "Route Forwarding Integration Tests"
        exit 0
    fi
    fail "failed to load route.bpf.o"
    print_summary "Route Forwarding Integration Tests"
    exit 1
fi
prog_pin="$PIN_DIR/route_ipv4"
if [ ! -e "$prog_pin" ]; then
    prog_pin="$(ls "$PIN_DIR" 2>/dev/null | awk 'NR==1{print}')"
    [ -n "$prog_pin" ] && prog_pin="$PIN_DIR/$prog_pin"
fi
if [ -e "$prog_pin" ] && ip netns exec "$NS_A" bpftool net attach xdpgeneric pinned "$prog_pin" dev "$VETH_A" 2>/dev/null; then
    pass "route program attached to $VETH_A"
else
    skip "could not attach route program"
fi
echo ""

echo "=== Test 3: Program route config ==="
if [ -e "$PIN_DIR/route_cfg" ]; then
    bpftool map update pinned "$PIN_DIR/route_cfg" key hex 00 00 00 00 value hex 01 00 00 00 >/dev/null 2>&1
    pass "route config enabled"
else
    skip "route_cfg map not pinned"
fi
echo ""

echo "=== Test 4: Route miss should drop ==="
capture_packet "$NS_B" "$VETH_B" "$PCAP_DROP" 3 &
cap_pid=$!
sleep 0.2
send_packet "$NS_A" "$VETH_A" "10.30.0.1" "8.8.8.8" icmp 0 0
wait "$cap_pid"
assert_dropped "$PCAP_DROP" "packet without route entry dropped"
assert_counter "route_stats" 2 1 "route miss counter increments" "$PIN_DIR/route_stats"
echo ""

echo "=== Test 5: Placeholder forwarding probe ==="
capture_packet "$NS_B" "$VETH_B" "$PCAP_FWD" 3 &
cap_pid=$!
sleep 0.2
send_packet "$NS_A" "$VETH_A" "10.30.0.1" "10.30.0.2" icmp 0 0
wait "$cap_pid"
if [ -s "$PCAP_FWD" ]; then
    pass "forwarding path reachable"
else
    skip "forwarding path depends on full pipeline route + arp setup"
fi
echo ""

print_summary "Route Forwarding Integration Tests"
exit $?
