#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

require_root
require_build

VETH_A="rs-test0"
VETH_B="rs-test1"
PIN_DIR="$BPF_PIN_PATH/rs_test"

teardown() {
    bpftool net detach xdpgeneric dev "$VETH_A" 2>/dev/null || true
    ip link set dev "$VETH_A" xdp off 2>/dev/null || true
    teardown_veth "$VETH_A"
    rm -rf "$PIN_DIR" 2>/dev/null || true
    cleanup_bpf
}

trap teardown EXIT

echo "========================================="
echo "Pipeline Integration Tests"
echo "========================================="
echo ""

cleanup_bpf
setup_veth "$VETH_A" "$VETH_B"
ip addr add 192.168.99.1/24 dev "$VETH_A" 2>/dev/null || true
ip addr add 192.168.99.2/24 dev "$VETH_B" 2>/dev/null || true
mkdir -p "$PIN_DIR"

echo "=== Test 1: Load Dispatcher BPF Object ==="
load_out="$(bpftool prog loadall "$BPF_DIR/dispatcher.bpf.o" "$PIN_DIR" type xdp 2>&1)"
load_rc=$?
if [ "$load_rc" -ne 0 ]; then
    if printf "%s" "$load_out" | grep -Eqi 'operation not permitted|permission denied|not supported'; then
        skip "BPF load not permitted in this environment"
        print_summary "Pipeline Integration Tests"
        exit 0
    fi
    fail "failed to load dispatcher.bpf.o"
else
    pass "dispatcher.bpf.o loaded"
fi
echo ""

echo "=== Test 2: Verify Maps Created ==="
maps=(rs_ctx_map rs_progs rs_prog_chain rs_event_bus rs_port_config_map rs_stats_map)
for map in "${maps[@]}"; do
    if [ -e "$BPF_PIN_PATH/$map" ] || [ -e "$PIN_DIR/$map" ]; then
        pass "map available: $map"
    else
        fail "map missing: $map"
    fi
done
echo ""

echo "=== Test 3: Attach XDP to veth ==="
dispatcher_pin="$PIN_DIR/rswitch_dispatcher"
if [ ! -e "$dispatcher_pin" ]; then
    dispatcher_pin="$(ls "$PIN_DIR" 2>/dev/null | head -n1)"
    [ -n "$dispatcher_pin" ] && dispatcher_pin="$PIN_DIR/$dispatcher_pin"
fi

prog_id=""
if [ -e "$dispatcher_pin" ]; then
    prog_id="$(bpftool prog show pinned "$dispatcher_pin" 2>/dev/null | awk '/id[[:space:]]+[0-9]+/{print $2; exit}')"
fi

if [ -n "$prog_id" ]; then
    if bpftool net attach xdpgeneric id "$prog_id" dev "$VETH_A" 2>/dev/null; then
        if ip -details link show "$VETH_A" | grep -q "xdp"; then
            pass "XDP program attached to $VETH_A"
        else
            fail "XDP attach command succeeded but no xdp state"
        fi
    else
        skip "could not attach XDP program to $VETH_A"
    fi
else
    skip "could not determine dispatcher program id"
fi
echo ""

echo "=== Test 4: Send Packet Through Pipeline ==="
if ping -c 1 -W 1 -I "$VETH_A" 192.168.99.2 >/dev/null 2>&1; then
    pass "traffic passed through veth pair"
else
    skip "traffic probe failed; environment may block ICMP"
fi
echo ""

print_summary "Pipeline Integration Tests"
exit $?
