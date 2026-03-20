#!/bin/bash
# rSwitch BPF Unit Test Runner
#
# This script stops rswitch services before running tests (to avoid
# destroying production pinned maps), then restarts them after.

if [ $(id -u) -ne 0 ]; then
    echo "Must run as root for BPF"
    exit 1
fi

BPF_DIR=./build/bpf
TEST_DIR=./build
FAIL=0

# ── Service Management ──────────────────────────────────────────
# Stop rswitch services before tests to avoid nuking production maps.
SERVICES_WERE_RUNNING=0
if systemctl is-active --quiet rswitch 2>/dev/null; then
    SERVICES_WERE_RUNNING=1
    echo "Stopping rswitch services for testing..."
    systemctl stop rswitch-mgmtd 2>/dev/null || true
    systemctl stop rswitch 2>/dev/null || true
    # Give services time to fully stop
    sleep 1
fi

cleanup_bpf() {
    rm -f /sys/fs/bpf/*
}

restart_services() {
    if [ "$SERVICES_WERE_RUNNING" = "1" ]; then
        echo ""
        echo "Restarting rswitch services..."
        systemctl start rswitch 2>/dev/null || true
        sleep 1
        systemctl start rswitch-mgmtd 2>/dev/null || true
        echo "Services restarted."
    fi
}

# Always restart services on exit (even on failure/interrupt)
trap restart_services EXIT

run_test() {
    echo "Running $1 tests"
    shift
    "$@"
    if [ $? -ne 0 ]; then
        FAIL=1
    fi
}

cleanup_bpf

run_test "dispatcher" $TEST_DIR/test_dispatcher $BPF_DIR/dispatcher.bpf.o
cleanup_bpf

run_test "ACL" $TEST_DIR/test_acl $BPF_DIR/acl.bpf.o
cleanup_bpf

run_test "VLAN" $TEST_DIR/test_vlan $BPF_DIR/vlan.bpf.o
cleanup_bpf

if [ -x "$TEST_DIR/test_acl_bpf" ]; then
    run_test "ACL BPF_PROG_RUN" $TEST_DIR/test_acl_bpf $BPF_DIR/acl.bpf.o $TEST_DIR/test_acl_bpf.junit.xml
    cleanup_bpf
fi

run_test "STP" $TEST_DIR/test_stp $BPF_DIR/stp.bpf.o
cleanup_bpf

run_test "Rate Limiter" $TEST_DIR/test_rate_limiter $BPF_DIR/rate_limiter.bpf.o
cleanup_bpf

run_test "Source Guard" $TEST_DIR/test_source_guard $BPF_DIR/source_guard.bpf.o
cleanup_bpf

run_test "Conntrack" $TEST_DIR/test_conntrack $BPF_DIR/conntrack.bpf.o
cleanup_bpf

run_test "ARP Learn" $TEST_DIR/test_arp_learn $BPF_DIR/arp_learn.bpf.o
cleanup_bpf

run_test "L2Learn" $TEST_DIR/test_l2learn $BPF_DIR/l2learn.bpf.o
cleanup_bpf

run_test "Route" $TEST_DIR/test_route $BPF_DIR/route.bpf.o
cleanup_bpf

run_test "Mirror" $TEST_DIR/test_mirror $BPF_DIR/mirror.bpf.o
cleanup_bpf

if [ $FAIL -ne 0 ]; then
    echo ""
    echo "SOME TESTS FAILED"
    exit 1
fi

echo ""
echo "All BPF unit tests passed"
