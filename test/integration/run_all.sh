#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OVERALL_PASS=0
OVERALL_FAIL=0

echo "========================================="
echo "rSwitch Integration Test Suite"
echo "========================================="
echo ""

run_test() {
    local name="$1"
    local script="$2"

    echo "--- Running: $name ---"
    if bash "$SCRIPT_DIR/$script"; then
        OVERALL_PASS=$((OVERALL_PASS + 1))
    else
        OVERALL_FAIL=$((OVERALL_FAIL + 1))
    fi
    echo ""
}

run_test "Loader Tests" "test_loader.sh"
run_test "Profile Tests" "test_profiles.sh"
run_test "Pipeline Tests" "test_pipeline.sh"
run_test "Hot-Reload Tests" "test_hotreload.sh"
run_test "VLAN Filtering Tests" "test_vlan_filtering.sh"
run_test "ACL Rules Tests" "test_acl_rules.sh"
run_test "Route Forwarding Tests" "test_route_forwarding.sh"

echo "========================================="
echo "Overall Results: $OVERALL_PASS suites passed, $OVERALL_FAIL failed"
echo "========================================="

[ "$OVERALL_FAIL" -eq 0 ]
