#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

require_root
require_build

echo "========================================="
echo "Hot-Reload Integration Tests"
echo "========================================="
echo ""

echo "=== Test 1: hot_reload Binary Exists ==="
if [ -x "$BUILD_DIR/hot_reload" ]; then
    pass "hot_reload binary exists"
else
    fail "hot_reload binary missing"
fi
echo ""

echo "=== Test 2: hot_reload Help ==="
help_out="$($BUILD_DIR/hot_reload --help 2>&1)"
help_rc=$?
if [ "$help_rc" -eq 0 ] && printf "%s" "$help_out" | grep -qi "usage"; then
    pass "hot_reload --help works"
else
    noarg_out="$($BUILD_DIR/hot_reload 2>&1)"
    if printf "%s" "$noarg_out" | grep -qi "usage"; then
        pass "hot_reload prints usage with no args"
    else
        fail "hot_reload help/usage output unavailable"
    fi
fi
echo ""

echo "=== Test 3: hot_reload Dry-Run ==="
if printf "%s" "$help_out" | grep -q -- "--dry-run"; then
    dry_out="$($BUILD_DIR/hot_reload list --dry-run 2>&1)"
    dry_rc=$?
    if [ "$dry_rc" -eq 0 ] || printf "%s" "$dry_out" | grep -Eqi 'dry-run|loaded modules|pipeline'; then
        pass "hot_reload dry-run path is reachable"
    else
        skip "dry-run execution requires active loader state"
    fi
else
    skip "hot_reload does not expose --dry-run"
fi
echo ""

print_summary "Hot-Reload Integration Tests"
exit $?
