#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RSWITCH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib.sh"

require_root
require_build

echo "========================================="
echo "Loader Integration Tests"
echo "========================================="
echo ""

echo "=== Test 1: Build Artifacts Exist ==="
required_bins=(
    rswitch_loader hot_reload rswitch-voqd rswitchctl rsportctl rsvlanctl
    rsaclctl rsroutectl rsqosctl rsvoqctl rswitch-telemetry rswitch-events
    rs_packet_trace test_dispatcher test_acl test_vlan
)

for bin in "${required_bins[@]}"; do
    if [ -x "$BUILD_DIR/$bin" ]; then
        pass "binary exists: $bin"
    else
        fail "binary missing: $bin"
    fi
done

bpf_count=0
for obj in "$BPF_DIR"/*.bpf.o; do
    if [ -f "$obj" ]; then
        bpf_count=$((bpf_count + 1))
        pass "BPF object exists: $(basename "$obj")"
    fi
done

if [ "$bpf_count" -ge 10 ]; then
    pass "BPF object count sanity: $bpf_count"
else
    fail "BPF object count too low: $bpf_count"
fi
echo ""

echo "=== Test 2: BPF Module Metadata (.rodata.mod) ==="
for obj in "$BPF_DIR"/*.bpf.o; do
    [ -f "$obj" ] || continue
    if llvm-objdump -h "$obj" 2>/dev/null | grep -q "\.rodata\.mod"; then
        pass "metadata present: $(basename "$obj")"
    else
        fail "metadata missing: $(basename "$obj")"
    fi
done
echo ""

echo "=== Test 3: BPF Module BTF (.BTF) ==="
for obj in "$BPF_DIR"/*.bpf.o; do
    [ -f "$obj" ] || continue
    if llvm-objdump -h "$obj" 2>/dev/null | grep -q "\.BTF"; then
        pass "BTF present: $(basename "$obj")"
    else
        fail "BTF missing: $(basename "$obj")"
    fi
done
echo ""

echo "=== Test 4: Loader Help ==="
loader_output="$($BUILD_DIR/rswitch_loader --help 2>&1)"
loader_rc=$?
if [ "$loader_rc" -eq 0 ] || printf "%s" "$loader_output" | grep -qi "usage"; then
    pass "rswitch_loader help works"
else
    fail "rswitch_loader --help failed"
fi
echo ""

echo "=== Test 5: Profile Listing ==="
profile_count=$(ls -1 "$PROFILE_DIR"/*.yaml 2>/dev/null | wc -l)
if [ "$profile_count" -ge 10 ]; then
    pass "profiles available: $profile_count"
else
    fail "expected >=10 profiles, got $profile_count"
fi
echo ""

echo "=== Test 6: CLI Tools Help ==="
cli_tools=(rswitchctl rsportctl rsvlanctl rsaclctl rsroutectl rsqosctl rsvoqctl rs_packet_trace rswitch-events rswitch-telemetry)
for tool in "${cli_tools[@]}"; do
    output="$($BUILD_DIR/$tool 2>&1)"
    rc=$?
    if [ "$rc" -le 1 ] && [ -n "$output" ]; then
        pass "$tool prints help/usage"
    else
        fail "$tool failed without usage output"
    fi
done
echo ""

cleanup_bpf
print_summary "Loader Integration Tests"
exit $?
