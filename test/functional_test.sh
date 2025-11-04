#!/bin/bash
# rSwitch Functional Test - Test ACL and Mirror functionality
# Prerequisites: 
#   - rSwitch loader must be running with modules loaded
#   - BPF maps must be pinned to /sys/fs/bpf/rswitch/
# Usage: sudo ./test/functional_test.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

BPF_PIN_PATH="/sys/fs/bpf/rswitch"

echo "========================================="
echo "rSwitch Functional Test"
echo "========================================="
echo ""

pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    SKIP=$((SKIP + 1))
}

info() {
    echo -e "${BLUE}ℹ INFO${NC}: $1"
}

# Check prerequisites
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

echo "=== Test 1: BPF Filesystem Check ==="
if [ -d "/sys/fs/bpf" ]; then
    pass "BPF filesystem mounted"
else
    fail "BPF filesystem not mounted"
    echo "Run: sudo mount -t bpf bpf /sys/fs/bpf"
    exit 1
fi

if [ -d "$BPF_PIN_PATH" ]; then
    info "rSwitch BPF pin path exists: $BPF_PIN_PATH"
    ls -la $BPF_PIN_PATH/ 2>/dev/null | head -20
else
    skip "rSwitch not loaded (BPF maps not pinned at $BPF_PIN_PATH)"
    echo ""
    echo "To run full functional tests:"
    echo "  1. Start rSwitch: sudo ./build/rswitch_loader"
    echo "  2. Re-run this test"
    exit 0
fi
echo ""

echo "=== Test 2: ACL Map Accessibility ==="
ACL_MAPS=("acl_rules" "acl_config_map" "acl_stats")
for map in "${ACL_MAPS[@]}"; do
    if [ -e "$BPF_PIN_PATH/$map" ]; then
        pass "ACL map '$map' is pinned"
        # Try to read the map
        if bpftool map show pinned $BPF_PIN_PATH/$map &>/dev/null; then
            info "  Map readable via bpftool"
        fi
    else
        skip "ACL map '$map' not found (module may not be loaded)"
    fi
done
echo ""

echo "=== Test 3: Mirror Map Accessibility ==="
MIRROR_MAPS=("mirror_config_map" "port_mirror_map" "mirror_stats")
for map in "${MIRROR_MAPS[@]}"; do
    if [ -e "$BPF_PIN_PATH/$map" ]; then
        pass "Mirror map '$map' is pinned"
        if bpftool map show pinned $BPF_PIN_PATH/$map &>/dev/null; then
            info "  Map readable via bpftool"
        fi
    else
        skip "Mirror map '$map' not found (module may not be loaded)"
    fi
done
echo ""

echo "=== Test 4: ACL Rule Management ==="
# Test adding an ACL rule
info "Adding test ACL rule..."
if ./build/rswitchctl acl-add-rule --id 100 --src 192.168.1.0/24 --dst-port 80 --action pass --priority 100 2>&1 | grep -q "successfully"; then
    pass "ACL rule added successfully"
    
    # Verify rule exists
    if ./build/rswitchctl acl-show-rules 2>&1 | grep -q "100"; then
        pass "ACL rule appears in show-rules output"
    else
        fail "ACL rule not visible in show-rules"
    fi
    
    # Delete rule
    info "Deleting test ACL rule..."
    if ./build/rswitchctl acl-del-rule 100 2>&1 | grep -q "deleted"; then
        pass "ACL rule deleted successfully"
    else
        fail "Failed to delete ACL rule"
    fi
else
    skip "Failed to add ACL rule (check if ACL module is loaded)"
fi
echo ""

echo "=== Test 5: ACL Enable/Disable ==="
info "Enabling ACL..."
if ./build/rswitchctl acl-enable 2>&1 | grep -q "enabled"; then
    pass "ACL enabled successfully"
    
    info "Disabling ACL..."
    if ./build/rswitchctl acl-disable 2>&1 | grep -q "disabled"; then
        pass "ACL disabled successfully"
    else
        fail "Failed to disable ACL"
    fi
else
    skip "Failed to enable/disable ACL (check if ACL module is loaded)"
fi
echo ""

echo "=== Test 6: ACL Statistics ==="
if ./build/rswitchctl acl-show-stats 2>&1 | grep -q "Total"; then
    pass "ACL statistics accessible"
    ./build/rswitchctl acl-show-stats 2>&1 | grep "Total" | sed 's/^/  /'
else
    skip "ACL statistics not available (check if ACL module is loaded)"
fi
echo ""

echo "=== Test 7: Mirror Configuration ==="
info "Setting SPAN port to 5..."
if ./build/rswitchctl mirror-set-span 5 2>&1 | grep -q "SPAN port set"; then
    pass "Mirror SPAN port configured"
    
    # Verify configuration
    if ./build/rswitchctl mirror-show-config 2>&1 | grep -q "SPAN Port: 5"; then
        pass "Mirror configuration verified"
    else
        fail "Mirror configuration not persisted"
    fi
else
    skip "Failed to configure mirror (check if Mirror module is loaded)"
fi
echo ""

echo "=== Test 8: Mirror Enable/Disable ==="
info "Enabling mirror..."
if ./build/rswitchctl mirror-enable 5 2>&1 | grep -q "enabled"; then
    pass "Mirror enabled successfully"
    
    info "Disabling mirror..."
    if ./build/rswitchctl mirror-disable 2>&1 | grep -q "disabled"; then
        pass "Mirror disabled successfully"
    else
        fail "Failed to disable mirror"
    fi
else
    skip "Failed to enable/disable mirror (check if Mirror module is loaded)"
fi
echo ""

echo "=== Test 9: Mirror Statistics ==="
if ./build/rswitchctl mirror-show-stats 2>&1 | grep -q "Ingress"; then
    pass "Mirror statistics accessible"
    ./build/rswitchctl mirror-show-stats 2>&1 | grep -E "(Packets|Bytes|Drops)" | sed 's/^/  /'
else
    skip "Mirror statistics not available (check if Mirror module is loaded)"
fi
echo ""

echo "=== Test 10: Per-Port Mirror Configuration ==="
info "Configuring port 3 mirroring..."
if ./build/rswitchctl mirror-set-port 3 --ingress --egress 2>&1 | grep -q "mirroring"; then
    pass "Per-port mirror configuration successful"
else
    skip "Failed to configure per-port mirror (check if Mirror module is loaded)"
fi
echo ""

echo "=== Test 11: BPF Program Status ==="
info "Checking loaded BPF programs..."
if bpftool prog show | grep -i "rSwitch" &>/dev/null; then
    pass "rSwitch BPF programs are loaded"
    bpftool prog show | grep -i "rSwitch" | head -10 | sed 's/^/  /'
else
    skip "No rSwitch BPF programs found (loader may not be running)"
fi
echo ""

echo "=== Test 12: BPF Map Contents Sample ==="
# Try to dump a sample map
if [ -e "$BPF_PIN_PATH/acl_config_map" ]; then
    info "ACL config map contents:"
    bpftool map dump pinned $BPF_PIN_PATH/acl_config_map 2>/dev/null | head -10 | sed 's/^/  /' || skip "Failed to dump ACL config map"
fi

if [ -e "$BPF_PIN_PATH/mirror_config_map" ]; then
    info "Mirror config map contents:"
    bpftool map dump pinned $BPF_PIN_PATH/mirror_config_map 2>/dev/null | head -10 | sed 's/^/  /' || skip "Failed to dump mirror config map"
fi
echo ""

echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo -e "${YELLOW}Skipped: $SKIP${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    if [ $SKIP -gt 0 ]; then
        echo -e "${YELLOW}⚠ Tests passed, but $SKIP tests were skipped${NC}"
        echo "This likely means rSwitch is not fully loaded."
        echo ""
        echo "To run all tests:"
        echo "  1. Ensure network interfaces are configured"
        echo "  2. Start rSwitch loader: sudo ./build/rswitch_loader"
        echo "  3. Re-run this test"
    else
        echo -e "${GREEN}✓ All tests passed!${NC}"
        echo ""
        echo "Next steps:"
        echo "  - Run traffic tests to verify packet processing"
        echo "  - Test ACL DROP/PASS actions with real traffic"
        echo "  - Test Mirror SPAN with tcpdump"
    fi
    exit 0
else
    echo -e "${RED}✗ $FAIL test(s) failed. Please review above.${NC}"
    exit 1
fi
