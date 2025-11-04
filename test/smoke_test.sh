#!/bin/bash
# rSwitch Smoke Test - Quick validation of ACL, Mirror, VLAN modules
# Usage: sudo ./test/smoke_test.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

echo "========================================="
echo "rSwitch Module Smoke Test"
echo "========================================="
echo ""

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

echo "=== Test 1: Module File Existence ==="
for mod in acl mirror vlan egress_vlan; do
    if [ -f "build/bpf/$mod.bpf.o" ]; then
        pass "Module $mod.bpf.o exists"
    else
        fail "Module $mod.bpf.o not found"
    fi
done
echo ""

echo "=== Test 2: Module Loading (Dry Run) ==="
# Try to load modules using bpftool (just verify ELF format)
for mod in acl mirror vlan egress_vlan; do
    if bpftool prog show 2>/dev/null | grep -q "rSwitch"; then
        warn "Some rSwitch programs already loaded, skipping load test for $mod"
    else
        # Check if module has valid BTF/CO-RE info
        if llvm-objdump -h build/bpf/$mod.bpf.o 2>/dev/null | grep -q ".BTF"; then
            pass "Module $mod has BTF info"
        else
            fail "Module $mod missing BTF info"
        fi
    fi
done
echo ""

echo "=== Test 3: rswitchctl Binary ==="
if [ -x "build/rswitchctl" ]; then
    pass "rswitchctl is executable"
else
    fail "rswitchctl not found or not executable"
fi

# Check if it shows help without crashing
if ./build/rswitchctl 2>&1 | grep -q "ACL Commands"; then
    pass "rswitchctl shows ACL commands in help"
else
    fail "rswitchctl missing ACL commands"
fi

if ./build/rswitchctl 2>&1 | grep -q "Mirror Commands"; then
    pass "rswitchctl shows Mirror commands in help"
else
    fail "rswitchctl missing Mirror commands"
fi
echo ""

echo "=== Test 4: BPF Map Definitions ==="
# Check if ACL module defines expected maps
if llvm-objdump -h build/bpf/acl.bpf.o 2>/dev/null | grep -q "maps"; then
    pass "ACL module has maps section"
else
    warn "ACL module maps section not found (may use BTF map definitions)"
fi

if llvm-objdump -h build/bpf/mirror.bpf.o 2>/dev/null | grep -q "maps"; then
    pass "Mirror module has maps section"
else
    warn "Mirror module maps section not found (may use BTF map definitions)"
fi
echo ""

echo "=== Test 5: Module Metadata (.rodata.mod) ==="
for mod in acl mirror vlan egress_vlan; do
    if llvm-objdump -h build/bpf/$mod.bpf.o 2>/dev/null | grep -q ".rodata.mod"; then
        pass "Module $mod has .rodata.mod metadata"
    else
        fail "Module $mod missing .rodata.mod metadata"
    fi
done
echo ""

echo "=== Test 6: XDP Program Sections ==="
# Check ACL has xdp section
if llvm-objdump -h build/bpf/acl.bpf.o 2>/dev/null | grep -q "xdp"; then
    pass "ACL module has xdp section"
else
    fail "ACL module missing xdp section"
fi

# Check egress_vlan has xdp_devmap section
if llvm-objdump -h build/bpf/egress_vlan.bpf.o 2>/dev/null | grep -q "xdp_devmap"; then
    pass "Egress VLAN module has xdp_devmap section"
else
    warn "Egress VLAN module missing xdp_devmap section (check SEC() macro)"
fi
echo ""

echo "=== Test 7: rswitchctl Map Access (Expected to Fail - Maps Not Pinned) ==="
# These should fail gracefully since maps aren't pinned yet
./build/rswitchctl acl-show-rules 2>&1 | grep -q "Failed to open" && pass "ACL commands fail gracefully when maps not available" || warn "ACL command behavior unexpected"

./build/rswitchctl mirror-show-config 2>&1 | grep -q "Failed to open" && pass "Mirror commands fail gracefully when maps not available" || warn "Mirror command behavior unexpected"
echo ""

echo "=== Test 8: Module Size Sanity Check ==="
ACL_SIZE=$(stat -c%s build/bpf/acl.bpf.o)
MIRROR_SIZE=$(stat -c%s build/bpf/mirror.bpf.o)
VLAN_SIZE=$(stat -c%s build/bpf/vlan.bpf.o)
EGRESS_VLAN_SIZE=$(stat -c%s build/bpf/egress_vlan.bpf.o)

echo "  ACL module: $(($ACL_SIZE / 1024))KB"
echo "  Mirror module: $(($MIRROR_SIZE / 1024))KB"
echo "  VLAN module: $(($VLAN_SIZE / 1024))KB"
echo "  Egress VLAN module: $(($EGRESS_VLAN_SIZE / 1024))KB"

if [ $ACL_SIZE -gt 10240 -a $ACL_SIZE -lt 102400 ]; then
    pass "ACL module size reasonable (10-100KB)"
else
    warn "ACL module size unusual: $(($ACL_SIZE / 1024))KB"
fi

if [ $MIRROR_SIZE -gt 10240 -a $MIRROR_SIZE -lt 102400 ]; then
    pass "Mirror module size reasonable (10-100KB)"
else
    warn "Mirror module size unusual: $(($MIRROR_SIZE / 1024))KB"
fi
echo ""

echo "=== Test 9: Inspect Module Metadata ==="
# Use inspect_module.py to verify modules
for mod in acl mirror vlan egress_vlan; do
    if python3 tools/inspect_module.py build/bpf/$mod.bpf.o 2>&1 | grep -q "Portable across kernel"; then
        pass "Module $mod is CO-RE portable"
    else
        fail "Module $mod not CO-RE portable"
    fi
done
echo ""

echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All critical tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Load modules into kernel (requires network interfaces)"
    echo "  2. Run functional tests with traffic"
    echo "  3. Verify ACL rule matching"
    echo "  4. Verify Mirror SPAN functionality"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Please review above.${NC}"
    exit 1
fi
