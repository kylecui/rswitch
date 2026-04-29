#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RSWITCH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib.sh"

PROFILE_DIR="$RSWITCH_DIR/etc/profiles"
INSTALL_SCRIPT="$RSWITCH_DIR/scripts/install.sh"

echo "========================================="
echo "Installer Profile Chooser Tests"
echo "========================================="
echo ""

echo "=== Test 1: All profile YAMLs referenced by installer exist ==="
for p in dumb l2-unmanaged l2-simple-managed l3-full all; do
    if [ -f "$PROFILE_DIR/${p}.yaml" ]; then
        pass "profile exists: ${p}.yaml"
    else
        fail "profile missing: ${p}.yaml"
    fi
done
echo ""

echo "=== Test 2: Installer script contains profile chooser ==="
if grep -q 'RSWITCH_PROFILE' "$INSTALL_SCRIPT"; then
    pass "installer supports RSWITCH_PROFILE env var"
else
    fail "installer missing RSWITCH_PROFILE support"
fi

if grep -q 'l2-simple-managed' "$INSTALL_SCRIPT"; then
    pass "installer has l2-simple-managed as default"
else
    fail "installer missing l2-simple-managed default"
fi
echo ""

echo "=== Test 3: Profile chooser case mapping ==="
expected_mappings=("1:dumb" "2:l2-unmanaged" "3:l2-simple-managed" "4:l3-full" "5:all")
for mapping in "${expected_mappings[@]}"; do
    num="${mapping%%:*}"
    name="${mapping##*:}"
    if grep -q "${num}) profile=\"${name}\"" "$INSTALL_SCRIPT"; then
        pass "case $num maps to $name"
    else
        fail "case $num does not map to $name"
    fi
done
echo ""

echo "=== Test 4: Default fallback ==="
if grep -q '\*) profile="l2-simple-managed"' "$INSTALL_SCRIPT"; then
    pass "invalid input defaults to l2-simple-managed"
else
    fail "invalid input fallback not set to l2-simple-managed"
fi
echo ""

echo "=== Test 5: Each profile YAML has required fields ==="
for p in dumb l2-unmanaged l2-simple-managed l3-full all; do
    f="$PROFILE_DIR/${p}.yaml"
    [ -f "$f" ] || continue
    if grep -Eq '^name:' "$f" && grep -Eq '^ingress:' "$f"; then
        pass "${p}.yaml has name and ingress"
    else
        fail "${p}.yaml missing name or ingress"
    fi
done
echo ""

print_summary "Installer Profile Chooser Tests"
exit $?
