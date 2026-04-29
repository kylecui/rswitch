#!/bin/bash

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

require_root
require_build

validated=0

echo "========================================="
echo "Profile Validation Tests"
echo "========================================="
echo ""

extract_modules() {
    local section="$1"
    local file="$2"
    awk -v sec="$section" '
        /^[^[:space:]].*:/ {
            if ($0 ~ "^" sec ":[[:space:]]*$") { insec=1; next }
            if (insec) { insec=0 }
        }
        insec && /^[[:space:]]*-[[:space:]]*/ {
            line=$0
            sub(/^[[:space:]]*-[[:space:]]*/, "", line)
            sub(/[[:space:]]*#.*/, "", line)
            gsub(/[[:space:]]+$/, "", line)
            if (length(line) > 0) print line
        }
    ' "$file"
}

for profile in "$PROFILE_DIR"/*.yaml; do
    [ -f "$profile" ] || continue
    name="$(basename "$profile")"
    info "Validating $name"

    if grep -Eq '^[[:space:]]*name:[[:space:]]*[^[:space:]]+' "$profile"; then
        pass "$name has name field"
    else
        fail "$name missing name field"
    fi

    has_ingress=0
    has_egress=0
    grep -Eq '^[[:space:]]*ingress:[[:space:]]*$' "$profile" && has_ingress=1
    grep -Eq '^[[:space:]]*egress:[[:space:]]*$' "$profile" && has_egress=1
    if [ "$has_ingress" -eq 1 ] || [ "$has_egress" -eq 1 ]; then
        pass "$name has ingress and/or egress"
    else
        fail "$name missing ingress/egress sections"
    fi

    while IFS= read -r module; do
        if [ -f "$BPF_DIR/$module.bpf.o" ]; then
            pass "$name module exists: $module"
        else
            fail "$name module missing object: $module"
        fi
    done < <( { extract_modules ingress "$profile"; extract_modules egress "$profile"; } | sort -u )

    if grep -Eq '^[[:space:]]*ports:[[:space:]]*$' "$profile"; then
        interfaces=$(grep -E '^[[:space:]]*-[[:space:]]*interface:[[:space:]]*[^[:space:]]+' "$profile" | wc -l)
        bad_interfaces=$(grep -E '^[[:space:]]*-[[:space:]]*interface:[[:space:]]*$' "$profile" | wc -l)
        if [ "$interfaces" -gt 0 ] && [ "$bad_interfaces" -eq 0 ]; then
            pass "$name ports interface format valid"
        else
            fail "$name ports interface format invalid"
        fi
    elif grep -Eq '^port_defaults:' "$profile"; then
        if grep -Eq '^[[:space:]]*vlan_mode:[[:space:]]*(off|access|trunk|hybrid)' "$profile"; then
            pass "$name port_defaults vlan_mode valid"
        else
            pass "$name port_defaults present (no explicit vlan_mode, defaults to off)"
        fi
    else
        skip "$name has no ports or port_defaults section"
    fi

    validated=$((validated + 1))
done

echo ""
info "Profiles validated: $validated"
print_summary "Profile Validation Tests"
exit $?
