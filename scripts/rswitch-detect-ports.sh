#!/bin/bash
# rswitch-detect-ports.sh — Auto-detect physical switch ports
#
# Discovers physical PCI Ethernet interfaces, identifies the management
# NIC (default route), and outputs the remaining ports as switch candidates.
#
# Output (stdout, one per line):
#   MGMT_NIC=<iface>
#   SWITCH_PORTS=<comma-separated list>
#   PORT_COUNT=<number>
#
# Exit codes:
#   0 — success (at least 1 switch port found)
#   1 — no switch ports found
#   2 — error

set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 2; }

# ── Management NIC detection ─────────────────────────────────────
# The management NIC is the one carrying the default route.  This is
# the interface SSH traffic arrives on — must NEVER be used as a
# switch port.

detect_mgmt_nic() {
    local mgmt=""

    # Method 1: ip route get (most reliable)
    mgmt=$(ip route get 1.1.1.1 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

    # Method 2: default route
    if [ -z "$mgmt" ]; then
        mgmt=$(ip route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    fi

    # Method 3: last resort — eth0
    if [ -z "$mgmt" ]; then
        if [ -e /sys/class/net/eth0 ]; then
            mgmt="eth0"
        fi
    fi

    echo "$mgmt"
}

# ── Physical port discovery ──────────────────────────────────────
# A "physical" NIC is one with a PCI device backing it:
#   /sys/class/net/<iface>/device → symlink exists only for PCI NICs
#
# We exclude:
#   - Management NIC (default route)
#   - Loopback
#   - Wireless interfaces (/sys/class/net/<iface>/wireless exists)
#   - Virtual interfaces (veth, bridge, bond, tun/tap, docker, vir)

detect_switch_ports() {
    local mgmt_nic="$1"
    local ports=()

    for net_dir in /sys/class/net/*/; do
        local iface
        iface=$(basename "$net_dir")

        # Skip loopback
        [ "$iface" = "lo" ] && continue

        # Skip management NIC
        [ "$iface" = "$mgmt_nic" ] && continue

        # Must have a PCI device backing (physical NIC)
        [ -e "${net_dir}device" ] || continue

        # Skip wireless
        [ -e "${net_dir}wireless" ] && continue

        # Skip known virtual prefixes
        case "$iface" in
            veth*|docker*|vir*|br-*|bond*|tun*|tap*|wg*) continue ;;
        esac

        # Skip if type is not Ethernet (type 1)
        local iftype
        iftype=$(cat "${net_dir}type" 2>/dev/null || echo "0")
        [ "$iftype" = "1" ] || continue

        ports+=("$iface")
    done

    # Sort for deterministic output
    IFS=$'\n' sorted=($(sort <<<"${ports[*]}")); unset IFS

    local csv=""
    for p in "${sorted[@]}"; do
        [ -n "$csv" ] && csv="${csv},"
        csv="${csv}${p}"
    done

    echo "$csv"
}

# ── Main ─────────────────────────────────────────────────────────

main() {
    # Allow override via environment
    local mgmt_nic="${RSWITCH_MGMT_NIC:-}"
    if [ -z "$mgmt_nic" ]; then
        mgmt_nic=$(detect_mgmt_nic)
    fi

    if [ -z "$mgmt_nic" ]; then
        die "Cannot detect management NIC. Set RSWITCH_MGMT_NIC=<iface>"
    fi

    # Allow override via environment
    local switch_ports="${RSWITCH_INTERFACES:-}"
    if [ -z "$switch_ports" ]; then
        switch_ports=$(detect_switch_ports "$mgmt_nic")
    fi

    if [ -z "$switch_ports" ]; then
        echo "MGMT_NIC=${mgmt_nic}"
        echo "SWITCH_PORTS="
        echo "PORT_COUNT=0"
        echo "" >&2
        echo "WARNING: No physical switch ports found (mgmt=$mgmt_nic)." >&2
        echo "Set RSWITCH_INTERFACES=eth1,eth2,... to specify manually." >&2
        exit 1
    fi

    local count
    count=$(echo "$switch_ports" | tr ',' '\n' | wc -l)

    echo "MGMT_NIC=${mgmt_nic}"
    echo "SWITCH_PORTS=${switch_ports}"
    echo "PORT_COUNT=${count}"
}

main "$@"
