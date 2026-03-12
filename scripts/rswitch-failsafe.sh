#!/bin/bash
# rswitch-failsafe.sh {setup|teardown|status}
# L2 bridge fallback when rSwitch fails after systemd retry exhaustion.
# Bridges switch ports with DHCP for basic management connectivity.

set -euo pipefail

FAILSAFE_BRIDGE="${FAILSAFE_BRIDGE:-rswitch-br}"
FAILSAFE_INTERFACES="${FAILSAFE_INTERFACES:-ens34,ens35,ens36,ens37}"
FAILSAFE_LOG="${FAILSAFE_LOG:-/var/log/rswitch/failsafe.log}"
# Pin bridge MAC to ens34 for consistent DHCP lease across reboots
MAC_SOURCE_IFACE="${MAC_SOURCE_IFACE:-ens34}"

log() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] FAILSAFE: $*" | tee -a "$FAILSAFE_LOG" 2>/dev/null || echo "[$ts] FAILSAFE: $*"
}

ensure_dirs() {
    mkdir -p /var/log/rswitch /run/rswitch 2>/dev/null || true
}

remove_xdp() {
    local iface="$1"
    if ip link show "$iface" 2>/dev/null | grep -q 'xdp'; then
        log "Removing XDP program from $iface"
        ip link set dev "$iface" xdp off 2>/dev/null || true
    fi
}

stop_dhcpcd() {
    if pgrep -f "dhcpcd.*${FAILSAFE_BRIDGE}" >/dev/null 2>&1; then
        dhcpcd -k "$FAILSAFE_BRIDGE" 2>/dev/null || true
        dhcpcd -x "$FAILSAFE_BRIDGE" 2>/dev/null || true
    fi
}

do_setup() {
    ensure_dirs
    log "=========================================="
    log "Fail-safe bridge setup starting"
    log "=========================================="

    IFS=',' read -ra IFACES <<< "$FAILSAFE_INTERFACES"

    if [ ${#IFACES[@]} -eq 0 ]; then
        log "ERROR: No interfaces configured"
        exit 1
    fi

    do_teardown_quiet

    local pinned_mac
    pinned_mac=$(ip link show "$MAC_SOURCE_IFACE" 2>/dev/null | awk '/link\/ether/ {print $2}')
    if [ -z "$pinned_mac" ]; then
        log "WARNING: Cannot read MAC from $MAC_SOURCE_IFACE, bridge will use kernel default"
    else
        log "Pinning bridge MAC to $MAC_SOURCE_IFACE: $pinned_mac"
    fi

    for iface in "${IFACES[@]}"; do
        remove_xdp "$iface"
    done

    log "Creating bridge $FAILSAFE_BRIDGE"
    ip link add name "$FAILSAFE_BRIDGE" type bridge
    ip link set dev "$FAILSAFE_BRIDGE" type bridge stp_state 0
    log "STP disabled on $FAILSAFE_BRIDGE"

    if [ -n "${pinned_mac:-}" ]; then
        ip link set dev "$FAILSAFE_BRIDGE" address "$pinned_mac"
    fi

    for iface in "${IFACES[@]}"; do
        if ip link show "$iface" >/dev/null 2>&1; then
            ip link set dev "$iface" up
            ip link set dev "$iface" master "$FAILSAFE_BRIDGE"
            log "Enslaved $iface to $FAILSAFE_BRIDGE"
        else
            log "WARNING: Interface $iface does not exist, skipping"
        fi
    done

    ip link set dev "$FAILSAFE_BRIDGE" up
    log "Bridge $FAILSAFE_BRIDGE is UP"

    log "Starting DHCP client on $FAILSAFE_BRIDGE"
    if command -v dhcpcd >/dev/null 2>&1; then
        dhcpcd -b -4 -L "$FAILSAFE_BRIDGE" >> "$FAILSAFE_LOG" 2>&1 || true
        log "dhcpcd started on $FAILSAFE_BRIDGE"
    else
        log "ERROR: dhcpcd not found, no DHCP client available"
        log "Bridge is up but has no IP address"
    fi

    log "Fail-safe bridge setup complete"
    log "=========================================="
}

# Silent version used internally for idempotent re-setup
do_teardown_quiet() {
    stop_dhcpcd

    if ! ip link show "$FAILSAFE_BRIDGE" >/dev/null 2>&1; then
        return 0
    fi

    IFS=',' read -ra IFACES <<< "$FAILSAFE_INTERFACES"
    for iface in "${IFACES[@]}"; do
        if ip link show "$iface" 2>/dev/null | grep -q "master $FAILSAFE_BRIDGE"; then
            ip link set dev "$iface" nomaster 2>/dev/null || true
        fi
    done

    ip link set dev "$FAILSAFE_BRIDGE" down 2>/dev/null || true
    ip link delete "$FAILSAFE_BRIDGE" 2>/dev/null || true
}

do_teardown() {
    ensure_dirs
    log "=========================================="
    log "Fail-safe bridge teardown starting"
    log "=========================================="

    if pgrep -f "dhcpcd.*${FAILSAFE_BRIDGE}" >/dev/null 2>&1; then
        log "Releasing DHCP lease on $FAILSAFE_BRIDGE"
        dhcpcd -k "$FAILSAFE_BRIDGE" 2>/dev/null || true
        dhcpcd -x "$FAILSAFE_BRIDGE" 2>/dev/null || true
    fi

    if ! ip link show "$FAILSAFE_BRIDGE" >/dev/null 2>&1; then
        log "Bridge $FAILSAFE_BRIDGE does not exist, nothing to tear down"
        log "=========================================="
        return 0
    fi

    IFS=',' read -ra IFACES <<< "$FAILSAFE_INTERFACES"
    for iface in "${IFACES[@]}"; do
        if ip link show "$iface" 2>/dev/null | grep -q "master $FAILSAFE_BRIDGE"; then
            ip link set dev "$iface" nomaster
            log "Removed $iface from $FAILSAFE_BRIDGE"
        fi
    done

    ip link set dev "$FAILSAFE_BRIDGE" down
    ip link delete "$FAILSAFE_BRIDGE"
    log "Deleted bridge $FAILSAFE_BRIDGE"

    log "Fail-safe bridge teardown complete"
    log "=========================================="
}

do_status() {
    echo "=== rSwitch Fail-safe Bridge Status ==="

    if ! ip link show "$FAILSAFE_BRIDGE" >/dev/null 2>&1; then
        echo "Bridge $FAILSAFE_BRIDGE: NOT PRESENT"
        echo "Fail-safe is INACTIVE"
        return 1
    fi

    echo "Bridge $FAILSAFE_BRIDGE: ACTIVE"
    echo ""

    echo "--- Bridge Link ---"
    ip link show "$FAILSAFE_BRIDGE"
    echo ""

    echo "--- IP Addresses ---"
    ip addr show "$FAILSAFE_BRIDGE" | grep -E '^\s+inet' || echo "  (no IP assigned)"
    echo ""

    echo "--- Enslaved Interfaces ---"
    bridge link show | grep "$FAILSAFE_BRIDGE" || echo "  (none)"
    echo ""

    echo "--- STP State ---"
    local stp_state
    stp_state=$(cat "/sys/class/net/$FAILSAFE_BRIDGE/bridge/stp_state" 2>/dev/null || echo "unknown")
    if [ "$stp_state" = "0" ]; then
        echo "  STP: disabled"
    elif [ "$stp_state" = "1" ]; then
        echo "  STP: enabled"
    else
        echo "  STP: $stp_state"
    fi
    echo ""

    echo "--- DHCP Client ---"
    if pgrep -f "dhcpcd.*${FAILSAFE_BRIDGE}" >/dev/null 2>&1; then
        echo "  dhcpcd: running"
    else
        echo "  dhcpcd: not running"
    fi

    echo "=== End Status ==="
    return 0
}

case "${1:-}" in
    setup)
        do_setup
        ;;
    teardown)
        do_teardown
        ;;
    status)
        do_status
        ;;
    *)
        echo "Usage: $0 {setup|teardown|status}" >&2
        exit 1
        ;;
esac
