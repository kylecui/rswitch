#!/bin/bash
# rSwitch Uninstaller
#
# Usage: sudo bash uninstall.sh [--yes]
#
# Stops all services, removes XDP programs, cleans up namespaces,
# removes installed files and systemd units.

set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/rswitch}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[rSwitch]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARNING]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

if [ "$EUID" -ne 0 ]; then
    error "Must be run as root (use sudo)"
    exit 1
fi

if [ "${1:-}" != "--yes" ]; then
    echo ""
    echo -e "${RED}This will completely remove rSwitch from this system.${NC}"
    echo -e "  Install prefix: ${INSTALL_PREFIX}"
    echo ""
    read -rp "Are you sure? [y/N] " ans
    case "$ans" in
        [Yy]*) ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

info "Stopping services..."
systemctl stop rswitch-mgmtd 2>/dev/null || true
systemctl stop rswitch-watchdog 2>/dev/null || true
systemctl stop rswitch 2>/dev/null || true
systemctl stop rswitch-failsafe 2>/dev/null || true

info "Disabling services..."
systemctl disable rswitch rswitch-mgmtd rswitch-failsafe rswitch-watchdog 2>/dev/null || true

info "Removing XDP programs from all interfaces..."
for iface in /sys/class/net/*/; do
    name=$(basename "$iface")
    if ip link show "$name" 2>/dev/null | grep -q 'xdp'; then
        ip link set dev "$name" xdp off 2>/dev/null || true
        info "  Detached XDP from $name"
    fi
done

info "Cleaning up management namespace..."
if ip netns list 2>/dev/null | grep -qw rswitch-mgmt; then
    ip netns del rswitch-mgmt 2>/dev/null || true
    info "  Deleted namespace rswitch-mgmt"
fi

info "Removing veth pairs..."
ip link del veth_voq_in 2>/dev/null || true
ip link del mgmt-br 2>/dev/null || true

info "Removing BPF pinned maps..."
rm -rf /sys/fs/bpf/rs_* 2>/dev/null || true
rm -rf /sys/fs/bpf/rswitch_* 2>/dev/null || true

info "Removing systemd units..."
rm -f /etc/systemd/system/rswitch.service
rm -f /etc/systemd/system/rswitch-mgmtd.service
rm -f /etc/systemd/system/rswitch-failsafe.service
rm -f /etc/systemd/system/rswitch-watchdog.service
systemctl daemon-reload 2>/dev/null || true

info "Removing CLI symlinks..."
for tool in rswitchctl rsportctl rsvlanctl rsaclctl rsroutectl rsqosctl \
            rsflowctl rsnatctl rsvoqctl rstunnelctl rswitch-events \
            rs_packet_trace rswitch-telemetry rswitch-sflow; do
    rm -f "/usr/local/bin/${tool}"
done

info "Removing installation directory: ${INSTALL_PREFIX}"
rm -rf "$INSTALL_PREFIX"

info "Removing runtime files..."
rm -rf /run/rswitch 2>/dev/null || true

echo ""
info "rSwitch has been completely removed."
info "Log files remain at /var/log/rswitch/ (remove manually if desired)."
