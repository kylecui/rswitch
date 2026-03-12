#!/bin/bash
# rSwitch Init Script for systemd service
#
# Handles NIC configuration, veth setup, and loader startup

set -e

RSWITCH_HOME="${RSWITCH_HOME:-/opt/rswitch}"
RSWITCH_PROFILE="${RSWITCH_PROFILE:-all-modules-test.yaml}"
RSWITCH_INTERFACES="${RSWITCH_INTERFACES:-ens34,ens35,ens36,ens37}"
LOG_DIR="/var/log/rswitch"
LOG_FILE="${LOG_DIR}/rswitch.log"
RUN_DIR="/run/rswitch"
PID_FILE="${RUN_DIR}/rswitch_loader.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root"
        exit 1
    fi
}

setup_directories() {
    mkdir -p "$LOG_DIR"
    mkdir -p "$RUN_DIR"
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
}

setup_nic() {
    local iface="$1"
    local cpu_id="$2"
    
    log "Configuring NIC: $iface (CPU $cpu_id)"
    
    if ! ip link show "$iface" &>/dev/null; then
        warn "Interface $iface does not exist, skipping"
        return 0
    fi
    
    # Force bring interface UP first
    ip link set "$iface" up 2>/dev/null || warn "Could not bring up $iface"
    
    # Set promiscuous mode
    ip link set "$iface" promisc on 2>/dev/null || warn "Could not set promisc on $iface"
    
    # Disable hardware offloads that interfere with XDP
    ethtool -K "$iface" rxvlan off txvlan off 2>/dev/null || warn "Could not disable VLAN offload on $iface"
    ethtool -K "$iface" gro off gso off tso off 2>/dev/null || warn "Could not disable offloads on $iface"
    ethtool -K "$iface" lro off 2>/dev/null || true  # LRO might not exist on all NICs
    ethtool -K "$iface" rx-vlan-filter off 2>/dev/null || true  # Disable VLAN filtering
    
    # Setup NIC queues for better XDP performance
    if [ -f "${RSWITCH_HOME}/scripts/setup_nic_queues.sh" ]; then
        "${RSWITCH_HOME}/scripts/setup_nic_queues.sh" "$iface" "$cpu_id" >> "$LOG_FILE" 2>&1 || warn "Queue setup failed for $iface"
    fi
    
    log "  NIC $iface configured (UP, promisc, offloads disabled)"
}

setup_veth() {
    log "Setting up veth pair for VOQd..."
    
    if [ -f "${RSWITCH_HOME}/scripts/setup_veth_egress.sh" ]; then
        VETH_IN="veth_voq_in" VETH_OUT="veth_voq_out" "${RSWITCH_HOME}/scripts/setup_veth_egress.sh" create >> "$LOG_FILE" 2>&1 || warn "Veth setup failed"
    else
        ip link add veth_voq_in type veth peer name veth_voq_out 2>/dev/null || true
        ip link set veth_voq_in up 2>/dev/null || true
        ip link set veth_voq_out up 2>/dev/null || true
    fi
    
    log "  Veth pair ready"
}

cleanup_veth() {
    log "Cleaning up veth pair..."
    
    if [ -f "${RSWITCH_HOME}/scripts/setup_veth_egress.sh" ]; then
        VETH_IN="veth_voq_in" VETH_OUT="veth_voq_out" "${RSWITCH_HOME}/scripts/setup_veth_egress.sh" destroy >> "$LOG_FILE" 2>&1 || true
    else
        ip link delete veth_voq_in 2>/dev/null || true
    fi
}

do_prepare() {
    check_root
    setup_directories

    if [ -x "${RSWITCH_HOME}/scripts/rswitch-failsafe.sh" ]; then
        "${RSWITCH_HOME}/scripts/rswitch-failsafe.sh" teardown 2>/dev/null || true
    fi
    
    log "=========================================="
    log "rSwitch Preparation"
    log "=========================================="
    
    IFS=',' read -ra IFACES <<< "$RSWITCH_INTERFACES"
    local cpu_id=1
    
    for iface in "${IFACES[@]}"; do
        setup_nic "$iface" "$cpu_id"
        cpu_id=$((cpu_id + 1))
        if [ $cpu_id -ge $(nproc) ]; then
            cpu_id=1
        fi
    done
    
    setup_veth
    
    log "Preparation complete"
}

do_start() {
    check_root
    setup_directories
    
    log "=========================================="
    log "rSwitch Starting"
    log "=========================================="
    
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        warn "rSwitch loader already running (PID: $(cat "$PID_FILE"))"
        return 0
    fi
    
    local profile_path="${RSWITCH_HOME}/etc/profiles/${RSWITCH_PROFILE}"
    if [ ! -f "$profile_path" ]; then
        error "Profile not found: $profile_path"
        exit 1
    fi
    
    log "Starting rswitch_loader..."
    log "  Profile: $RSWITCH_PROFILE"
    log "  Interfaces: $RSWITCH_INTERFACES"
    
    "${RSWITCH_HOME}/build/rswitch_loader" \
        --profile "$profile_path" \
        --ifaces "$RSWITCH_INTERFACES" \
        >> "$LOG_FILE" 2>&1 &
    
    local loader_pid=$!
    echo "$loader_pid" > "$PID_FILE"
    
    sleep 3
    
    if ! kill -0 "$loader_pid" 2>/dev/null; then
        error "rswitch_loader failed to start"
        rm -f "$PID_FILE"
        exit 1
    fi
    
    log "rswitch_loader started (PID: $loader_pid)"
    
    local voqd_timeout=10
    for i in $(seq 1 $voqd_timeout); do
        if pgrep -x "rswitch-voqd" > /dev/null; then
            log "VOQd started (PID: $(pgrep -x rswitch-voqd))"
            break
        fi
        sleep 1
    done
    
    log "=========================================="
    log "rSwitch Started Successfully"
    log "=========================================="
}

do_stop() {
    check_root
    
    log "=========================================="
    log "rSwitch Stopping"
    log "=========================================="
    
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping rswitch_loader (PID: $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
    
    pkill -x "rswitch-voqd" 2>/dev/null || true
    pkill -x "rswitch_loader" 2>/dev/null || true
    
    if [ -f "${RSWITCH_HOME}/scripts/unload.sh" ]; then
        log "Unloading BPF programs..."
        "${RSWITCH_HOME}/scripts/unload.sh" >> "$LOG_FILE" 2>&1 || true
    fi
    
    cleanup_veth
    
    log "rSwitch stopped"
}

do_reload() {
    check_root
    log "Reloading rSwitch..."
    
    if [ -f "${RSWITCH_HOME}/scripts/hot-reload.sh" ]; then
        "${RSWITCH_HOME}/scripts/hot-reload.sh" >> "$LOG_FILE" 2>&1 || error "Hot reload failed"
    else
        warn "Hot reload not available, doing full restart"
        do_stop
        do_start
    fi
}

do_status() {
    echo "=== rSwitch Status ==="
    echo ""
    
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "rswitch_loader: RUNNING (PID: $(cat "$PID_FILE"))"
    else
        echo "rswitch_loader: STOPPED"
    fi
    
    if pgrep -x "rswitch-voqd" > /dev/null; then
        echo "rswitch-voqd: RUNNING (PID: $(pgrep -x rswitch-voqd))"
    else
        echo "rswitch-voqd: STOPPED"
    fi
    
    echo ""
    echo "=== BPF Maps ==="
    ls -la /sys/fs/bpf/ 2>/dev/null | head -20 || echo "  (none)"
    
    echo ""
    echo "=== Interfaces ==="
    IFS=',' read -ra IFACES <<< "$RSWITCH_INTERFACES"
    for iface in "${IFACES[@]}"; do
        if ip link show "$iface" &>/dev/null; then
            local xdp_status
            if ip link show "$iface" | grep -q "xdp"; then
                xdp_status="XDP attached"
            else
                xdp_status="no XDP"
            fi
            echo "  $iface: UP ($xdp_status)"
        else
            echo "  $iface: NOT FOUND"
        fi
    done
    
    echo ""
    echo "=== Veth Pair ==="
    if ip link show veth_voq_in &>/dev/null; then
        echo "  veth_voq_in: UP"
        echo "  veth_voq_out: UP"
    else
        echo "  (not configured)"
    fi
}

case "${1:-}" in
    prepare)
        do_prepare
        ;;
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    reload)
        do_reload
        ;;
    status)
        do_status
        ;;
    restart)
        do_stop
        sleep 2
        do_prepare
        do_start
        ;;
    *)
        echo "Usage: $0 {prepare|start|stop|reload|restart|status}"
        exit 1
        ;;
esac
