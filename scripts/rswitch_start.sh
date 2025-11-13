#!/bin/bash
# rSwitch Startup Script for jzzn Lab
# 
# This script properly starts rSwitch with:
# - NIC queue isolation setup
# - QoS priority configuration
# - VOQd integration
# - Proper error handling

set -e  # Exit on error

# Configuration
RSWITCH_DIR="/home/jzzn/dev/rswitch"
PROFILE="etc/profiles/l3-qos-voqd-test.yaml"
INTERFACES="enp3s0,enp4s0,enp5s0"
LOG_DIR="/var/log/rswitch"
LOG_FILE="${LOG_DIR}/rswitch_loader.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

# Create log directory
mkdir -p "$LOG_DIR"

log "=========================================="
log "rSwitch Startup Script"
log "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
    exit 1
fi

# Change to rSwitch directory
cd "$RSWITCH_DIR" || {
    error "Failed to change to rSwitch directory: $RSWITCH_DIR"
    exit 1
}

log "Working directory: $(pwd)"

# Step 1: Setup promiscuous mode
log "[1/5] Setting up promiscuous mode..."
if [ -f "/home/jzzn/dev/promisc_switch.sh" ]; then
    /home/jzzn/dev/promisc_switch.sh >> "$LOG_FILE" 2>&1
    log "  ✓ Promiscuous mode configured"
else
    warn "  promisc_switch.sh not found, skipping"
fi

# Step 2: Setup NIC queue isolation (with proper CPU affinity)
log "[2/5] Setting up NIC queue isolation..."

# Detect number of CPUs
NUM_CPUS=$(nproc)
log "  Detected $NUM_CPUS CPUs"

# Setup queues for each interface with safe CPU affinity
INTERFACES_ARRAY=(${INTERFACES//,/ })
for i in "${!INTERFACES_ARRAY[@]}"; do
    IFACE="${INTERFACES_ARRAY[$i]}"
    # Calculate safe CPU affinity (avoid CPU 0, use modulo to wrap around)
    CPU_ID=$(( (i + 1) % NUM_CPUS ))
    
    log "  Setting up $IFACE (CPU $CPU_ID)..."
    
    if [ -f "scripts/setup_nic_queues.sh" ]; then
        # Run setup script with error handling
        if ./scripts/setup_nic_queues.sh "$IFACE" "$CPU_ID" >> "$LOG_FILE" 2>&1; then
            log "    ✓ Queue isolation configured for $IFACE"
        else
            warn "    Failed to setup queue isolation for $IFACE (non-critical)"
        fi
    else
        warn "  setup_nic_queues.sh not found, skipping queue isolation"
        break
    fi
done

# Step 3: Start rSwitch loader
log "[3/5] Starting rSwitch loader..."

# Kill any existing loader
if pgrep -x "rswitch_loader" > /dev/null; then
    warn "  Existing rswitch_loader found, stopping..."
    killall -TERM rswitch_loader 2>/dev/null || true
    sleep 2
    killall -KILL rswitch_loader 2>/dev/null || true
    sleep 1
fi

# Start loader in background
log "  Command: ./build/rswitch_loader --profile $PROFILE --ifaces $INTERFACES"
./build/rswitch_loader --profile "$PROFILE" --ifaces "$INTERFACES" >> "$LOG_FILE" 2>&1 &
LOADER_PID=$!

log "  rswitch_loader started (PID: $LOADER_PID)"

# Wait for loader to initialize (give it 3 seconds)
log "  Waiting for loader initialization..."
sleep 3

# Check if loader is still running
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    error "  rswitch_loader died during startup!"
    error "  Check logs: tail -f $LOG_FILE"
    exit 1
fi

log "  ✓ rswitch_loader running (PID: $LOADER_PID)"

# Step 4: Configure QoS priorities (optional, for DHCP fix)
log "[4/5] Configuring QoS priorities..."

# Wait a bit more for maps to be fully loaded
sleep 2

# Check if QoS maps are available
if ./build/rsqosctl stats >> "$LOG_FILE" 2>&1; then
    log "  QoS maps available"
    
    # Uncomment these lines if you want DHCP to work (not be intercepted by VOQd)
    # log "  Setting DHCP to NORMAL priority..."
    # ./build/rsqosctl add-class --proto udp --dport 67 --priority normal >> "$LOG_FILE" 2>&1 || warn "    Failed to set DHCP server priority"
    # ./build/rsqosctl add-class --proto udp --dport 68 --priority normal >> "$LOG_FILE" 2>&1 || warn "    Failed to set DHCP client priority"
    
    log "  ✓ QoS configuration complete (using defaults)"
else
    warn "  QoS maps not available yet (non-critical)"
fi

# Step 5: Verify VOQd status
log "[5/5] Verifying VOQd status..."

# Wait up to 10 seconds for VOQd to start (loader starts it asynchronously)
VOQD_TIMEOUT=10
VOQD_FOUND=0
for i in $(seq 1 $VOQD_TIMEOUT); do
    if pgrep -x "rswitch-voqd" > /dev/null; then
        VOQD_PID=$(pgrep -x "rswitch-voqd")
        log "  ✓ VOQd running (PID: $VOQD_PID)"
        VOQD_FOUND=1
        break
    fi
    sleep 1
done

if [ $VOQD_FOUND -eq 0 ]; then
    warn "  VOQd not running after ${VOQD_TIMEOUT}s (check /tmp/rswitch-voqd.log)"
    warn "  This is non-critical - rSwitch will operate in fast-path mode only"
    if [ -f "/tmp/rswitch-voqd.log" ]; then
        warn "  Recent VOQd log:"
        tail -10 /tmp/rswitch-voqd.log | while read line; do
            warn "    $line"
        done
    fi
fi

log "=========================================="
log "rSwitch Startup Complete"
log "=========================================="
log ""
log "Status:"
log "  Loader PID: $LOADER_PID"
log "  Log file: $LOG_FILE"
log ""
log "Useful commands:"
log "  View logs: tail -f $LOG_FILE"
log "  Check status: ps aux | grep rswitch"
log "  Stop: killall rswitch_loader"
log ""

# Save PID file for easy management
echo "$LOADER_PID" > /var/run/rswitch_loader.pid

exit 0
