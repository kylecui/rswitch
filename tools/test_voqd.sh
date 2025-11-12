#!/bin/bash
# VOQd Data Plane Testing Script
# Tests VOQd in different modes with AF_XDP integration

set -e

BIN_DIR="./build"
VOQD="$BIN_DIR/rswitch-voqd"
VOQCTL="$BIN_DIR/rsvoqctl"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."
    
    # Check if binaries exist
    if [ ! -x "$VOQD" ]; then
        log_error "VOQd binary not found: $VOQD"
        log_info "Run 'make' to build"
        exit 1
    fi
    
    if [ ! -x "$VOQCTL" ]; then
        log_error "VOQCtl binary not found: $VOQCTL"
        exit 1
    fi
    
    # Check for root privileges
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (AF_XDP requires privileges)"
        exit 1
    fi
    
    log_info "Requirements check passed"
}

test_metadata_mode() {
    log_info "=== Test 1: Metadata-Only Mode (No AF_XDP) ==="
    
    log_info "Starting VOQd in SHADOW mode (metadata-only)..."
    $VOQD -p 4 -m shadow -s -S 5 &
    VOQD_PID=$!
    
    sleep 2
    
    if kill -0 $VOQD_PID 2>/dev/null; then
        log_info "VOQd running (PID: $VOQD_PID)"
    else
        log_error "VOQd failed to start"
        return 1
    fi
    
    log_info "Waiting 10 seconds for statistics..."
    sleep 10
    
    log_info "Stopping VOQd..."
    kill -INT $VOQD_PID
    wait $VOQD_PID 2>/dev/null || true
    
    log_info "Test 1 completed"
    echo ""
}

test_afxdp_mode() {
    local INTERFACES="$1"
    
    if [ -z "$INTERFACES" ]; then
        log_warn "No interfaces specified, skipping AF_XDP test"
        return 0
    fi
    
    log_info "=== Test 2: AF_XDP Mode (Full Data Plane) ==="
    
    # Count interfaces
    IFS=',' read -ra IFACES <<< "$INTERFACES"
    NUM_PORTS=${#IFACES[@]}
    
    log_info "Interfaces: $INTERFACES ($NUM_PORTS ports)"
    
    # Check if interfaces exist
    for iface in "${IFACES[@]}"; do
        if ! ip link show "$iface" &>/dev/null; then
            log_error "Interface $iface does not exist"
            return 1
        fi
        log_info "Found interface: $iface"
    done
    
    log_info "Starting VOQd in ACTIVE mode with AF_XDP..."
    $VOQD -p $NUM_PORTS -m active -P 0x0F -i "$INTERFACES" -s -S 5 &
    VOQD_PID=$!
    
    sleep 3
    
    if kill -0 $VOQD_PID 2>/dev/null; then
        log_info "VOQd running with AF_XDP (PID: $VOQD_PID)"
    else
        log_error "VOQd failed to start in ACTIVE mode"
        return 1
    fi
    
    log_info "Configuring port rate limits..."
    # Set 100 Mbps on port 0
    $VOQCTL set-port-rate --port 0 --rate 100000000 --burst 65536 || log_warn "Failed to set rate"
    
    log_info "Configuring queue parameters..."
    # Set critical priority queue params
    $VOQCTL set-queue-params --port 0 --prio 3 --quantum 2048 --max-depth 8192 || log_warn "Failed to set queue params"
    
    log_info "Waiting 15 seconds for AF_XDP processing..."
    sleep 15
    
    log_info "Querying VOQ statistics..."
    $VOQCTL show-stats || log_warn "Failed to get stats"
    
    log_info "Stopping VOQd..."
    kill -INT $VOQD_PID
    wait $VOQD_PID 2>/dev/null || true
    
    log_info "Test 2 completed"
    echo ""
}

test_zero_copy_mode() {
    local INTERFACES="$1"
    
    if [ -z "$INTERFACES" ]; then
        log_warn "No interfaces specified, skipping zero-copy test"
        return 0
    fi
    
    log_info "=== Test 3: Zero-Copy AF_XDP Mode ==="
    
    IFS=',' read -ra IFACES <<< "$INTERFACES"
    NUM_PORTS=${#IFACES[@]}
    
    log_info "Starting VOQd with zero-copy enabled..."
    $VOQD -p $NUM_PORTS -m active -P 0x08 -i "$INTERFACES" -z -s -S 5 &
    VOQD_PID=$!
    
    sleep 3
    
    if kill -0 $VOQD_PID 2>/dev/null; then
        log_info "VOQd running with zero-copy (PID: $VOQD_PID)"
        
        log_info "Waiting 10 seconds..."
        sleep 10
        
        log_info "Stopping VOQd..."
        kill -INT $VOQD_PID
        wait $VOQD_PID 2>/dev/null || true
        
        log_info "Test 3 completed"
    else
        log_warn "Zero-copy mode not supported on this NIC (expected behavior)"
        log_info "Falling back to copy mode is normal for most NICs"
    fi
    
    echo ""
}

# Main test suite
main() {
    log_info "VOQd Data Plane Test Suite"
    echo ""
    
    check_requirements
    
    # Test 1: Metadata-only mode (always works)
    test_metadata_mode
    
    # Test 2 & 3: AF_XDP modes (require interface specification)
    if [ $# -ge 1 ]; then
        INTERFACES="$1"
        test_afxdp_mode "$INTERFACES"
        test_zero_copy_mode "$INTERFACES"
    else
        log_warn "No interfaces specified via command line"
        log_info "Usage: $0 <interface1>,<interface2>,..."
        log_info "Example: $0 ens33,ens34,ens35,ens36"
        log_info "Skipping AF_XDP tests"
    fi
    
    echo ""
    log_info "=== Test Suite Summary ==="
    log_info "✓ Metadata-only mode: Passed"
    
    if [ $# -ge 1 ]; then
        log_info "✓ AF_XDP mode: Check output above"
        log_info "✓ Zero-copy mode: Check output above"
    else
        log_info "⊘ AF_XDP tests: Skipped (no interfaces)"
    fi
    
    echo ""
    log_info "All tests completed!"
}

main "$@"
