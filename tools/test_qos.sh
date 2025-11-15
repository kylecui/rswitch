#!/bin/bash
# rSwitch QoS Testing Script
#
# This script tests QoS functionality:
# 1. Priority classification (DSCP → priority)
# 2. Rate limiting (token bucket)
# 3. AF_XDP redirection for high-priority traffic
# 4. Queue depth monitoring and congestion control
#
# Requirements:
# - rSwitch loader running with qos-voqd-test.yaml profile
# - iperf3 installed for traffic generation
# - tcpdump for packet capture
# - bpftool for BPF map inspection

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
INTERFACES="${INTERFACES:-ens33,ens34,ens35,ens36}"
IFS=',' read -ra IFACE_ARRAY <<< "$INTERFACES"
DURATION=10  # Test duration in seconds
VERBOSE=${VERBOSE:-0}

# Parse command line arguments
ENABLE_DEBUG=0
TEST_CASE="all"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --debug          Enable BPF debug output (rs_debug prints)"
    echo "  -t, --test <case>    Run specific test case:"
    echo "                       priority   - Priority classification test"
    echo "                       ratelimit  - Rate limiting test"
    echo "                       afxdp      - AF_XDP redirect test"
    echo "                       stats      - Statistics collection test"
    echo "                       all        - All tests (default)"
    echo "  -i, --interfaces     Comma-separated interface list"
    echo "  -v, --verbose        Verbose output"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -d -t priority"
    echo "  $0 -t ratelimit -v"
    echo "  $0 --interfaces ens33,ens34,ens35"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            ENABLE_DEBUG=1
            shift
            ;;
        -t|--test)
            TEST_CASE="$2"
            shift 2
            ;;
        -i|--interfaces)
            INTERFACES="$2"
            IFS=',' read -ra IFACE_ARRAY <<< "$INTERFACES"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Check required tools
    local missing=0
    for tool in bpftool ip ethtool tcpdump; do
        if ! command -v $tool &> /dev/null; then
            log_error "Required tool not found: $tool"
            missing=1
        fi
    done
    
    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
    
    # Check if interfaces exist
    for iface in "${IFACE_ARRAY[@]}"; do
        if ! ip link show "$iface" &> /dev/null; then
            log_error "Interface not found: $iface"
            exit 1
        fi
    done
    
    log_info "All requirements satisfied"
}

enable_debug_output() {
    if [[ $ENABLE_DEBUG -eq 1 ]]; then
        log_info "Enabling BPF debug output..."
        
        # Need to rebuild with DEBUG=1
        log_warn "To enable debug output, rebuild with: make clean && DEBUG=1 make"
        log_warn "Then reload the loader"
        
        # Start trace_pipe reader in background
        log_info "Starting trace_pipe reader..."
        (
            echo "=== BPF Trace Output ===" > /tmp/qos_test_trace.log
            timeout ${DURATION}s cat /sys/kernel/debug/tracing/trace_pipe >> /tmp/qos_test_trace.log 2>&1 &
        ) &
        TRACE_PID=$!
        
        sleep 1
        log_info "Trace reader started (PID: $TRACE_PID, log: /tmp/qos_test_trace.log)"
    fi
}

check_qos_maps() {
    log_info "Checking QoS BPF maps..."
    
    # Check if QoS maps are loaded
    local maps=(qos_class_map qos_rate_map qos_qdepth_map qos_config_map)
    
    for map in "${maps[@]}"; do
        if bpftool map show name "$map" &> /dev/null; then
            log_info "  ✓ Map found: $map"
            if [[ $VERBOSE -eq 1 ]]; then
                bpftool map show name "$map"
            fi
        else
            log_warn "  ✗ Map not found: $map"
        fi
    done
}

dump_qos_stats() {
    log_info "QoS Statistics:"
    echo "=========================================="
    
    # Dump rate limiter stats
    if bpftool map show name qos_rate_map &> /dev/null; then
        echo ""
        echo "Rate Limiter Stats (per-priority):"
        echo "Priority | Rate(bps) | Burst | Tokens | TotalBytes | DroppedBytes | DroppedPkts"
        echo "---------|-----------|-------|--------|------------|--------------|------------"
        
        # Dump map (format: key → value)
        bpftool map dump name qos_rate_map 2>/dev/null | grep -A1 "key:" | while read -r line; do
            if [[ $line == *"key:"* ]]; then
                prio=$(echo "$line" | awk '{print $2}')
            elif [[ $line == *"value:"* ]]; then
                # Parse struct qos_rate_limiter fields
                values=$(echo "$line" | tr -d '[]' | awk '{for(i=2;i<=NF;i++) printf "%s ", $i}')
                echo "$prio | $values"
            fi
        done
    fi
    
    # Dump queue depth stats
    if bpftool map show name qos_qdepth_map &> /dev/null; then
        echo ""
        echo "Queue Depth (per-priority):"
        echo "Priority | Queue Depth"
        echo "---------|------------"
        bpftool map dump name qos_qdepth_map 2>/dev/null | grep -E "key:|value:" | paste - - | \
        awk '{print $2 " | " $5}'
    fi
    
    # Dump AF_XDP redirect stats
    if bpftool map show name afxdp_stats_map &> /dev/null; then
        echo ""
        echo "AF_XDP Redirect Stats:"
        bpftool map dump name afxdp_stats_map 2>/dev/null
    fi
    
    echo "=========================================="
}

# Test 1: Priority Classification
test_priority_classification() {
    log_test "Test 1: Priority Classification (DSCP → Priority Mapping)"
    echo ""
    
    log_info "Configuring QoS classification rules..."
    
    # Add classification rules using rsqosctl (if available)
    if [[ -f ./build/rsqosctl ]]; then
        # DSCP 46 (EF) → Priority 3 (CRITICAL)
        ./build/rsqosctl add-class --proto tcp --dscp 46 --priority 3 2>/dev/null || true
        
        # DSCP 32 (AF41) → Priority 2 (HIGH)
        ./build/rsqosctl add-class --proto tcp --dscp 32 --priority 2 2>/dev/null || true
        
        # DSCP 0 (BE) → Priority 0 (LOW)
        ./build/rsqosctl add-class --proto tcp --dscp 0 --priority 0 2>/dev/null || true
        
        log_info "Classification rules configured"
    else
        log_warn "rsqosctl not found, skipping rule configuration"
        log_warn "QoS will use default DSCP→priority mapping from module"
    fi
    
    log_info "Sending test packets with different DSCP values..."
    
    # Generate packets with different DSCP markings
    # Use ping with TOS (Type of Service) field
    
    local test_ip="10.174.29.100"
    local iface="${IFACE_ARRAY[0]}"
    
    # Test CRITICAL priority (DSCP 46 = ToS 184)
    log_info "  Testing CRITICAL priority (DSCP 46)..."
    ping -I "$iface" -Q 184 -c 3 -W 1 "$test_ip" &>/dev/null || true
    
    # Test HIGH priority (DSCP 32 = ToS 128)
    log_info "  Testing HIGH priority (DSCP 32)..."
    ping -I "$iface" -Q 128 -c 3 -W 1 "$test_ip" &>/dev/null || true
    
    # Test LOW priority (DSCP 0 = ToS 0)
    log_info "  Testing LOW priority (DSCP 0)..."
    ping -I "$iface" -Q 0 -c 3 -W 1 "$test_ip" &>/dev/null || true
    
    sleep 2
    
    log_info "Checking classification results..."
    dump_qos_stats
    
    # Check trace output
    if [[ $ENABLE_DEBUG -eq 1 ]] && [[ -f /tmp/qos_test_trace.log ]]; then
        echo ""
        log_info "Debug trace output (QoS classification):"
        grep "QoS: Classified" /tmp/qos_test_trace.log | tail -10 || true
    fi
    
    echo ""
    log_info "✓ Priority classification test completed"
    echo ""
}

# Test 2: Rate Limiting
test_rate_limiting() {
    log_test "Test 2: Rate Limiting (Token Bucket)"
    echo ""
    
    log_info "Configuring rate limiters..."
    
    # Set rate limits (if rsqosctl available)
    if [[ -f ./build/rsqosctl ]]; then
        # Priority 3 (CRITICAL): 100 Mbps, 64KB burst
        ./build/rsqosctl set-rate --priority 3 --rate 100000000 --burst 65536 2>/dev/null || true
        
        # Priority 2 (HIGH): 50 Mbps, 32KB burst
        ./build/rsqosctl set-rate --priority 2 --rate 50000000 --burst 32768 2>/dev/null || true
        
        # Priority 0 (LOW): 10 Mbps, 16KB burst
        ./build/rsqosctl set-rate --priority 0 --rate 10000000 --burst 16384 2>/dev/null || true
        
        log_info "Rate limits configured"
    else
        log_warn "rsqosctl not found, using default rate limits"
    fi
    
    log_info "Generating high-bandwidth traffic to trigger rate limiting..."
    
    # Use iperf3 if available, otherwise use dd + nc
    local iface="${IFACE_ARRAY[0]}"
    local target_ip="10.174.29.100"
    
    if command -v iperf3 &> /dev/null; then
        log_info "  Using iperf3 for traffic generation (10 seconds)..."
        
        # Start iperf3 server in background (on remote host)
        # iperf3 -s -D
        
        # Generate traffic with different DSCP markings
        log_info "    Testing LOW priority (should be rate-limited to 10 Mbps)..."
        iperf3 -c "$target_ip" -t 5 -S 0x00 -b 50M 2>/dev/null || log_warn "iperf3 failed"
        
        log_info "    Testing HIGH priority (should be rate-limited to 50 Mbps)..."
        iperf3 -c "$target_ip" -t 5 -S 0x80 -b 100M 2>/dev/null || log_warn "iperf3 failed"
        
    else
        log_warn "iperf3 not found, skipping bandwidth test"
        log_info "Install iperf3 for better rate limiting tests"
    fi
    
    sleep 2
    
    log_info "Checking rate limiter statistics..."
    dump_qos_stats
    
    # Check for drops
    echo ""
    log_info "Checking for rate-limited drops..."
    if bpftool map dump name qos_rate_map 2>/dev/null | grep -q "dropped_packets:"; then
        drops=$(bpftool map dump name qos_rate_map 2>/dev/null | grep "dropped_packets:" | awk '{sum+=$2} END {print sum}')
        if [[ $drops -gt 0 ]]; then
            log_info "  ✓ Rate limiting active: $drops packets dropped"
        else
            log_warn "  ! No packets dropped (rate limit may not be triggered)"
        fi
    fi
    
    echo ""
    log_info "✓ Rate limiting test completed"
    echo ""
}

# Test 3: AF_XDP Redirection
test_afxdp_redirect() {
    log_test "Test 3: AF_XDP Redirection (High-Priority Traffic)"
    echo ""
    
    log_info "Checking AF_XDP devmap..."
    if bpftool map show name afxdp_devmap &> /dev/null; then
        log_info "  ✓ AF_XDP devmap found"
        bpftool map dump name afxdp_devmap | head -20
    else
        log_warn "  ✗ AF_XDP devmap not found"
        log_warn "AF_XDP redirection may not be configured"
    fi
    
    log_info "Checking VOQd state..."
    if bpftool map show name voqd_state_map &> /dev/null; then
        log_info "  VOQd state:"
        bpftool map dump name voqd_state_map
    else
        log_warn "  VOQd state map not found (VOQd may not be running)"
    fi
    
    log_info "Generating high-priority traffic for AF_XDP redirect..."
    
    # Send CRITICAL priority traffic (DSCP 46)
    local iface="${IFACE_ARRAY[0]}"
    local target_ip="10.174.29.100"
    
    log_info "  Sending CRITICAL priority packets (DSCP 46)..."
    ping -I "$iface" -Q 184 -c 10 -i 0.1 "$target_ip" &>/dev/null || true
    
    sleep 2
    
    log_info "Checking AF_XDP redirect statistics..."
    if [[ -f ./build/rsqosctl ]]; then
        ./build/rsqosctl show-stats 2>/dev/null || true
    fi
    
    # Check ringbuf events
    if bpftool map show name rs_event_bus &> /dev/null; then
        log_info "Checking event bus for AF_XDP redirect events..."
        # Would need rswitch-events consumer running
    fi
    
    echo ""
    log_info "✓ AF_XDP redirection test completed"
    echo ""
}

# Test 4: Statistics Collection
test_statistics() {
    log_test "Test 4: Statistics Collection and Monitoring"
    echo ""
    
    log_info "Collecting baseline statistics..."
    
    # Dump all QoS-related maps
    echo "=== QoS Map Contents ==="
    
    echo ""
    echo "1. QoS Config Map (per-port configuration):"
    if bpftool map show name qos_config_map &> /dev/null; then
        bpftool map dump name qos_config_map
    else
        echo "  (not found)"
    fi
    
    echo ""
    echo "2. QoS Classification Map (traffic → priority rules):"
    if bpftool map show name qos_class_map &> /dev/null; then
        log_info "  Total rules: $(bpftool map dump name qos_class_map 2>/dev/null | grep -c "key:" || echo 0)"
        if [[ $VERBOSE -eq 1 ]]; then
            bpftool map dump name qos_class_map | head -50
        fi
    else
        echo "  (not found)"
    fi
    
    echo ""
    echo "3. Rate Limiter Map:"
    dump_qos_stats
    
    echo ""
    echo "4. Port Statistics (rs_stats_map):"
    if bpftool map show name rs_stats_map &> /dev/null; then
        echo "Port | RX Pkts | RX Bytes | TX Pkts | TX Bytes | Drops"
        echo "-----|---------|----------|---------|----------|------"
        bpftool map dump name rs_stats_map 2>/dev/null | grep -E "key:|value:" | paste - - | \
        awk '{
            port=$2
            # Parse stats struct (rx_packets, rx_bytes, tx_packets, tx_bytes, tx_drops, rx_drops)
            getline; rx_pkts=$2; rx_bytes=$3; tx_pkts=$4; tx_bytes=$5; tx_drops=$6; rx_drops=$7
            printf "%4s | %7s | %8s | %7s | %8s | %s/%s\n", port, rx_pkts, rx_bytes, tx_pkts, tx_bytes, tx_drops, rx_drops
        }'
    else
        echo "  (not found)"
    fi
    
    echo ""
    log_info "✓ Statistics collection test completed"
    echo ""
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test artifacts..."
    
    # Kill trace reader if running
    if [[ -n "$TRACE_PID" ]]; then
        kill $TRACE_PID 2>/dev/null || true
    fi
    
    # Clean up any test traffic generators
    pkill -f "iperf3.*test" 2>/dev/null || true
    
    log_info "Cleanup complete"
}

trap cleanup EXIT

# Main test execution
main() {
    echo ""
    echo "========================================"
    echo "  rSwitch QoS Testing Suite"
    echo "========================================"
    echo ""
    
    check_requirements
    enable_debug_output
    check_qos_maps
    
    echo ""
    
    case $TEST_CASE in
        priority)
            test_priority_classification
            ;;
        ratelimit)
            test_rate_limiting
            ;;
        afxdp)
            test_afxdp_redirect
            ;;
        stats)
            test_statistics
            ;;
        all)
            test_priority_classification
            test_rate_limiting
            test_afxdp_redirect
            test_statistics
            ;;
        *)
            log_error "Unknown test case: $TEST_CASE"
            usage
            ;;
    esac
    
    # Final summary
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    
    if [[ $ENABLE_DEBUG -eq 1 ]] && [[ -f /tmp/qos_test_trace.log ]]; then
        echo ""
        log_info "Full debug trace saved to: /tmp/qos_test_trace.log"
        echo ""
        log_info "Key QoS events in trace:"
        grep -E "QoS: (Classified|Rate limited|ECN marked|Congestion drop)" /tmp/qos_test_trace.log | wc -l || echo "0"
    fi
    
    echo ""
    log_info "All tests completed!"
    echo ""
}

main "$@"
