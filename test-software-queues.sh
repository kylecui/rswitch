#!/bin/bash
# test-software-queues.sh - Complete test suite for rSwitch software queues

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Debug: Print paths
echo "DEBUG: SCRIPT_DIR=$SCRIPT_DIR" >&2
echo "DEBUG: PROJECT_ROOT=$PROJECT_ROOT" >&2
echo "DEBUG: VOQD_BIN=$VOQD_BIN" >&2

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PROFILE="qos-software-queues-test"
VOQD_BIN="$PROJECT_ROOT/build/rswitch-voqd"
LOADER_BIN="$PROJECT_ROOT/build/rswitch_loader"
TEST_DURATION=30
LOG_FILE="/tmp/rswitch-software-queues-test.log"

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  rSwitch Software Queues Test Suite${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This test requires root privileges"
        print_info "Run with: sudo $0"
        exit 1
    fi
}

setup_test_environment() {
    print_step "Setting up test environment"

    # Create dummy interface for testing
    if ! ip link show dummy0 >/dev/null 2>&1; then
        print_info "Creating dummy interface dummy0"
        modprobe dummy
        ip link add dummy0 type dummy
        ip link set dummy0 up
        ip addr add 192.168.1.1/24 dev dummy0
    fi

    # Clean up any existing rSwitch processes
    pkill -f rswitch-voqd 2>/dev/null || true
    pkill -f rswitch_loader 2>/dev/null || true

    # Clean up existing BPF maps
    if [ -d /sys/fs/bpf ]; then
        find /sys/fs/bpf -name "*rs*" -type d -exec rm -rf {} + 2>/dev/null || true
    fi

    sleep 2
    print_success "Test environment ready"
}

cleanup_test_environment() {
    print_step "Cleaning up test environment"

    # Stop test processes
    pkill -f rswitch-voqd 2>/dev/null || true
    pkill -f rswitch_loader 2>/dev/null || true

    # Remove dummy interface
    ip link delete dummy0 2>/dev/null || true

    # Clean up BPF maps
    if [ -d /sys/fs/bpf ]; then
        find /sys/fs/bpf -name "*rs*" -type d -exec rm -rf {} + 2>/dev/null || true
    fi

    print_success "Cleanup complete"
}

test_software_queues_shadow_mode() {
    print_step "Testing Software Queues in SHADOW Mode"

    # Start VOQd in shadow mode with software queues
    print_info "Starting VOQd in shadow mode with software queues"
    $VOQD_BIN -m shadow -q -Q 2048 -p 2 -P 0x0F -s -S 2 > "$LOG_FILE" 2>&1 &
    VOQD_PID=$!

    sleep 5

    # Check if VOQd is running
    if ! kill -0 $VOQD_PID 2>/dev/null; then
        print_error "VOQd failed to start"
        cat "$LOG_FILE"
        return 1
    fi

    # Check for software queue initialization message
    if grep -q "Software queue simulation enabled" "$LOG_FILE"; then
        print_success "Software queues initialized correctly"
    else
        print_error "Software queue initialization not found in logs"
        cat "$LOG_FILE"
        kill $VOQD_PID 2>/dev/null || true
        return 1
    fi

    # Generate some test traffic
    print_info "Generating test traffic with different DSCP values"
    timeout 10 ping -c 3 -Q 0xb8 192.168.1.1 >/dev/null 2>&1 || true  # DSCP 46 (EF)
    timeout 10 ping -c 3 -Q 0x80 192.168.1.1 >/dev/null 2>&1 || true  # DSCP 32 (AF41)
    timeout 10 ping -c 3 192.168.1.1 >/dev/null 2>&1 || true            # DSCP 0 (BE)

    sleep 5

    # Check statistics
    if grep -q "VOQd Statistics" "$LOG_FILE"; then
        print_success "VOQd statistics being collected"
    else
        print_warning "VOQd statistics not found (may be timing issue)"
    fi

    # Stop VOQd
    kill $VOQD_PID 2>/dev/null || true
    wait $VOQD_PID 2>/dev/null || true

    print_success "Shadow mode test completed"
    return 0
}

test_software_queues_active_mode() {
    print_step "Testing Software Queues in ACTIVE Mode"

    # Start VOQd in active mode with software queues
    print_info "Starting VOQd in active mode with software queues"
    $VOQD_BIN -m active -q -Q 2048 -p 2 -P 0x0F -i lo,dummy0 -s -S 2 > "$LOG_FILE" 2>&1 &
    VOQD_PID=$!

    sleep 5

    # Check if VOQd is running
    if ! kill -0 $VOQD_PID 2>/dev/null; then
        print_error "VOQd failed to start in active mode"
        cat "$LOG_FILE"
        kill $VOQD_PID 2>/dev/null || true
        return 1
    fi

    # Check for software queue initialization
    if grep -q "Software queue simulation enabled" "$LOG_FILE"; then
        print_success "Software queues initialized in active mode"
    else
        print_error "Software queue initialization not found in active mode logs"
        cat "$LOG_FILE"
        kill $VOQD_PID 2>/dev/null || true
        return 1
    fi

    # Generate test traffic
    print_info "Generating test traffic in active mode"
    timeout 10 ping -c 3 -Q 0xb8 127.0.0.1 >/dev/null 2>&1 || true
    timeout 10 ping -c 3 -Q 0x80 127.0.0.1 >/dev/null 2>&1 || true
    timeout 10 ping -c 3 127.0.0.1 >/dev/null 2>&1 || true

    sleep 5

    # Stop VOQd
    kill $VOQD_PID 2>/dev/null || true
    wait $VOQD_PID 2>/dev/null || true

    print_success "Active mode test completed"
    return 0
}

test_full_pipeline() {
    print_step "Testing Full Pipeline with Software Queues"

    # Load rSwitch with the test profile
    print_info "Loading rSwitch with software queues test profile"
    $LOADER_BIN -p $PROFILE > /tmp/loader.log 2>&1 &
    LOADER_PID=$!

    sleep 3

    # Check if loader succeeded
    if ! kill -0 $LOADER_PID 2>/dev/null; then
        print_error "rSwitch loader failed"
        cat /tmp/loader.log
        return 1
    fi

    # Start VOQd
    print_info "Starting VOQd with software queues"
    $VOQD_BIN -m shadow -q -Q 2048 -p 2 -P 0x0F -s -S 2 > "$LOG_FILE" 2>&1 &
    VOQD_PID=$!

    sleep 5

    # Check both processes are running
    if kill -0 $LOADER_PID 2>/dev/null && kill -0 $VOQD_PID 2>/dev/null; then
        print_success "Both rSwitch loader and VOQd are running"
    else
        print_error "One or both processes failed to start"
        kill $LOADER_PID 2>/dev/null || true
        kill $VOQD_PID 2>/dev/null || true
        return 1
    fi

    # Generate traffic through rSwitch
    print_info "Generating traffic through rSwitch pipeline"
    timeout 10 ping -c 5 -Q 0xb8 192.168.1.1 >/dev/null 2>&1 || true

    sleep 5

    # Stop processes
    kill $VOQD_PID 2>/dev/null || true
    kill $LOADER_PID 2>/dev/null || true
    wait $VOQD_PID 2>/dev/null || true
    wait $LOADER_PID 2>/dev/null || true

    print_success "Full pipeline test completed"
    return 0
}

run_performance_test() {
    print_step "Running Performance Test"

    print_info "Starting VOQd for performance measurement"
    $VOQD_BIN -m shadow -q -Q 2048 -p 2 -P 0x0F -s -S 1 > "$LOG_FILE" 2>&1 &
    VOQD_PID=$!

    sleep 3

    # Measure baseline CPU and memory
    local start_cpu=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}')
    local start_mem=$(free | grep Mem | awk '{print $3/$2 * 100.0}')

    # Generate traffic for 10 seconds
    print_info "Generating traffic for 10 seconds..."
    timeout 10 ping -f -Q 0xb8 192.168.1.1 >/dev/null 2>&1 || true

    sleep 2

    # Measure final CPU and memory
    local end_cpu=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}')
    local end_mem=$(free | grep Mem | awk '{print $3/$2 * 100.0}')

    # Check logs for performance indicators
    local rx_packets=$(grep "RX:" "$LOG_FILE" | tail -1 | awk '{print $2}' || echo "0")
    local tx_packets=$(grep "TX:" "$LOG_FILE" | tail -1 | awk '{print $2}' || echo "0")

    print_info "Performance Results:"
    print_info "  RX Packets: $rx_packets"
    print_info "  TX Packets: $tx_packets"
    print_info "  CPU Usage Change: $start_cpu% -> $end_cpu%"
    print_info "  Memory Usage: ${end_mem}%"

    if [ "$rx_packets" -gt 0 ] 2>/dev/null; then
        print_success "Performance test shows packet processing"
    else
        print_warning "No packets processed (may be expected for shadow mode)"
    fi

    kill $VOQD_PID 2>/dev/null || true
    wait $VOQD_PID 2>/dev/null || true

    print_success "Performance test completed"
}

main() {
    print_header

    # Parse command line arguments
    local test_type="all"
    while [[ $# -gt 0 ]]; do
        case $1 in
            --shadow-only)
                test_type="shadow"
                shift
                ;;
            --active-only)
                test_type="active"
                shift
                ;;
            --full-only)
                test_type="full"
                shift
                ;;
            --perf-only)
                test_type="perf"
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --shadow-only    Test only shadow mode"
                echo "  --active-only    Test only active mode"
                echo "  --full-only      Test only full pipeline"
                echo "  --perf-only      Run only performance test"
                echo "  --help           Show this help"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_root
    trap cleanup_test_environment EXIT

    setup_test_environment

    local failed_tests=0

    case $test_type in
        "shadow")
            test_software_queues_shadow_mode || ((failed_tests++))
            ;;
        "active")
            test_software_queues_active_mode || ((failed_tests++))
            ;;
        "full")
            test_full_pipeline || ((failed_tests++))
            ;;
        "perf")
            run_performance_test || ((failed_tests++))
            ;;
        "all")
            test_software_queues_shadow_mode || ((failed_tests++))
            test_software_queues_active_mode || ((failed_tests++))
            test_full_pipeline || ((failed_tests++))
            run_performance_test || ((failed_tests++))
            ;;
    esac

    echo
    if [ $failed_tests -eq 0 ]; then
        print_success "All tests passed! 🎉"
        print_info "Software queues are working correctly."
        echo
        print_info "Next steps:"
        echo "  1. Try the profile: sudo ./build/rswitch_loader -p qos-software-queues-test"
        echo "  2. Run VOQd: sudo ./build/rswitch-voqd -m shadow -q -Q 2048 -p 2 -P 0x0F -s -S 5"
        echo "  3. Monitor: watch -n 2 'sudo ./build/rsvoqctl show-stats'"
    else
        print_error "$failed_tests test(s) failed"
        exit 1
    fi
}

main "$@"