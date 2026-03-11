#!/bin/bash

set -euo pipefail
source "$(dirname "$0")/lib_bench.sh"

DURATION=${BENCH_DURATION:-${DEFAULT_DURATION}}
PACKET_SIZES=${BENCH_PACKET_SIZES:-${DEFAULT_PACKET_SIZES}}
PROFILES=${BENCH_PROFILES:-${DEFAULT_PROFILES}}
INTERFACE=${BENCH_INTERFACE:-""}

usage() {
    echo "Usage: $0 [-d duration] [-s sizes] [-p profiles] [-i interface]"
    echo ""
    echo "Options:"
    echo "  -d SECONDS    Test duration per run (default: ${DEFAULT_DURATION})"
    echo "  -s SIZES      Space-separated packet sizes (default: '${DEFAULT_PACKET_SIZES}')"
    echo "  -p PROFILES   Space-separated profile names (default: '${DEFAULT_PROFILES}')"
    echo "  -i INTERFACE  Network interface for pktgen (required for hardware test)"
    echo ""
    echo "Environment Variables:"
    echo "  BENCH_DURATION, BENCH_PACKET_SIZES, BENCH_PROFILES, BENCH_INTERFACE"
    exit 1
}

while getopts "d:s:p:i:h" opt; do
    case $opt in
        d) DURATION=$OPTARG ;;
        s) PACKET_SIZES="$OPTARG" ;;
        p) PROFILES="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

echo "============================================"
echo "rSwitch Throughput Benchmark"
echo "============================================"
echo "Duration per test: ${DURATION}s"
echo "Packet sizes: ${PACKET_SIZES}"
echo "Profiles: ${PROFILES}"
echo "Interface: ${INTERFACE:-'(synthetic mode)'}"
echo "============================================"
echo ""

bench_init

run_synthetic_bench() {
    local profile_name="$1"
    local pkt_size="$2"

    local profile_file="${RSWITCH_DIR}/etc/profiles/${profile_name}.yaml"
    if [ ! -f "${profile_file}" ]; then
        echo -e "${YELLOW}  Profile ${profile_name} not found, skipping${NC}"
        return
    fi

    local start_ns=$(date +%s%N)
    ${RSWITCH_DIR}/build/rswitchctl validate-profile "${profile_file}" > /dev/null 2>&1 || true
    local end_ns=$(date +%s%N)
    local elapsed_us=$(( (end_ns - start_ns) / 1000 ))

    echo -e "  Profile load time: ${elapsed_us} us"
    bench_record "${profile_name}" "${pkt_size}" 0 "${elapsed_us}" 0 0
}

run_pktgen_bench() {
    local profile_name="$1"
    local pkt_size="$2"

    echo -e "${YELLOW}  pktgen benchmark not implemented yet${NC}"
    echo -e "${YELLOW}  (requires root and loaded rswitch instance)${NC}"
    bench_record "${profile_name}" "${pkt_size}" 0 0 0 0
}

for profile in ${PROFILES}; do
    echo -e "${GREEN}Testing profile: ${profile}${NC}"
    for size in ${PACKET_SIZES}; do
        echo "  Packet size: ${size}B"
        if [ -n "${INTERFACE}" ] && bench_check_pktgen; then
            run_pktgen_bench "${profile}" "${size}"
        else
            run_synthetic_bench "${profile}" "${size}"
        fi
    done
    echo ""
done

bench_finish

echo ""
echo "============================================"
echo "Benchmark Complete"
echo "============================================"
