#!/bin/bash

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${BENCH_DIR}/results"
RSWITCH_DIR="${BENCH_DIR}/../.."

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

DEFAULT_DURATION=10
DEFAULT_PACKET_SIZES="64 512 1518"
DEFAULT_PROFILES="l2-dumb l3 l3-acl-lab"
PKTGEN_SCRIPT="/proc/net/pktgen"

bench_init() {
    mkdir -p "${RESULTS_DIR}"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S_%N)
    RESULT_FILE="${RESULTS_DIR}/bench_${TIMESTAMP}.json"
    echo '{"timestamp":"'$(date -Iseconds)'","results":[' > "${RESULT_FILE}"
    FIRST_RESULT=1
}

bench_record() {
    local profile="$1" pkt_size="$2" pps="$3" latency_p50="$4" latency_p99="$5" cpu="$6"

    if [ ${FIRST_RESULT} -eq 0 ]; then
        echo "," >> "${RESULT_FILE}"
    fi
    FIRST_RESULT=0

    cat >> "${RESULT_FILE}" << EOF
{"profile":"${profile}","packet_size":${pkt_size},"pps":${pps},"latency_p50_us":${latency_p50},"latency_p99_us":${latency_p99},"cpu_percent":${cpu}}
EOF
}

bench_finish() {
    echo '],"summary":{"host":"'$(hostname)'","kernel":"'$(uname -r)'"}}' >> "${RESULT_FILE}"
    echo -e "${GREEN}Results saved to: ${RESULT_FILE}${NC}"
}

bench_compare() {
    local baseline="$1" current="$2"
    if [ ! -f "${baseline}" ]; then
        echo -e "${YELLOW}No baseline found. Saving current as baseline.${NC}"
        cp "${current}" "${RESULTS_DIR}/baseline.json"
        return 0
    fi
    echo -e "${YELLOW}Regression detection requires jq. Skipping detailed comparison.${NC}"
    return 0
}

bench_cpu_sample() {
    local duration=${1:-5}
    local pid=$(pgrep -f rswitch_loader | head -1)
    if [ -z "$pid" ]; then
        echo "0"
        return
    fi
    local cpu1=$(cat /proc/$pid/stat 2>/dev/null | awk '{print $14+$15}')
    sleep "$duration"
    local cpu2=$(cat /proc/$pid/stat 2>/dev/null | awk '{print $14+$15}')
    local ticks=$((cpu2 - cpu1))
    local hz=$(getconf CLK_TCK)
    local pct=$(echo "scale=1; $ticks * 100 / ($hz * $duration)" | bc 2>/dev/null || echo "0")
    echo "$pct"
}

bench_check_pktgen() {
    if [ ! -d "$PKTGEN_SCRIPT" ]; then
        echo -e "${YELLOW}WARNING: pktgen not available. Using synthetic benchmarks.${NC}"
        return 1
    fi
    return 0
}
