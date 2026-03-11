#!/bin/bash

set -euo pipefail
source "$(dirname "$0")/lib_bench.sh"

echo "============================================"
echo "rSwitch Latency Benchmark"
echo "============================================"
echo ""
echo "This benchmark requires:"
echo "  1. rSwitch loaded with a profile"
echo "  2. BPF timestamp instrumentation enabled"
echo "  3. Traffic generator (T-Rex or pktgen)"
echo ""
echo "Currently: placeholder for future implementation"
echo ""

bench_init

echo "Latency benchmark: not yet implemented (requires BPF timestamping)"
echo "See: test/benchmark/README.md for planned approach"

bench_finish
