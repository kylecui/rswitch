#!/bin/bash

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Running all rSwitch benchmarks..."
echo ""

echo "=== Throughput Benchmark ==="
bash "${BENCH_DIR}/bench_throughput.sh" "$@"
echo ""

echo "=== Latency Benchmark ==="
bash "${BENCH_DIR}/bench_latency.sh"
echo ""

echo "All benchmarks complete."
