#!/bin/bash
# Generate vmlinux.h for CO-RE (Compile Once - Run Everywhere)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INCLUDE_DIR="${SCRIPT_DIR}/../bpf/include"
VMLINUX_H="${INCLUDE_DIR}/vmlinux.h"

echo "Generating vmlinux.h for CO-RE support..."

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool not found. Please install bpftool:"
    echo "  Ubuntu/Debian: sudo apt install linux-tools-$(uname -r)"
    echo "  RHEL/CentOS: sudo yum install bpftool"
    exit 1
fi

# Check if BTF is available
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Error: /sys/kernel/btf/vmlinux not found"
    echo "Your kernel may not have BTF support enabled."
    echo "Required kernel config: CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

# Generate vmlinux.h
mkdir -p "${INCLUDE_DIR}"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_H}"

echo "✓ Generated: ${VMLINUX_H}"
echo "  Size: $(wc -l < "${VMLINUX_H}") lines"
echo ""
echo "You can now build BPF programs with CO-RE support."
