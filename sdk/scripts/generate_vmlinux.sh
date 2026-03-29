#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# generate_vmlinux.sh — Generate vmlinux.h from running kernel BTF
#
# Usage:
#   ./generate_vmlinux.sh [output_path]
#
# Default output: vmlinux.h in current directory
#
# Requirements:
#   - bpftool (usually in linux-tools-$(uname -r) or bpftool package)
#   - Kernel with BTF support (/sys/kernel/btf/vmlinux must exist)

set -euo pipefail

OUTPUT="${1:-vmlinux.h}"

# Check prerequisites
if ! command -v bpftool &>/dev/null; then
    echo "Error: bpftool not found." >&2
    echo "Install with: apt install linux-tools-\$(uname -r)  # Debian/Ubuntu" >&2
    echo "          or: dnf install bpftool                    # Fedora/RHEL" >&2
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "Error: /sys/kernel/btf/vmlinux not found." >&2
    echo "Your kernel may not have BTF support enabled." >&2
    echo "Rebuild with CONFIG_DEBUG_INFO_BTF=y" >&2
    exit 1
fi

echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUTPUT"
echo "Done: $OUTPUT ($(wc -l < "$OUTPUT") lines)"
