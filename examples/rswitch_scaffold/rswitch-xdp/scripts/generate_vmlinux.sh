#!/usr/bin/env bash
set -euo pipefail
out="include/vmlinux.h"
mkdir -p include
if ! command -v bpftool >/dev/null; then
  echo "bpftool not found. Please install it (e.g., apt install bpftool)" >&2
  exit 1
fi
echo "[*] Generating $out from kernel BTF..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$out"
echo "[+] Done."
