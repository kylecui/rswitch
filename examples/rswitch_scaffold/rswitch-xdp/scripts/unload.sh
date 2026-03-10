#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: $0 <iface>" >&2
  exit 1
fi
# Detach XDP
sudo ip link set dev "$IFACE" xdp off 2>/dev/null || true
# Unpin/purge (demo-safe)
sudo rm -rf /sys/fs/bpf/rswitch 2>/dev/null || true
echo "[+] Unloaded."
