#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-}"
DEV_PORT="${2:-0}"   # devmap port index to set (demo)
MODE="${MODE:-native}"  # or "generic"

if [[ -z "$IFACE" ]]; then
  echo "Usage: $0 <iface> [dev_port_index]" >&2
  exit 1
fi

# Load program
sudo ./xdp_voq_user --iface "$IFACE" --mode "$MODE" --pin /sys/fs/bpf/rswitch \
  --devport "$DEV_PORT" --qos ./etc/qos.json

# Inspect
sudo bpftool net
sudo bpftool map show | grep rswitch || true
