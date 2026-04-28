#!/bin/bash
# rswitch-killswitch-trigger.sh <target-ip> <stop|reboot> [key-file] [port]
# Send killswitch trigger keys via UDP to running rswitch instance.

set -euo pipefail

TARGET_IP="${1:-}"
ACTION="${2:-}"
KEY_FILE="${3:-/etc/rswitch/killswitch.key}"
PORT="${4:-19999}"

log() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] KILLSWITCH-TRIGGER: $*"
}

usage() {
    cat >&2 <<'EOF'
Usage: rswitch-killswitch-trigger.sh <target-ip> <stop|reboot> [key-file] [port]

Arguments:
  target-ip      IP address of target rswitch instance
  stop|reboot    Action to trigger (stop or reboot)
  key-file       Path to killswitch.key file (default: /etc/rswitch/killswitch.key)
  port           UDP port for trigger (default: 19999)

Example:
  rswitch-killswitch-trigger.sh 192.168.1.10 stop
  rswitch-killswitch-trigger.sh 192.168.1.10 reboot /etc/rswitch/killswitch.key 19999
EOF
    exit 1
}

if [ -z "$TARGET_IP" ] || [ -z "$ACTION" ]; then
    usage
fi

if [ ! -f "$KEY_FILE" ]; then
    log "ERROR: Key file not found: $KEY_FILE"
    exit 1
fi

case "$ACTION" in
    stop)
        KEY_LINE=1
        ;;
    reboot)
        KEY_LINE=2
        ;;
    *)
        log "ERROR: Unknown action: $ACTION (expected 'stop' or 'reboot')"
        usage
        ;;
esac

KEY=$(sed -n "${KEY_LINE}p" "$KEY_FILE" 2>/dev/null)

if [ -z "$KEY" ]; then
    log "ERROR: Cannot read key line $KEY_LINE from $KEY_FILE"
    exit 1
fi

log "Sending $ACTION trigger to $TARGET_IP:$PORT"
log "Key (first 8 chars): ${KEY:0:8}..."

if command -v socat >/dev/null 2>&1; then
    log "Using socat to send UDP payload"
    echo -n "$KEY" | xxd -r -p | socat - "UDP:$TARGET_IP:$PORT" 2>/dev/null || {
        log "ERROR: socat send failed"
        exit 1
    }
else
    log "socat not available, falling back to python"
    if ! command -v python3 >/dev/null 2>&1; then
        log "ERROR: Neither socat nor python3 found"
        exit 1
    fi

    python3 <<PYTHON_EOF
import socket
import sys

try:
    key_hex = "$KEY"
    payload = bytes.fromhex(key_hex)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload, ("$TARGET_IP", $PORT))
    sock.close()
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_EOF
    if [ $? -ne 0 ]; then
        log "ERROR: python3 send failed"
        exit 1
    fi
fi

log "$ACTION trigger sent successfully"
