#!/bin/bash
# Load rSwitch with specified profile

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."

# Default values
PROFILE=""
IFACES=""
MODE="native"

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Load rSwitch with specified configuration.

Options:
    -p, --profile FILE    Profile YAML file (required)
    -i, --ifaces LIST     Comma-separated interface list (e.g., ens34,ens35,ens36)
    -m, --mode MODE       XDP mode: native (default), skb, hw
    -h, --help            Show this help

Examples:
    $0 -p etc/profiles/l2.yaml -i ens34,ens35,ens36
    $0 --profile etc/profiles/l3.yaml --ifaces eth0,eth1,eth2 --mode native

Environment Variables:
    RSWITCH_INTERFACES    Default interface list if -i not specified
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -i|--ifaces)
            IFACES="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate inputs
if [ -z "$PROFILE" ]; then
    echo "Error: Profile required (-p/--profile)"
    usage
fi

if [ ! -f "$PROJECT_ROOT/$PROFILE" ]; then
    echo "Error: Profile not found: $PROFILE"
    exit 1
fi

# Use environment variable if interfaces not specified
if [ -z "$IFACES" ] && [ -n "$RSWITCH_INTERFACES" ]; then
    IFACES="$RSWITCH_INTERFACES"
fi

if [ -z "$IFACES" ]; then
    echo "Error: Interfaces required (-i/--ifaces or RSWITCH_INTERFACES env var)"
    usage
fi

# Check if loader exists
LOADER="$PROJECT_ROOT/build/rswitch_loader"
if [ ! -x "$LOADER" ]; then
    echo "Error: Loader not found or not executable: $LOADER"
    echo "Run: make"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "=== Loading rSwitch ==="
echo "  Profile: $PROFILE"
echo "  Interfaces: $IFACES"
echo "  Mode: $MODE"
echo ""

# Load rSwitch
exec "$LOADER" --profile "$PROJECT_ROOT/$PROFILE" --ifaces "$IFACES" --mode "$MODE"
