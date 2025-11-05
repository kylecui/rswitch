#!/bin/bash
# rSwitch Hot-Reload Helper Script
# 
# Simplifies module hot-reloading by automatically finding the rs_progs map FD
# and invoking the hot_reload tool.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RSWITCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HOT_RELOAD="$RSWITCH_DIR/build/hot_reload"
PIN_PATH="/sys/fs/bpf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat << EOF
Usage: $(basename $0) <command> [OPTIONS]

Commands:
  reload <module>     Hot-reload a module (e.g., 'vlan', 'l2learn', 'lastcall')
  unload <module>     Remove module from pipeline
  list                List currently loaded modules
  verify [stages...]  Verify pipeline integrity (default: 20 80 90)
  
Options:
  -n, --dry-run       Validate but don't apply changes
  -v, --verbose       Verbose output
  -h, --help          Show this help

Examples:
  # Hot-reload vlan module
  $(basename $0) reload vlan

  # Hot-reload with verbose output
  $(basename $0) reload l2learn -v

  # Verify pipeline stages
  $(basename $0) verify 20 80 90

  # Dry-run (check without applying)
  $(basename $0) reload vlan -n

EOF
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check if hot_reload tool exists
if [ ! -f "$HOT_RELOAD" ]; then
    echo -e "${RED}Error: hot_reload tool not found at $HOT_RELOAD${NC}"
    echo "Please run 'make' to build it"
    exit 1
fi

# Find rs_progs map FD
find_rs_progs_fd() {
    # Try pinned path first
    if [ -f "$PIN_PATH/rs_progs" ]; then
        # Get FD from pinned map
        local fd=$(bpftool map show pinned "$PIN_PATH/rs_progs" 2>/dev/null | head -1 | awk '{print $1}' | cut -d: -f1)
        if [ -n "$fd" ]; then
            echo "$fd"
            return 0
        fi
    fi
    
    # Fallback: search by name
    local fd=$(bpftool map list 2>/dev/null | grep "rs_progs" | head -1 | awk '{print $1}' | cut -d: -f1)
    if [ -n "$fd" ]; then
        echo "$fd"
        return 0
    fi
    
    echo -e "${RED}Error: rs_progs map not found${NC}" >&2
    echo "Make sure rswitch_loader is running" >&2
    return 1
}

# Parse arguments
if [ $# -lt 1 ]; then
    usage
fi

COMMAND="$1"
shift

MODULE=""
STAGES=""
EXTRA_ARGS=""

# Parse command-specific arguments
case "$COMMAND" in
    reload|unload)
        if [ $# -lt 1 ]; then
            echo -e "${RED}Error: module name required for $COMMAND${NC}"
            usage
        fi
        MODULE="$1"
        shift
        EXTRA_ARGS="$@"
        ;;
    list)
        EXTRA_ARGS="$@"
        ;;
    verify)
        # Collect stage numbers
        while [ $# -gt 0 ]; do
            case "$1" in
                -*)
                    EXTRA_ARGS="$EXTRA_ARGS $1"
                    ;;
                *)
                    STAGES="$STAGES $1"
                    ;;
            esac
            shift
        done
        
        # Default stages if none specified
        if [ -z "$STAGES" ]; then
            STAGES="20 80 90"
        fi
        ;;
    -h|--help)
        usage
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        usage
        ;;
esac

# Find rs_progs map FD
echo -e "${YELLOW}Finding rs_progs map...${NC}"
RS_PROGS_FD=$(find_rs_progs_fd)
if [ $? -ne 0 ]; then
    exit 1
fi
echo -e "${GREEN}Found rs_progs map: FD $RS_PROGS_FD${NC}"
echo ""

# Execute command
case "$COMMAND" in
    reload)
        echo -e "${YELLOW}Hot-reloading module: $MODULE${NC}"
        $HOT_RELOAD reload "$MODULE" -p "$RS_PROGS_FD" $EXTRA_ARGS
        ;;
    unload)
        echo -e "${YELLOW}Unloading module: $MODULE${NC}"
        $HOT_RELOAD unload "$MODULE" -p "$RS_PROGS_FD" $EXTRA_ARGS
        ;;
    list)
        $HOT_RELOAD list $EXTRA_ARGS
        ;;
    verify)
        echo -e "${YELLOW}Verifying pipeline stages: $STAGES${NC}"
        $HOT_RELOAD verify $STAGES -p "$RS_PROGS_FD" $EXTRA_ARGS
        ;;
esac

exit $?
