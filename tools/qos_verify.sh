#!/bin/bash
# Quick QoS Verification Script
# Run this after loading rSwitch with QoS profile

set -e

echo "=========================================="
echo "  rSwitch QoS Quick Verification"
echo "=========================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: Must run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# 1. Check QoS maps exist
echo "[1/5] Checking QoS BPF maps..."
maps_found=0
for map in qos_class_map qos_rate_map qos_qdepth_map qos_config_map; do
    if bpftool map show name "$map" &>/dev/null; then
        echo "  ✓ $map"
        ((maps_found++))
    else
        echo "  ✗ $map (not found)"
    fi
done

if [[ $maps_found -eq 0 ]]; then
    echo ""
    echo "ERROR: No QoS maps found!"
    echo "Make sure rSwitch loader is running with QoS profile:"
    echo "  sudo ./build/rswitch_loader --profile etc/profiles/qos-voqd-test.yaml --ifaces <your_ifaces>"
    exit 1
fi

echo ""

# 2. Check QoS program loaded
echo "[2/5] Checking QoS BPF program..."
if bpftool prog list | grep -q "name qos_egress"; then
    echo "  ✓ QoS egress program loaded"
else
    echo "  ✗ QoS program not found"
fi
echo ""

# 3. Display current rate limiter status
echo "[3/5] Rate Limiter Status:"
echo "Priority | Rate(bps)    | Burst(bytes) | TotalPkts  | DroppedPkts"
echo "---------|--------------|--------------|------------|------------"

for prio in 0 1 2 3; do
    if bpftool map lookup name qos_rate_map key $prio &>/dev/null; then
        # This is a simplified dump - actual parsing would be more complex
        result=$(bpftool map lookup name qos_rate_map key $prio 2>/dev/null)
        echo "   $prio     | (see below for details)"
    fi
done

echo ""
echo "Full rate map dump:"
bpftool map dump name qos_rate_map 2>/dev/null || echo "  (empty or error)"
echo ""

# 4. Check queue depths
echo "[4/5] Current Queue Depths:"
if bpftool map show name qos_qdepth_map &>/dev/null; then
    bpftool map dump name qos_qdepth_map 2>/dev/null || echo "  (empty)"
else
    echo "  (map not found)"
fi
echo ""

# 5. Check VOQd/AF_XDP status
echo "[5/5] AF_XDP/VOQd Status:"
if bpftool map show name voqd_state_map &>/dev/null; then
    echo "VOQd state map found"
    
    # Parse JSON output
    local json_output=$(bpftool map dump name voqd_state_map -j 2>/dev/null)
    local mode=$(echo "$json_output" | grep -o '"mode":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
    local running=$(echo "$json_output" | grep -o '"running":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
    local prio_mask=$(echo "$json_output" | grep -o '"prio_mask":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
    
    mode=${mode:-0}
    running=${running:-0}
    prio_mask=${prio_mask:-0}
    
    # Convert mode to string
    case $mode in
        0) mode_str="BYPASS" ;;
        1) mode_str="SHADOW" ;;
        2) mode_str="ACTIVE" ;;
        *) mode_str="UNKNOWN" ;;
    esac
    
    echo "  Mode: $mode_str ($mode)"
    echo "  Running: $running (0=stopped, 1=running)"
    echo "  Priority Mask: 0x$(printf '%02x' $prio_mask)"
    
    if [[ $running -eq 0 ]]; then
        echo "  ⚠️  VOQd not running - all traffic uses XDP fast-path"
    elif [[ $mode -eq 0 ]]; then
        echo "  ℹ️  BYPASS mode - VOQd running but not intercepting traffic"
    elif [[ $mode -eq 1 ]]; then
        echo "  ℹ️  SHADOW mode - VOQd observing without intercepting"
    elif [[ $mode -eq 2 ]]; then
        echo "  ✓ ACTIVE mode - VOQd handling high-priority flows"
    fi
else
    echo "  VOQd not configured (fast-path only)"
fi
echo ""

# Summary
echo "=========================================="
echo "  Quick Test Commands"
echo "=========================================="
echo ""
echo "1. Monitor QoS in real-time:"
echo "   sudo ./tools/qos_monitor.sh"
echo ""
echo "2. Test priority classification:"
echo "   # CRITICAL priority (DSCP 46 = ToS 184)"
echo "   ping -I ens33 -Q 184 -c 5 10.174.29.100"
echo ""
echo "   # HIGH priority (DSCP 32 = ToS 128)"
echo "   ping -I ens33 -Q 128 -c 5 10.174.29.100"
echo ""
echo "   # NORMAL priority (DSCP 0 = ToS 0)"
echo "   ping -I ens33 -Q 0 -c 5 10.174.29.100"
echo ""
echo "3. Enable debug output to see classification:"
echo "   sudo cat /sys/kernel/debug/tracing/trace_pipe | grep QoS"
echo ""
echo "   (Note: Requires rebuild with DEBUG=1 make)"
echo ""
echo "4. Run comprehensive tests:"
echo "   sudo ./tools/test_qos.sh --test all --verbose"
echo ""
echo "5. Check port statistics:"
echo "   sudo bpftool map dump name rs_stats_map"
echo ""
echo "=========================================="
echo "  QoS is $([ $maps_found -ge 2 ] && echo 'READY' || echo 'NOT READY')"
echo "=========================================="
echo ""

if [[ $maps_found -ge 2 ]]; then
    echo "✓ QoS maps are loaded and ready for testing"
    echo ""
    echo "Suggested next steps:"
    echo "  1. Run: sudo ./tools/qos_monitor.sh (in separate terminal)"
    echo "  2. Generate test traffic with different DSCP values"
    echo "  3. Observe classification and rate limiting in action"
    exit 0
else
    echo "✗ QoS not fully configured"
    echo "Please check loader configuration and restart"
    exit 1
fi
