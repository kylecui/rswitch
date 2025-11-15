#!/bin/bash
# Quick diagnostic script for rSwitch startup issues

echo "=========================================="
echo "rSwitch Startup Diagnostics"
echo "=========================================="
echo ""

# Check 1: Loader process
echo "[1] Checking rSwitch loader process..."
if pgrep -x "rswitch_loader" > /dev/null; then
    LOADER_PID=$(pgrep -x "rswitch_loader")
    echo "  ✓ Loader running (PID: $LOADER_PID)"
    echo "    Command: $(ps -p $LOADER_PID -o cmd=)"
else
    echo "  ✗ Loader NOT running"
fi
echo ""

# Check 2: VOQd process
echo "[2] Checking VOQd process..."
if pgrep -x "rswitch-voqd" > /dev/null; then
    VOQD_PID=$(pgrep -x "rswitch-voqd")
    echo "  ✓ VOQd running (PID: $VOQD_PID)"
else
    echo "  ✗ VOQd NOT running"
    if [ -f "/tmp/rswitch-voqd.log" ]; then
        echo "  VOQd log (last 10 lines):"
        tail -10 /tmp/rswitch-voqd.log | sed 's/^/    /'
    fi
fi
echo ""

# Check 3: XDP programs attached
echo "[3] Checking XDP programs..."
for iface in enp3s0 enp4s0 enp5s0; do
    if ip link show "$iface" | grep -q "xdp"; then
        echo "  ✓ $iface: XDP attached"
        XDP_INFO=$(ip link show "$iface" | grep "prog/xdp" | head -1)
        echo "    $XDP_INFO"
    else
        echo "  ✗ $iface: No XDP program"
    fi
done
echo ""

# Check 4: BPF maps
echo "[4] Checking BPF maps..."
if ls /sys/fs/bpf/*.map > /dev/null 2>&1; then
    MAP_COUNT=$(ls /sys/fs/bpf/ | wc -l)
    echo "  ✓ Found $MAP_COUNT BPF objects in /sys/fs/bpf/"
    echo "  Key maps:"
    for map in qos_config_ext_map qos_class_map voqd_state_map rs_prog_chain; do
        if [ -e "/sys/fs/bpf/$map" ]; then
            echo "    ✓ $map"
        else
            echo "    ✗ $map (missing)"
        fi
    done
else
    echo "  ✗ No BPF maps found in /sys/fs/bpf/"
fi
echo ""

# Check 5: Recent errors in system log
echo "[5] Checking system log for errors..."
if journalctl -u rc-local.service --since "5 minutes ago" --no-pager -n 20 2>/dev/null | grep -i error; then
    echo "  Found errors (see above)"
else
    echo "  ✓ No recent errors in rc-local.service"
fi
echo ""

# Check 6: Network interfaces status
echo "[6] Checking network interfaces..."
for iface in enp3s0 enp4s0 enp5s0; do
    if ip link show "$iface" 2>/dev/null | grep -q "UP"; then
        echo "  ✓ $iface: UP"
    else
        echo "  ✗ $iface: DOWN or not found"
    fi
done
echo ""

# Check 7: CPU affinity for IRQs
echo "[7] Checking IRQ affinity..."
for iface in enp3s0 enp4s0 enp5s0; do
    IRQ=$(grep "$iface" /proc/interrupts | head -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$IRQ" ]; then
        AFFINITY=$(cat /proc/irq/$IRQ/smp_affinity 2>/dev/null || echo "unknown")
        echo "  $iface (IRQ $IRQ): affinity=$AFFINITY"
    else
        echo "  $iface: IRQ not found"
    fi
done
echo ""

echo "=========================================="
echo "Diagnostic Complete"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  - View loader log: journalctl -u rc-local.service -f"
echo "  - View VOQd log: tail -f /tmp/rswitch-voqd.log"
echo "  - Manual start: sudo /home/jzzn/dev/rSwitch/tools/scripts/jzzn/rswitch_start.sh"
echo ""
