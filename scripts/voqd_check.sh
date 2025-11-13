#!/bin/bash
# VOQd health check script

echo "========================================"
echo "VOQd Health Check"
echo "========================================"
echo ""

# Check if VOQd process is running
if pgrep -x "rswitch-voqd" > /dev/null; then
    VOQD_PID=$(pgrep -x "rswitch-voqd")
    echo "✓ VOQd Process: Running (PID: $VOQD_PID)"
    
    # Check CPU usage
    CPU=$(ps -p $VOQD_PID -o %cpu= | tr -d ' ')
    MEM=$(ps -p $VOQD_PID -o %mem= | tr -d ' ')
    echo "  CPU: ${CPU}%  MEM: ${MEM}%"
    
    # Check threads
    THREADS=$(ps -T -p $VOQD_PID | tail -n +2 | wc -l)
    echo "  Threads: $THREADS"
else
    echo "✗ VOQd Process: NOT running"
    echo ""
    echo "Last 20 lines of /tmp/rswitch-voqd.log:"
    tail -20 /tmp/rswitch-voqd.log 2>/dev/null || echo "  (log file not found)"
    exit 1
fi

echo ""

# Check AF_XDP sockets
echo "AF_XDP Sockets:"
if [ -f "/sys/fs/bpf/xsks_map" ]; then
    echo "✓ xsks_map exists"
    # Try to dump the map (requires bpftool)
    if command -v bpftool >/dev/null 2>&1; then
        SOCKET_COUNT=$(bpftool map dump pinned /sys/fs/bpf/xsks_map 2>/dev/null | grep -c "key:")
        echo "  Socket entries: $SOCKET_COUNT"
    fi
else
    echo "✗ xsks_map not found"
fi

echo ""

# Check VOQd state map
echo "VOQd State:"
if [ -f "/sys/fs/bpf/voqd_state_map" ]; then
    echo "✓ voqd_state_map exists"
    if command -v bpftool >/dev/null 2>&1; then
        echo "  State map contents:"
        bpftool map dump pinned /sys/fs/bpf/voqd_state_map 2>/dev/null | head -20 | sed 's/^/    /'
    fi
else
    echo "✗ voqd_state_map not found"
fi

echo ""

# Parse VOQd log for statistics
if [ -f "/tmp/rswitch-voqd.log" ]; then
    echo "Recent VOQd Statistics (from log):"
    
    # Get last statistics block
    LAST_STATS=$(tac /tmp/rswitch-voqd.log | awk '/=== Data Plane Statistics ===/,/=== VOQd Statistics/' | tac)
    
    if [ -n "$LAST_STATS" ]; then
        # Extract key metrics
        RX_PKT=$(echo "$LAST_STATS" | grep "^RX:" | awk '{print $2}')
        TX_PKT=$(echo "$LAST_STATS" | grep "^TX:" | awk '{print $2}')
        HEARTBEATS=$(echo "$LAST_STATS" | grep "State:" | awk -F'heartbeats=' '{print $2}' | awk '{print $1}' | tr -d ',')
        
        echo "  RX packets: ${RX_PKT:-0}"
        echo "  TX packets: ${TX_PKT:-0}"
        echo "  Heartbeats: ${HEARTBEATS:-0}"
        
        # Check for suspicious TX socket count
        TX_SOCKETS=$(echo "$LAST_STATS" | grep "AF_XDP:" | awk -F'TX=' '{print $2}' | awk '{print $1}')
        if [ -n "$TX_SOCKETS" ] && [ "$TX_SOCKETS" -gt 100 ]; then
            echo ""
            echo "⚠️  WARNING: Suspicious TX socket count: $TX_SOCKETS"
            echo "    This might indicate a memory corruption issue"
        fi
    else
        echo "  (No statistics found in log)"
    fi
    
    # Check for errors
    ERROR_COUNT=$(grep -c "ERROR\|error\|failed" /tmp/rswitch-voqd.log 2>/dev/null || echo 0)
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo ""
        echo "⚠️  Found $ERROR_COUNT error messages in log"
        echo "  Recent errors:"
        grep -i "ERROR\|error\|failed" /tmp/rswitch-voqd.log | tail -5 | sed 's/^/    /'
    fi
fi

echo ""
echo "========================================"

# Exit with success if VOQd is running
if pgrep -x "rswitch-voqd" > /dev/null; then
    echo "✓ VOQd is healthy"
    exit 0
else
    echo "✗ VOQd is not running"
    exit 1
fi
