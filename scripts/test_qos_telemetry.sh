#!/bin/bash
# Test script for QoS and Telemetry functionality

echo "=== rSwitch QoS and Telemetry Test ==="
echo 

echo "1. Testing Telemetry Exporter..."
echo "Starting Prometheus telemetry on port 9090 (background)..."
sudo ./build/rswitch-telemetry -p 127.0.0.1:9090 -i 5 &
TELEMETRY_PID=$!
sleep 2

echo "Fetching sample metrics..."
curl -s http://127.0.0.1:9090/metrics | head -20

echo "Stopping telemetry exporter..."
sudo kill $TELEMETRY_PID 2>/dev/null
echo

echo "2. Testing Event Consumer..."
echo "This would normally consume events from BPF ringbuf:"
sudo ./build/rswitch-events --help
echo

echo "3. Testing QoS Configuration..."
if [ -f /sys/fs/bpf/qos_config_map ]; then
    echo "QoS maps available - module is loaded"
    # Example QoS configuration would go here
    echo "TODO: Add QoS test rules when module is integrated into loader"
else
    echo "QoS maps not found - module not yet loaded"
    echo "To enable QoS:"
    echo "  1. Load rSwitch with qos-enabled profile"
    echo "  2. Use rsqosctl to configure rules"
fi
echo

echo "4. QoS Module Information:"
echo "Location: ./build/bpf/qos.bpf.o"
ls -la ./build/bpf/qos.bpf.o
echo

echo "5. Sample QoS Commands (when active):"
echo "  # Classify SSH as critical"
echo "  rsqosctl add-class --proto tcp --dport 22 --priority critical"
echo 
echo "  # Rate limit background traffic"
echo "  rsqosctl set-rate-limit --priority low --rate 10M --burst 1M"
echo
echo "  # Enable DSCP remarking"
echo "  rsqosctl set-dscp --priority critical --dscp 46"
echo
echo "  # Set congestion threshold"
echo "  rsqosctl set-congestion --threshold 75"
echo

echo "6. Telemetry Integration Points:"
echo "  - Prometheus: http://localhost:9090/metrics"
echo "  - Events: BPF ringbuf → rswitch-events → JSON/logs"
echo "  - Stats: Per-CPU BPF maps → aggregated metrics"
echo "  - VOQd: State monitoring for adaptive QoS"
echo

echo "=== Next Steps ==="
echo "1. Integrate QoS module into loader (add to profile loading)"
echo "2. Add ringbuf event emission from modules" 
echo "3. Configure Grafana dashboard for metrics visualization"
echo "4. Implement rate limiting policies based on network conditions"
echo "5. Connect to VOQd for sophisticated queue management"
echo