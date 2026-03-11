# rSwitch Monitoring Setup

This directory contains pre-built Grafana dashboards and configuration for monitoring rSwitch with Prometheus.

## Overview

rSwitch includes a Prometheus exporter (`rswitch-prometheus`) that exposes metrics on port 9417. These dashboards provide comprehensive visibility into switch operations, QoS, security, and VLAN statistics.

## Available Dashboards

### 1. rSwitch Overview (`rswitch-overview.json`)
System-wide monitoring dashboard:
- **System Metrics**: Uptime, interface count, MAC table entries, VLAN count
- **Port Statistics**: Per-port throughput (packets/sec and bytes/sec)
- **Error Tracking**: Port drops and errors by interface
- **Module Overview**: Processing statistics for all modules

### 2. rSwitch QoS & VOQd (`rswitch-qos.json`)
Quality of Service and Virtual Output Queue monitoring:
- **VOQd Mode**: Current operating mode (bypass/shadow/active)
- **Queue Depth**: Per-port and per-priority queue utilization
- **QoS Statistics**: Module processing, forwarding, and drop rates
- **Rate Limiting**: Policer and rate limiter drop tracking

### 3. rSwitch Security (`rswitch-security.json`)
Security module monitoring:
- **ACL Activity**: Access control list processing and drops
- **Source Guard**: IP/MAC source verification tracking
- **DHCP Snooping**: DHCP packet inspection statistics
- **Connection Tracking**: Conntrack module activity
- **Aggregate Metrics**: Total blocked packets across all security modules

### 4. rSwitch VLAN (`rswitch-vlan.json`)
VLAN-specific statistics:
- **VLAN Count**: Active VLANs in the system
- **VLAN Processing**: Module throughput and bandwidth
- **Drop Analysis**: VLAN and egress VLAN drops
- **Module Comparison**: Statistics for both ingress and egress VLAN modules

## Quick Start

### Prerequisites

- **Prometheus** (v2.30+)
- **Grafana** (v9.0+)
- **rSwitch** with Prometheus exporter enabled

### Step 1: Configure Prometheus

Add the following scrape configuration to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'rswitch'
    static_configs:
      - targets: ['localhost:9417']
        labels:
          instance: 'rswitch-main'
    scrape_interval: 10s
    scrape_timeout: 5s
```

Reload Prometheus configuration:
```bash
# Using systemd
sudo systemctl reload prometheus

# Using docker
docker kill -s HUP prometheus

# Using prometheus CLI
curl -X POST http://localhost:9090/-/reload
```

### Step 2: Start rSwitch Prometheus Exporter

```bash
# Start the exporter (usually runs alongside rSwitch daemon)
sudo rswitch-prometheus --port 9417
```

Verify metrics are being exported:
```bash
curl http://localhost:9417/metrics
```

### Step 3: Import Dashboards to Grafana

#### Option A: Grafana UI (Manual Import)

1. Open Grafana web interface (default: http://localhost:3000)
2. Navigate to **Dashboards** → **Import**
3. Click **Upload JSON file**
4. Select one of the dashboard JSON files from `rswitch/monitoring/grafana/`
5. Select your Prometheus data source
6. Click **Import**
7. Repeat for all four dashboards

#### Option B: Provisioning (Automated)

1. Copy dashboard files to Grafana provisioning directory:
```bash
sudo mkdir -p /etc/grafana/provisioning/dashboards/rswitch
sudo cp rswitch/monitoring/grafana/*.json /etc/grafana/provisioning/dashboards/rswitch/
```

2. Create provisioning configuration:
```bash
sudo cat > /etc/grafana/provisioning/dashboards/rswitch.yaml <<EOF
apiVersion: 1

providers:
  - name: 'rSwitch'
    orgId: 1
    folder: 'rSwitch'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards/rswitch
      foldersFromFilesStructure: false
EOF
```

3. Create Prometheus data source provisioning:
```bash
sudo cat > /etc/grafana/provisioning/datasources/prometheus.yaml <<EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: true
EOF
```

4. Restart Grafana:
```bash
sudo systemctl restart grafana-server
```

#### Option C: Docker Compose

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    network_mode: host

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards/rswitch
      - ./grafana/provisioning:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false

volumes:
  prometheus_data:
  grafana_data:
```

## Dashboard Variables

All dashboards support the following template variables:

- **`$interface`**: Filter by network interface (available in Overview dashboard)
- **`$port`**: Filter by port number (available in QoS dashboard)
- **`$priority`**: Filter by QoS priority (available in QoS dashboard)
- **`$interval`**: Adjust rate calculation interval (default: 1m)

## Metrics Reference

### Port Metrics
- `rswitch_port_rx_packets_total{interface="ethN"}` - Received packets
- `rswitch_port_tx_packets_total{interface="ethN"}` - Transmitted packets
- `rswitch_port_rx_bytes_total{interface="ethN"}` - Received bytes
- `rswitch_port_tx_bytes_total{interface="ethN"}` - Transmitted bytes
- `rswitch_port_drop_packets_total{interface="ethN",direction="rx|tx"}` - Dropped packets
- `rswitch_port_error_packets_total{interface="ethN",direction="rx|tx"}` - Error packets

### Module Metrics
- `rswitch_module_packets_processed_total{module="name"}` - Packets processed
- `rswitch_module_packets_forwarded_total{module="name"}` - Packets forwarded
- `rswitch_module_packets_dropped_total{module="name"}` - Packets dropped
- `rswitch_module_bytes_processed_total{module="name"}` - Bytes processed

### VOQd Metrics
- `rswitch_voqd_mode` - Current VOQd mode (0=bypass, 1=shadow, 2=active)
- `rswitch_voqd_queue_depth{port="N",priority="N"}` - Queue depth per port/priority

### System Metrics
- `rswitch_mac_table_entries` - Current MAC address table size
- `rswitch_vlan_count` - Number of configured VLANs
- `rswitch_uptime_seconds` - System uptime in seconds
- `rswitch_info{version="X.Y.Z"}` - Version information

## Alerting

Example Prometheus alerting rules for rSwitch:

```yaml
groups:
  - name: rswitch_alerts
    interval: 30s
    rules:
      # High drop rate
      - alert: HighPacketDropRate
        expr: rate(rswitch_port_drop_packets_total[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet drop rate on {{ $labels.interface }}"
          description: "Interface {{ $labels.interface }} is dropping {{ $value }} packets/sec"

      # MAC table full
      - alert: MacTableNearFull
        expr: rswitch_mac_table_entries > 8000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "MAC table filling up"
          description: "MAC table has {{ $value }} entries (threshold: 8000)"

      # Queue depth critical
      - alert: VoqdQueueDepthHigh
        expr: rswitch_voqd_queue_depth > 8000
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "VOQd queue depth critical"
          description: "Port {{ $labels.port }} priority {{ $labels.priority }} queue depth: {{ $value }}"

      # Security drops
      - alert: SecurityModuleHighDrops
        expr: rate(rswitch_module_packets_dropped_total{module=~"acl|source_guard|dhcp_snooping"}[5m]) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High security drops in {{ $labels.module }}"
          description: "Security module {{ $labels.module }} dropping {{ $value }} packets/sec"
```

## Troubleshooting

### Metrics Not Showing Up

1. **Check exporter is running:**
   ```bash
   curl http://localhost:9417/metrics
   ```

2. **Verify Prometheus scraping:**
   ```bash
   # Check targets in Prometheus UI
   http://localhost:9090/targets
   ```

3. **Check Prometheus logs:**
   ```bash
   journalctl -u prometheus -f
   ```

### Dashboard Shows No Data

1. **Verify data source connection in Grafana:**
   - Navigate to Configuration → Data Sources
   - Test the Prometheus connection

2. **Check time range:**
   - Ensure the dashboard time range includes active data
   - Try "Last 5 minutes" or "Last 15 minutes"

3. **Verify metrics exist:**
   - Open Grafana Explore
   - Run query: `rswitch_uptime_seconds`

### Permission Issues

```bash
# Ensure Grafana can read dashboard files
sudo chown -R grafana:grafana /etc/grafana/provisioning/dashboards/rswitch/
sudo chmod 644 /etc/grafana/provisioning/dashboards/rswitch/*.json
```

## Customization

### Adding Custom Panels

1. Open any dashboard in Grafana
2. Click **Add panel** → **Add a new panel**
3. Use PromQL to query rSwitch metrics
4. Save the dashboard
5. Export JSON via dashboard settings → JSON Model

### Adjusting Thresholds

Color thresholds and alert levels can be adjusted in dashboard panel settings:
1. Edit panel → Field tab → Thresholds
2. Modify values and colors as needed

## Performance Considerations

- **Scrape Interval**: Default 10s is recommended. Lower values increase load on both Prometheus and rSwitch.
- **Retention**: Configure Prometheus retention based on storage capacity:
  ```bash
  --storage.tsdb.retention.time=30d
  --storage.tsdb.retention.size=50GB
  ```
- **Query Optimization**: Use recording rules for frequently accessed metrics

## Support

For issues or questions:
- Check rSwitch documentation
- Review Prometheus and Grafana logs
- Verify network connectivity between components

## License

These dashboards are distributed under the same license as rSwitch.
