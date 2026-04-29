# Operations Guide

Day-to-day operational procedures for running rSwitch in production.

## Daily Health Checks

### Quick Status Check

```bash
# Service status
sudo systemctl status rswitch rswitch-mgmtd rswitch-voqd

# BPF pipeline loaded
ls /sys/fs/bpf/rs_* | head -5

# Port statistics (packet flow confirms forwarding)
sudo ./build/rswitchctl show-stats

# VOQd state (if QoS enabled)
sudo bpftool map dump name voqd_state_map
```

### Automated Health Script

```bash
#!/bin/bash
# /opt/rswitch/scripts/health-check.sh
set -euo pipefail

ERRORS=0

# Check core service
if ! systemctl is-active --quiet rswitch; then
    echo "CRITICAL: rswitch.service not running"
    ERRORS=$((ERRORS + 1))
fi

# Check BPF maps pinned
if [ ! -e /sys/fs/bpf/rs_ctx_map ]; then
    echo "CRITICAL: BPF pipeline not loaded (rs_ctx_map missing)"
    ERRORS=$((ERRORS + 1))
fi

# Check management portal (if enabled)
if systemctl is-enabled --quiet rswitch-mgmtd 2>/dev/null; then
    if ! systemctl is-active --quiet rswitch-mgmtd; then
        echo "WARNING: rswitch-mgmtd not running"
        ERRORS=$((ERRORS + 1))
    fi
fi

# Check VOQd (if enabled)
if systemctl is-enabled --quiet rswitch-voqd 2>/dev/null; then
    STATE=$(sudo bpftool map dump name voqd_state_map 2>/dev/null | grep -o '"mode":[0-9]' | cut -d: -f2)
    if [ "$STATE" = "0" ] && [ "$(cat /etc/rswitch/expected_voqd_mode 2>/dev/null)" != "bypass" ]; then
        echo "WARNING: VOQd in BYPASS mode (expected ACTIVE)"
        ERRORS=$((ERRORS + 1))
    fi
fi

if [ $ERRORS -eq 0 ]; then
    echo "OK: All checks passed"
fi
exit $ERRORS
```

## Log Management

### Journal Logs

rSwitch services log to systemd journal:

```bash
# Follow all rSwitch logs
sudo journalctl -u 'rswitch*' -f

# Last hour, specific service
sudo journalctl -u rswitch --since "1 hour ago"

# Errors only
sudo journalctl -u rswitch -p err

# Boot-persistent logs (ensure Storage=persistent in journald.conf)
sudo journalctl -u rswitch -b
```

### VOQd Log File

VOQd writes statistics to `/tmp/rswitch-voqd.log` when started with `-S <interval>`:

```bash
tail -f /tmp/rswitch-voqd.log
```

Configure log rotation:

```bash
# /etc/logrotate.d/rswitch-voqd
/tmp/rswitch-voqd.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        systemctl reload rswitch 2>/dev/null || true
    endscript
}
```

### Journal Retention

```bash
# /etc/systemd/journald.conf
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=30d
```

After editing, restart journald:

```bash
sudo systemctl restart systemd-journald
```

## Backup and Recovery

### What to Back Up

| Item | Path | Frequency |
|------|------|-----------|
| Profile configs | `/opt/rswitch/etc/profiles/` or `/etc/rswitch/` | On change |
| Environment files | `/etc/rswitch/rswitch.env` | On change |
| Systemd overrides | `/etc/systemd/system/rswitch*.service` | On change |
| Logrotate config | `/etc/logrotate.d/rswitch-voqd` | On change |
| Prometheus alert rules | Prometheus config directory | On change |
| Grafana dashboards | `/etc/grafana/provisioning/dashboards/rswitch/` | On change |

> **Note**: BPF maps (`/sys/fs/bpf/rs_*`) are ephemeral and recreated on each start. Do not back them up.

### Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/rswitch/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Profiles and config
cp -a /opt/rswitch/etc/ "$BACKUP_DIR/etc/"
cp -a /etc/rswitch/ "$BACKUP_DIR/etc-rswitch/" 2>/dev/null || true

# Systemd units
cp /etc/systemd/system/rswitch*.service "$BACKUP_DIR/" 2>/dev/null || true

# Current running state snapshot
sudo ./build/rswitchctl show-pipeline > "$BACKUP_DIR/pipeline-state.txt" 2>/dev/null || true
sudo ./build/rsvlanctl show > "$BACKUP_DIR/vlan-state.txt" 2>/dev/null || true
sudo ./build/rsaclctl show > "$BACKUP_DIR/acl-state.txt" 2>/dev/null || true

echo "Backup saved to $BACKUP_DIR"
```

### Recovery

1. Reinstall rSwitch binaries (see [Installation](../deployment/Installation.md))
2. Restore profile configs to `/opt/rswitch/etc/profiles/`
3. Restore systemd service files and `daemon-reload`
4. Start services: `sudo systemctl start rswitch`
5. Verify pipeline: `sudo ./build/rswitchctl show-pipeline`

## Upgrade Procedures

### In-Place Upgrade

```bash
# 1. Build new version
cd /path/to/rswitch-source
git pull
make clean && make vmlinux && make

# 2. Stop services
sudo systemctl stop rswitch

# 3. Deploy new binaries
sudo cp -a build/ /opt/rswitch/build/

# 4. Compare profile changes (new version may add fields)
diff /opt/rswitch/etc/profiles/ etc/profiles/

# 5. Start services
sudo systemctl start rswitch

# 6. Verify
sudo systemctl status rswitch
sudo ./build/rswitchctl show-pipeline
sudo ./build/rswitchctl show-stats
```

### Hot-Reload (Module-Only Updates)

For module updates without full restart:

```bash
# Reload a single module
sudo ./scripts/hot-reload.sh reload <module_name>
```

Hot-reload performs atomic `prog_array` replacement — no XDP detach, no packet loss. See [Hot-Reload](../development/Hot_Reload.md).

### Rollback

```bash
# Stop current version
sudo systemctl stop rswitch

# Restore previous binaries from backup
sudo cp -a /var/backups/rswitch/<date>/build/ /opt/rswitch/build/

# Restore profiles if changed
sudo cp -a /var/backups/rswitch/<date>/etc/ /opt/rswitch/etc/

# Restart
sudo systemctl start rswitch
```

## Capacity Planning

### Resource Requirements

| Resource | Guideline |
|----------|-----------|
| **CPU** | 1 core per 10 Gbps throughput (XDP native mode); VOQd needs 1 dedicated core |
| **Memory** | ~200 MB base + BPF map memory (scales with RS_MAX_INTERFACES=256 and VLAN/ACL table sizes) |
| **Locked memory** | `LimitMEMLOCK=infinity` (systemd) or `ulimit -l unlimited` |
| **NIC queues** | 1+ per interface for basic XDP; multiple for AF_XDP zero-copy |
| **Kernel** | 5.8+ (5.15+ for management portal with BPF_F_BROADCAST) |

### Scaling Limits

| Parameter | Default | Max Tested |
|-----------|---------|------------|
| Interfaces | — | 256 (RS_MAX_INTERFACES) |
| VLANs | — | 4094 |
| ACL rules | — | 10,000+ |
| MAC table entries | 8,192 default | 65,536 |
| VOQd queue depth | 2,048 | 16,384 |

### Monitoring Thresholds

Set Prometheus alerts for:

| Metric | Warning | Critical |
|--------|---------|----------|
| `rswitch_port_drop_packets_total` rate | >100 pps for 5m | >1000 pps for 2m |
| `rswitch_mac_table_entries` | >8,000 | >12,000 |
| `rswitch_voqd_queue_depth` | >4,000 | >8,000 |
| Module drop rate | >500 pps | >5,000 pps |

See [Monitoring Setup](../../monitoring/README.md) for complete Prometheus/Grafana configuration.

## Alerting and Monitoring

### Prometheus Exporter

```bash
# Start exporter (usually via systemd)
sudo rswitch-prometheus --port 9417

# Verify metrics
curl -s http://localhost:9417/metrics | head -20
```

### Key Metrics to Watch

| Metric | What It Tells You |
|--------|-------------------|
| `rswitch_uptime_seconds` | Service stability — resets indicate restarts |
| `rswitch_port_rx_packets_total` / `tx` | Traffic flow per interface |
| `rswitch_port_drop_packets_total` | Packet loss — investigate if non-zero |
| `rswitch_module_packets_dropped_total` | Which module is dropping (ACL, VLAN, etc.) |
| `rswitch_voqd_mode` | VOQd operating state (0=bypass, 1=shadow, 2=active) |
| `rswitch_voqd_queue_depth` | QoS queue utilization |
| `rswitch_mac_table_entries` | MAC table growth — alert before overflow |
| `rswitch_vlan_count` | VLAN count tracking |

### Grafana Dashboards

Four pre-built dashboards in `monitoring/grafana/`:

| Dashboard | File | Focus |
|-----------|------|-------|
| Overview | `rswitch-overview.json` | System-wide health, port throughput, errors |
| QoS & VOQd | `rswitch-qos.json` | Queue depth, scheduling stats, rate limiting |
| Security | `rswitch-security.json` | ACL drops, source guard, DHCP snooping |
| VLAN | `rswitch-vlan.json` | VLAN processing, drop analysis |

## Disaster Recovery

### Complete Failure (Service Won't Start)

```bash
# 1. Check journal for errors
sudo journalctl -u rswitch -n 50 --no-pager

# 2. Check BPF maps are cleaned up from previous run
ls /sys/fs/bpf/rs_*
# If stale maps exist:
sudo rm -rf /sys/fs/bpf/rs_*

# 3. Verify NIC state
for iface in ens34 ens35 ens36; do
    ethtool -k $iface | grep rx-vlan-offload
    ip link show $iface | grep PROMISC
done

# 4. Try starting with verbose output
sudo /opt/rswitch/build/rswitch_loader \
    --profile /opt/rswitch/etc/profiles/l2.yaml \
    --ifaces ens34,ens35,ens36 \
    --verbose

# 5. If still failing, try minimal profile
sudo /opt/rswitch/build/rswitch_loader \
    --profile /opt/rswitch/etc/profiles/dumb.yaml \
    --ifaces ens34,ens35
```

### VOQd Auto-Degradation

VOQd automatically falls back to BYPASS mode when:
- Heartbeat timeout occurs
- Ringbuf overflows under load
- VOQd process crashes

Recovery is automatic when VOQd restarts. Monitor with:

```bash
sudo bpftool map dump name voqd_state_map
```

### Network Connectivity Lost

If rSwitch misconfiguration causes network isolation:

```bash
# 1. Stop rSwitch (removes XDP programs)
sudo systemctl stop rswitch

# 2. Clean up pinned maps
sudo rm -rf /sys/fs/bpf/rs_*

# 3. Verify NICs return to normal Linux stack
ip link show
ping <gateway>
```

## Scheduled Maintenance

### Maintenance Window Procedure

```bash
# 1. Notify monitoring (silence alerts)
# (Configure Prometheus alertmanager silence)

# 2. Graceful stop
sudo systemctl stop rswitch

# 3. Perform maintenance (kernel update, NIC firmware, etc.)
# ...

# 4. Start rSwitch
sudo systemctl start rswitch

# 5. Verify
sudo systemctl status rswitch
sudo ./build/rswitchctl show-stats
sudo ./build/rswitchctl show-pipeline

# 6. Un-silence alerts
```

### Kernel Updates

After a kernel update:

1. Verify kernel version is 5.8+: `uname -r`
2. Rebuild if needed (CO-RE binaries should work across versions): `make clean && make vmlinux && make`
3. Reboot and verify: `sudo systemctl status rswitch`

> CO-RE compatibility means most kernel updates do not require rebuilds. Rebuild only if BPF load failures occur after the update.

## See Also

- [Systemd Integration](../deployment/Systemd_Integration.md) — service configuration
- [Troubleshooting](../usage/Troubleshooting.md) — diagnostic procedures
- [Performance Tuning](Performance_Tuning.md) — optimization guide
- [Monitoring Setup](../../monitoring/README.md) — Prometheus and Grafana
