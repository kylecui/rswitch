# Systemd Integration

Run rSwitch as a system service for production deployments.

## Service File

Create `/etc/systemd/system/rswitch.service`:

```ini
[Unit]
Description=rSwitch Reconfigurable Network Switch
Documentation=https://github.com/your-org/rswitch
After=network-online.target rswitch-nic.service
Wants=network-online.target
Requires=rswitch-nic.service

[Service]
Type=simple
ExecStart=/opt/rswitch/build/rswitch_loader \
    --profile /opt/rswitch/etc/profiles/l2.yaml \
    --ifaces ens34,ens35,ens36
ExecStop=/bin/kill -SIGTERM $MAINPID
ExecStopPost=/bin/rm -rf /sys/fs/bpf/rs_*

# Restart policy
Restart=on-failure
RestartSec=5

# Security
User=root
LimitMEMLOCK=infinity
LimitNOFILE=65536

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rswitch

[Install]
WantedBy=multi-user.target
```

## NIC Pre-Configuration Service

Create `/etc/systemd/system/rswitch-nic.service` to configure NICs before rSwitch starts:

```ini
[Unit]
Description=rSwitch NIC Configuration
Before=rswitch.service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -K ens34 rx-vlan-offload off
ExecStart=/usr/sbin/ethtool -K ens35 rx-vlan-offload off
ExecStart=/usr/sbin/ethtool -K ens36 rx-vlan-offload off
ExecStart=/usr/sbin/ip link set dev ens34 promisc on
ExecStart=/usr/sbin/ip link set dev ens35 promisc on
ExecStart=/usr/sbin/ip link set dev ens36 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

## Installation Steps

### 1. Deploy Binaries

```bash
sudo mkdir -p /opt/rswitch
sudo cp -r build/ /opt/rswitch/build/
sudo cp -r etc/ /opt/rswitch/etc/
sudo cp -r scripts/ /opt/rswitch/scripts/
```

### 2. Install Service Files

```bash
sudo cp rswitch.service /etc/systemd/system/
sudo cp rswitch-nic.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 3. Enable and Start

```bash
# Enable at boot
sudo systemctl enable rswitch-nic.service
sudo systemctl enable rswitch.service

# Start now
sudo systemctl start rswitch.service
```

### 4. Verify

```bash
sudo systemctl status rswitch.service
sudo journalctl -u rswitch -f
```

## Managing the Service

```bash
# Start / stop / restart
sudo systemctl start rswitch
sudo systemctl stop rswitch
sudo systemctl restart rswitch

# View logs
sudo journalctl -u rswitch -f              # Follow logs
sudo journalctl -u rswitch --since "1h ago" # Last hour
sudo journalctl -u rswitch -n 100           # Last 100 lines

# Check status
sudo systemctl status rswitch
```

## Changing Profiles

To switch profiles without editing the service file, use an environment file:

### 1. Create Environment File

```bash
# /etc/rswitch/rswitch.env
RSWITCH_PROFILE=/opt/rswitch/etc/profiles/l3-qos-voqd-test.yaml
RSWITCH_IFACES=ens34,ens35,ens36,ens37
```

### 2. Update Service File

```ini
[Service]
EnvironmentFile=/etc/rswitch/rswitch.env
ExecStart=/opt/rswitch/build/rswitch_loader \
    --profile ${RSWITCH_PROFILE} \
    --ifaces ${RSWITCH_IFACES}
```

### 3. Reload and Restart

```bash
sudo systemctl daemon-reload
sudo systemctl restart rswitch
```

## Resource Limits

rSwitch uses BPF maps that require locked memory. The service file sets `LimitMEMLOCK=infinity` to prevent map creation failures.

If running without systemd, set the limit manually:

```bash
ulimit -l unlimited
```

Or in `/etc/security/limits.conf`:
```
root    soft    memlock    unlimited
root    hard    memlock    unlimited
```

## Watchdog (Optional)

For critical deployments, add a watchdog to automatically restart rSwitch if it becomes unresponsive:

```ini
[Service]
WatchdogSec=30
# rswitch_loader must call sd_notify(0, "WATCHDOG=1") periodically
```

> **Note**: Watchdog integration requires rswitch_loader to support systemd notifications (currently not implemented — planned feature).

## Log Rotation

systemd journal handles log rotation automatically. To configure retention:

```bash
# /etc/systemd/journald.conf
[Journal]
SystemMaxUse=500M
MaxRetentionSec=30d
```

For VOQd logs (written to `/tmp/rswitch-voqd.log`), add logrotate:

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

## Multiple Instances

To run multiple rSwitch instances on different interface sets:

```bash
# Copy and customize service files
sudo cp /etc/systemd/system/rswitch.service /etc/systemd/system/rswitch-lan.service
sudo cp /etc/systemd/system/rswitch.service /etc/systemd/system/rswitch-wan.service

# Edit each with different profiles and interfaces
sudo systemctl enable rswitch-lan rswitch-wan
```

> **Important**: Each instance must use different interfaces and non-conflicting BPF map names.

## See Also

- [Installation](Installation.md) — build and install
- [NIC Configuration](NIC_Configuration.md) — NIC setup
- [Configuration](Configuration.md) — YAML profile reference

---

## Downstream Integration

Projects that build on top of rSwitch (e.g., network appliances, traffic analyzers) need their services to start **after** the rSwitch pipeline is fully loaded. This section covers dependency ordering, readiness detection, and graceful shutdown.

### Service Dependency Ordering

Your downstream service should declare a dependency on `rswitch.service`:

```ini
[Unit]
Description=My Downstream Network Service
After=rswitch.service
Requires=rswitch.service

[Service]
Type=simple
ExecStartPre=/bin/sh -c 'test -e /sys/fs/bpf/rs_ctx_map'
ExecStart=/usr/local/bin/my-service
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Key directives:

| Directive | Purpose |
|-----------|---------|
| `After=rswitch.service` | Start only after rSwitch has started |
| `Requires=rswitch.service` | If rSwitch fails to start, don't start this service either |
| `ExecStartPre=...test -e /sys/fs/bpf/rs_ctx_map` | Verify BPF pipeline is actually loaded (pin file exists) |

### Readiness Detection

Currently, rSwitch uses `Type=forking` — systemd considers the service ready once the init script exits. This does **not** guarantee the BPF pipeline is fully loaded. To handle this:

**Option 1: Pin file check (recommended)**

Add an `ExecStartPre` that polls for the presence of a core BPF map pin file:

```bash
#!/bin/bash
# /usr/local/bin/wait-for-rswitch.sh
for i in $(seq 1 30); do
    if [ -e /sys/fs/bpf/rs_ctx_map ] && [ -e /sys/fs/bpf/rs_progs ]; then
        exit 0
    fi
    sleep 1
done
echo "rSwitch pipeline not ready after 30s" >&2
exit 1
```

```ini
[Service]
ExecStartPre=/usr/local/bin/wait-for-rswitch.sh
```

**Option 2: sd_notify (planned)**

A future release will add `Type=notify` support with `sd_notify(READY=1)` after pipeline load, eliminating the need for pin file polling. See [Platform Backlog](../backlog/platform-backlog.md).

### Startup Sequence

```
systemd
  └─ rswitch-nic.service     (Type=oneshot) — configure NIC offloads
       └─ rswitch.service     (Type=forking) — load BPF pipeline
            ├─ BPF programs loaded and attached
            ├─ Pin files created (/sys/fs/bpf/rs_*)
            └─ your-service.service — downstream starts after pin files exist
```

### Graceful Shutdown Ordering

Systemd reverses the startup order on shutdown. With `Requires=rswitch.service`, your downstream service stops **before** rSwitch tears down the pipeline:

```
Shutdown:
  1. your-service.service stops (SIGTERM → your process)
  2. rswitch.service stops (unpin maps, detach XDP)
  3. rswitch-nic.service stops (no-op, oneshot)
```

If your service reads BPF maps during shutdown (e.g., flushing statistics), ensure your shutdown handler completes before systemd's `TimeoutStopSec` (default 90s).

### Interface Configuration Best Practice

Instead of hardcoding interface names in service files, use an `EnvironmentFile`:

```bash
# /etc/rswitch/interfaces.conf
RSWITCH_IFACES=ens34,ens35,ens36,ens37
```

```ini
[Service]
EnvironmentFile=/etc/rswitch/interfaces.conf
ExecStart=/opt/rswitch/scripts/rswitch-init.sh start
```

This allows changing interfaces without editing service files or running `systemctl daemon-reload`.

### Common Pitfalls

| Issue | Cause | Fix |
|-------|-------|-----|
| Downstream starts before pipeline is loaded | rSwitch `Type=forking` returns before BPF load completes | Use `ExecStartPre` pin file check |
| "No such file" errors on BPF map access | Service started before pin files were created | Add pin file readiness check |
| Downstream keeps running after rSwitch stops | Missing `Requires=` dependency | Add `Requires=rswitch.service` |
| Interface names change across reboots | Hardcoded names in service files | Use `EnvironmentFile` for interface config |

## FHS Install Layout

The installer supports an FHS-compatible layout via `--fhs`:

```bash
sudo bash install.sh --fhs
```

| Component | Default (`/opt/rswitch`) | FHS (`--fhs`) |
|-----------|--------------------------|---------------|
| Binaries | `/opt/rswitch/build/` | `/usr/lib/rswitch/build/` |
| Config | `/opt/rswitch/etc/` | `/etc/rswitch/` |
| Docs | `/opt/rswitch/docs/` | `/usr/share/doc/rswitch/` |
| Logs | `/var/log/rswitch/` | `/var/log/rswitch/` |
| Systemd units | `/etc/systemd/system/` | `/etc/systemd/system/` |

The FHS layout is recommended for distribution packaging.
