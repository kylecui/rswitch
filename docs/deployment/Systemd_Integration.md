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
