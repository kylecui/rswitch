# Security Hardening Guide

Production security hardening for rSwitch deployments. Covers OS-level, application-level, and BPF-specific security measures.

## Overview

rSwitch runs with root privileges to load XDP/BPF programs and access raw network interfaces. This guide documents how to minimize the attack surface while maintaining full functionality.

### Security Audit Status

All 20 findings from the [Security Audit](../../SECURITY_AUDIT.md) have been fixed, including:

- **C-1**: Command injection via `system()`/`popen()` → replaced with `fork()`+`execvp()`
- **C-2**: Plaintext credentials → SHA-256 hashed passwords with `constant_time_compare()`
- **C-3**: CORS wildcard on auth endpoints → configurable origin restriction

## OS Hardening

### Kernel Configuration

```bash
# Verify kernel version (5.8+ required, 5.15+ for management portal)
uname -r

# Recommended sysctl settings
cat >> /etc/sysctl.d/99-rswitch.conf <<EOF
# Disable IP forwarding in Linux stack (rSwitch handles forwarding in XDP)
net.ipv4.ip_forward = 0

# Harden network stack
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# BPF hardening
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
EOF

sudo sysctl --system
```

| Setting | Value | Purpose |
|---------|-------|---------|
| `unprivileged_bpf_disabled=1` | Prevent non-root BPF program loading | Only root (rSwitch) can load BPF |
| `bpf_jit_harden=2` | Full JIT hardening | Mitigates JIT spray attacks |
| `ip_forward=0` | Disable kernel IP forwarding | rSwitch forwards in XDP, not the kernel stack |

### Filesystem Permissions

```bash
# Restrict rSwitch installation directory
sudo chmod 750 /opt/rswitch/
sudo chmod 750 /opt/rswitch/build/
sudo chmod 640 /opt/rswitch/etc/profiles/*.yaml

# Restrict config files containing credentials
sudo chmod 600 /etc/rswitch/rswitch.env

# BPF pin directory (must be accessible by rswitch services)
sudo chmod 700 /sys/fs/bpf/
```

### User and Group Isolation

While rSwitch requires root for BPF operations, limit access to rSwitch management:

```bash
# Create rswitch group for operators
sudo groupadd rswitch

# Only rswitch group members can read configs
sudo chgrp -R rswitch /opt/rswitch/etc/
sudo chmod 750 /opt/rswitch/etc/

# CLI tools need root but restrict who can sudo
# /etc/sudoers.d/rswitch
%rswitch ALL=(root) NOPASSWD: /opt/rswitch/build/rswitchctl, \
    /opt/rswitch/build/rsvlanctl, \
    /opt/rswitch/build/rsaclctl, \
    /opt/rswitch/build/rsroutectl, \
    /opt/rswitch/build/rsqosctl, \
    /opt/rswitch/build/rsvoqctl, \
    /opt/rswitch/build/rsdiag
```

## Management Portal Security

### Authentication Configuration

The management portal (`rswitch-mgmtd`) supports SHA-256 hashed passwords:

```yaml
# Profile YAML
management:
  auth_enabled: true
  auth_user: admin
  auth_password: "<your-password>"  # Hashed to SHA-256 at startup
```

On startup, `mgmtd` hashes the plaintext password with SHA-256 and overwrites the original in memory with `explicit_bzero()`. Password verification uses `constant_time_compare()` to prevent timing side-channel attacks.

### CORS Configuration

**Never** use `Access-Control-Allow-Origin: *` in production (this was fixed in C-3):

```yaml
management:
  cors_origin: "https://your-management-host.example.com"
```

When `cors_origin` is set, the response includes:
- `Access-Control-Allow-Origin: <configured-origin>`
- `Access-Control-Allow-Credentials: true`

When unset, the CORS header is omitted entirely.

### Namespace Isolation

The management portal runs in a dedicated Linux network namespace (`rswitch-mgmt`):

```
Default Namespace (Data Plane)
  └── rswitch-mgmt namespace
       └── rswitch-mgmtd :8080
```

This ensures:
- Management traffic cannot interfere with data plane forwarding
- Portal is only reachable from the switch network (not the host's management NIC)
- `mgmtd` process is network-isolated from host services

Verify namespace isolation:

```bash
# Confirm namespace exists
ip netns list | grep rswitch-mgmt

# Confirm mgmtd runs in namespace
sudo ip netns exec rswitch-mgmt ss -tlnp | grep 8080
```

### Session Security

- Sessions use HTTP cookies (set by `POST /api/auth/login`)
- All API endpoints except `/api/auth/login` require a valid session cookie
- Session invalidation via `POST /api/auth/logout`

**Recommendation**: Deploy a reverse proxy (nginx, HAProxy) in front of `mgmtd` for TLS termination:

```nginx
server {
    listen 443 ssl;
    server_name rswitch-mgmt.example.com;

    ssl_certificate     /etc/ssl/certs/rswitch.crt;
    ssl_certificate_key /etc/ssl/private/rswitch.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## BPF Map Security

### Pinned Map Access Control

BPF maps are pinned at `/sys/fs/bpf/rs_*`. Restrict access:

```bash
# Only root can access BPF maps
sudo chmod 700 /sys/fs/bpf/
```

Key maps that contain sensitive data:

| Map | Content | Risk if Exposed |
|-----|---------|----------------|
| `rs_acl_map` | ACL rules | Policy bypass |
| `rs_port_config_map` | Port configuration | Misconfiguration |
| `rs_vlan_map` | VLAN membership | VLAN hopping |
| `rs_route_map` | Routing table | Traffic hijacking |

### Map Size Limits

BPF maps consume locked memory. The systemd service file sets `LimitMEMLOCK=infinity`. To set a specific cap:

```ini
# /etc/systemd/system/rswitch.service.d/limits.conf
[Service]
LimitMEMLOCK=512M
```

## Service Hardening

### Systemd Security Options

Add security directives to the rSwitch service file:

```ini
[Service]
# Restrict capabilities (rSwitch needs these specific caps)
# Note: Full root is currently required for BPF operations
# Future: CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN

# Restrict filesystem access
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf /tmp/rswitch-voqd.log /var/log/rswitch
ProtectHome=yes
PrivateTmp=yes

# Restrict system calls
SystemCallFilter=@system-service @network-io @io-event
SystemCallFilter=~@privileged @resources

# No new privileges after exec
NoNewPrivileges=yes

# Restrict namespace creation (rSwitch creates network namespaces for mgmtd)
# RestrictNamespaces=~user pid cgroup ipc — keep 'net' allowed
```

> **Caution**: Some systemd hardening options may conflict with BPF operations. Test thoroughly before applying in production. Start with `ProtectHome=yes` and `PrivateTmp=yes` which are safe.

### Network Exposure

rSwitch binds to these ports:

| Service | Port | Interface | Purpose |
|---------|------|-----------|---------|
| `rswitch-mgmtd` | 8080 | mgmt0 (namespace) | Management portal |
| `rswitch-prometheus` | 9417 | localhost | Prometheus metrics |

Use firewall rules to restrict access:

```bash
# Only allow Prometheus scraping from monitoring server
sudo iptables -A INPUT -p tcp --dport 9417 -s <prometheus-server-ip> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9417 -j DROP
```

## Audit and Compliance

### Logging for Audit

Configure persistent logging:

```bash
# Journal persistence
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal

# Verify journal is persistent
journalctl --disk-usage
```

Key log sources:

| Source | Command | Content |
|--------|---------|---------|
| Service lifecycle | `journalctl -u rswitch` | Start/stop/restart events |
| Management API | `journalctl -u rswitch-mgmtd` | Login attempts, API calls |
| VOQd state changes | `journalctl -u rswitch-voqd` | Mode transitions, degradations |
| BPF events | `sudo ./build/rswitch-events` | Real-time pipeline events |
| Diagnostics | `sudo ./build/rsdiag start` | L2 fentry/fexit trace events |

### Security Checklist

| Item | Check | Command |
|------|-------|---------|
| Unprivileged BPF disabled | `kernel.unprivileged_bpf_disabled = 1` | `sysctl kernel.unprivileged_bpf_disabled` |
| JIT hardening enabled | `net.core.bpf_jit_harden = 2` | `sysctl net.core.bpf_jit_harden` |
| Portal auth enabled | `auth_enabled: true` in profile | Check profile YAML |
| CORS restricted | `cors_origin` set to specific host | Check profile YAML |
| Namespace isolation active | mgmtd in `rswitch-mgmt` namespace | `ip netns list` |
| BPF pins restricted | `/sys/fs/bpf/` mode 700 | `ls -la /sys/fs/bpf/` |
| Config files restricted | Profile YAML mode 640 | `ls -la /opt/rswitch/etc/profiles/` |
| No plaintext passwords | Passwords hashed at startup | Verified by design (C-2 fix) |

## Incident Response

### Suspected Compromise

```bash
# 1. Isolate: stop rSwitch to halt all forwarding
sudo systemctl stop rswitch

# 2. Preserve evidence: dump current state
sudo bpftool prog list > /tmp/incident-progs.txt 2>/dev/null
sudo bpftool map list > /tmp/incident-maps.txt 2>/dev/null
sudo journalctl -u 'rswitch*' --since "24 hours ago" > /tmp/incident-logs.txt

# 3. Check for unauthorized BPF programs
sudo bpftool prog list | grep -v rswitch
# Any unexpected programs indicate potential compromise

# 4. Clean up
sudo rm -rf /sys/fs/bpf/rs_*

# 5. Rebuild from known-good source and redeploy
```

### Unauthorized Access to Management Portal

```bash
# Check login attempts in mgmtd logs
sudo journalctl -u rswitch-mgmtd | grep -i "auth\|login\|unauthorized"

# Rotate credentials: update profile and restart
# Edit profile YAML with new auth_password
sudo systemctl restart rswitch-mgmtd
```

## See Also

- [Security Audit](../../SECURITY_AUDIT.md) — full audit findings and fixes
- [Management Portal](Management_Portal.md) — portal architecture and API
- [Systemd Integration](Systemd_Integration.md) — service configuration
- [Operations Guide](../operations/Operations_Guide.md) — day-to-day operations
