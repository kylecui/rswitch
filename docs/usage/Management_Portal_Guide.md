# Management Portal User Guide

Step-by-step guide for using the rSwitch web management portal to monitor and configure your switch.

## Accessing the Portal

### Prerequisites

- Management portal enabled in the active profile (`management.enabled: true`)
- rSwitch loader and `rswitch-mgmtd` running
- Browser on a device connected to the same L2 network as the switch ports

### Finding the Portal IP

The management portal runs in the `rswitch-mgmt` network namespace and obtains its IP via DHCP (or static configuration):

```bash
# Check management interface IP
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
```

Open `http://<mgmt-ip>:8080` in your browser.

### Login

If authentication is enabled (`auth_enabled: true`):

1. Navigate to the portal URL
2. Enter username and password (configured in the profile YAML)
3. Click **Login**

The default credentials are set in your profile:

```yaml
management:
  auth_user: admin
  auth_password: rswitch
```

> **Security**: Change the default password before production deployment. See [Security Hardening](../deployment/Security_Hardening.md).

## Dashboard (index.html)

The main dashboard provides a system overview:

| Section | Information |
|---------|-------------|
| **System Info** | Hostname, rSwitch version, uptime, management IP |
| **Port Summary** | Total ports, ports up/down, total throughput |
| **Quick Stats** | MAC table entries, VLAN count, active modules |

The dashboard auto-refreshes to show real-time status.

## Ports (ports.html)

### Port Status Grid

A visual faceplate grid shows all switch ports with:

- **Color coding**: Green (up/link), Gray (down/no link), Red (error)
- **Port number** and interface name
- **Link state** (UP/DOWN)

### Port Details

Click any port to see:

| Field | Description |
|-------|-------------|
| Interface name | Linux interface name (e.g., `ens34`) |
| ifindex | Kernel interface index |
| Link state | UP / DOWN |
| RX packets / bytes | Received counters |
| TX packets / bytes | Transmitted counters |
| RX drops / errors | Receive-side issues |
| TX drops / errors | Transmit-side issues |
| VLAN mode | ACCESS / TRUNK / HYBRID |
| Access VLAN | VLAN ID for access mode |
| Trunk VLANs | Allowed VLAN list for trunk mode |

## Modules (modules.html)

### Pipeline Visualization

Shows the loaded module pipeline in execution order:

```
Ingress: dispatcher → vlan → acl → route → l2learn → lastcall
Egress:  egress_qos → egress_vlan → egress_final
```

### Module Table

| Column | Description |
|--------|-------------|
| Name | Module name |
| Stage | Pipeline stage number (10-99 ingress, 100-199 egress) |
| Packets Processed | Total packets through this module |
| Packets Forwarded | Packets passed to next stage |
| Packets Dropped | Packets dropped by this module |
| Bytes Processed | Total bytes processed |

## VLANs (vlans.html)

### VLAN Table

Lists all configured VLANs with member ports.

| Column | Description |
|--------|-------------|
| VLAN ID | 1-4094 |
| Name | Optional VLAN name |
| Member Ports | Ports assigned to this VLAN |
| Mode per Port | ACCESS / TRUNK / HYBRID per member |

### VLAN Operations

**Create VLAN**:
1. Click **Add VLAN**
2. Enter VLAN ID (1-4094)
3. Select member ports and mode (access/trunk)
4. Click **Save**

**Delete VLAN**:
1. Click the delete icon next to the VLAN
2. Confirm deletion

**Modify VLAN membership**:
1. Click the VLAN row to expand
2. Add/remove ports, change port modes
3. Click **Save**

Equivalent CLI:
```bash
sudo ./build/rsvlanctl add-port ens34 trunk 100,200
sudo ./build/rsvlanctl show
```

## ACLs (acls.html)

### ACL Rule Table

| Column | Description |
|--------|-------------|
| Rule ID | Stable unique identifier |
| Priority | Rule priority (lower = higher priority) |
| Source IP/Mask | Source network match |
| Dest IP/Mask | Destination network match |
| Protocol | TCP / UDP / ICMP / Any |
| Src Port | Source port range |
| Dst Port | Destination port range |
| Action | ALLOW / DENY |
| Hit Count | Packets matched by this rule |

### ACL Operations

**Add Rule**:
1. Click **Add Rule**
2. Fill in match criteria (source/dest IP, protocol, ports)
3. Select action (Allow/Deny)
4. Set priority
5. Click **Save**

**Delete Rule**:
1. Click the delete icon next to the rule
2. Confirm deletion

Rules are identified by stable IDs (not positional index), so deleting a rule does not shift other rule identifiers.

Equivalent CLI:
```bash
sudo ./build/rsaclctl add --src 10.0.0.0/8 --dst 192.168.1.0/24 --action deny --priority 100
sudo ./build/rsaclctl show
```

## Routes (routes.html)

### Routing Table

| Column | Description |
|--------|-------------|
| Destination | Network prefix (CIDR) |
| Next Hop | Next hop IP address |
| Interface | Egress interface |
| Metric | Route metric |

### Route Operations

**Add Route**:
1. Click **Add Route**
2. Enter destination prefix (e.g., `10.0.0.0/8`)
3. Enter next hop IP
4. Select egress interface
5. Click **Save**

**Delete Route**:
1. Click the delete icon
2. Confirm deletion

Equivalent CLI:
```bash
sudo ./build/rsroutectl add 10.0.0.0/8 via 192.168.1.1 dev ens34
sudo ./build/rsroutectl show
```

## DHCP Snooping (dhcp.html)

Displays the DHCP snooping binding table:

| Column | Description |
|--------|-------------|
| MAC Address | Client MAC |
| IP Address | Assigned IP |
| VLAN | VLAN where binding was learned |
| Port | Port where DHCP exchange occurred |
| Lease Time | Remaining lease duration |

This page is read-only — bindings are populated automatically by the DHCP snooping module.

## Network (network.html)

Network topology and MAC address table view:

### MAC Address Table

| Column | Description |
|--------|-------------|
| MAC Address | Learned MAC address |
| Port | Interface where MAC was learned |
| VLAN | VLAN association |
| Age | Time since last seen |

### ARP Table

Displays the ARP table used by the L3 routing module.

## Live Logs (logs.html)

Real-time event stream via WebSocket connection:

- **Event types**: Module events, pipeline transitions, drop notifications, state changes
- **Filtering**: Filter by event type, module, or severity
- **Auto-scroll**: New events appear at the bottom

The WebSocket connects to the same `mgmtd` server and streams events from the `rswitch-events` daemon.

## Profiles (profiles.html)

View and manage loaded profile configurations:

| Section | Information |
|---------|-------------|
| Active Profile | Currently loaded YAML profile name and path |
| Profile Details | Module list, settings, port configuration |
| VOQd Config | VOQd mode, priority mask, queue settings |

> **Note**: Profile changes require reloading the rSwitch loader. The portal shows the current state but does not support live profile switching.

## REST API Reference

All API endpoints require authentication (session cookie) except `POST /api/auth/login`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login with `{"username":"...","password":"..."}` |
| `POST` | `/api/auth/logout` | Invalidate session |

### System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/system/info` | Hostname, version, uptime, port count, management IP |
| `GET` | `/api/system/health` | Health check endpoint |
| `POST` | `/api/system/reboot` | Reboot the system |
| `POST` | `/api/system/shutdown` | Shut down the system |
| `GET` | `/api/system/network` | Management network configuration |
| `PUT` | `/api/system/network` | Update management network configuration |

### Ports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/ports` | All ports with status and statistics |
| `GET` | `/api/ports/:id/stats` | Per-port detailed statistics |
| `PUT` | `/api/ports/:id/config` | Update port configuration (VLAN mode, etc.) |

### Modules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/modules` | Loaded modules and pipeline stages |
| `GET` | `/api/modules/:name/stats` | Per-module processing statistics |
| `POST` | `/api/modules/:name/reload` | Hot-reload a specific module |
| `PUT` | `/api/modules/:name/config` | Update module configuration |

### VLANs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/vlans` | VLAN table |
| `POST` | `/api/vlans` | Create VLAN |
| `PUT` | `/api/vlans/:id` | Update VLAN |
| `DELETE` | `/api/vlans/:id` | Delete VLAN by ID |

### ACLs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/acls` | ACL rule list |
| `POST` | `/api/acls` | Create ACL rule |
| `PUT` | `/api/acls/:id` | Update ACL rule |
| `DELETE` | `/api/acls/:id` | Delete ACL rule by stable ID |

### Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/routes` | Routing table |
| `POST` | `/api/routes` | Add route |
| `DELETE` | `/api/routes/:name` | Delete route by name |

### NAT

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/nat/rules` | NAT rule list |
| `POST` | `/api/nat/rules` | Create NAT rule |
| `GET` | `/api/nat/conntrack` | Connection tracking table |

### Profiles

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/profiles` | List available profiles |
| `GET` | `/api/profiles/active` | Currently active profile |
| `POST` | `/api/profiles/apply` | Apply (activate) a profile |
| `GET` | `/api/profiles/:name` | Get profile details |
| `PUT` | `/api/profiles/:name` | Update profile |
| `DELETE` | `/api/profiles/:name` | Delete profile |

### Configuration Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config/snapshots` | List configuration snapshots |
| `POST` | `/api/config/save` | Save current configuration |
| `POST` | `/api/config/reset` | Reset configuration to defaults |
| `POST` | `/api/config/export` | Export configuration |
| `POST` | `/api/config/snapshot` | Create named snapshot |
| `POST` | `/api/config/rollback/:id` | Roll back to a previous snapshot |
| `GET` | `/api/config/audit` | Configuration audit log |

### Topology

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/topology` | Network topology (LLDP/STP neighbor data) |

### Events & DHCP

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/events` | Event log |
| `GET` | `/api/dhcp-snooping` | DHCP snooping binding table |
| `POST` | `/api/dhcp-snooping/config` | Update DHCP snooping configuration |
| `POST` | `/api/dhcp-snooping/trusted-ports` | Set trusted ports for DHCP snooping |

### WebSocket

| Path | Description |
|------|-------------|
| `/api/ws` | Real-time event stream (used by the Logs page) |

### Example: curl Usage

```bash
# Login and save session cookie
curl -c cookies.txt -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"rswitch"}' \
  http://<mgmt-ip>:8080/api/auth/login

# Get system info
curl -b cookies.txt http://<mgmt-ip>:8080/api/system/info

# Health check
curl -b cookies.txt http://<mgmt-ip>:8080/api/system/health

# Get port statistics
curl -b cookies.txt http://<mgmt-ip>:8080/api/ports

# Get per-port stats
curl -b cookies.txt http://<mgmt-ip>:8080/api/ports/0/stats

# List modules / pipeline
curl -b cookies.txt http://<mgmt-ip>:8080/api/modules

# Create VLAN
curl -b cookies.txt -X POST -H 'Content-Type: application/json' \
  -d '{"vlan_id":100,"name":"Engineering"}' \
  http://<mgmt-ip>:8080/api/vlans

# Add ACL rule
curl -b cookies.txt -X POST -H 'Content-Type: application/json' \
  -d '{"src":"10.0.0.0/8","dst":"0.0.0.0/0","action":"deny","priority":100}' \
  http://<mgmt-ip>:8080/api/acls

# List profiles
curl -b cookies.txt http://<mgmt-ip>:8080/api/profiles

# Save configuration snapshot
curl -b cookies.txt -X POST http://<mgmt-ip>:8080/api/config/snapshot

# Logout
curl -b cookies.txt -X POST http://<mgmt-ip>:8080/api/auth/logout
```

## Troubleshooting

### Portal Not Accessible

1. **Check mgmtd is running**:
   ```bash
   sudo systemctl status rswitch-mgmtd
   ```

2. **Check management IP**:
   ```bash
   sudo ip netns exec rswitch-mgmt ip addr show mgmt0
   ```

3. **Check namespace and port**:
   ```bash
   sudo ip netns exec rswitch-mgmt ss -tlnp | grep 8080
   ```

4. **DHCP timeout**: Verify XDP mode consistency across all ports. See [Management Portal — Troubleshooting](../deployment/Management_Portal.md#troubleshooting).

### Authentication Failed

- Verify credentials match the active profile YAML
- Check mgmtd logs: `sudo journalctl -u rswitch-mgmtd`
- Restart mgmtd: `sudo systemctl restart rswitch-mgmtd`

### Stale Data / No Updates

- Check that `rswitch-events` is running (for live logs)
- Verify BPF maps are readable: `sudo bpftool map show | grep rs_`
- Hard-refresh the browser (Ctrl+Shift+R)

## See Also

- [Management Portal](../deployment/Management_Portal.md) — architecture, namespace design, REST API details
- [CLI Reference](CLI_Reference.md) — equivalent CLI commands for all portal operations
- [Security Hardening](../deployment/Security_Hardening.md) — portal security configuration
- [Troubleshooting](Troubleshooting.md) — general diagnostic procedures
