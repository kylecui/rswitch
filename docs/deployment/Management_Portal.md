# Management Portal

Web-based management UI for rSwitch. Runs an embedded Mongoose HTTP server inside a network namespace, with DHCP-based IP acquisition through the XDP pipeline.

> For the validated physical-machine native-XDP rollout guide, read [物理机 Native XDP 部署与运维手册](../zh-CN/deployment/Physical_Machine_Native_XDP_Deployment.md) first.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Default Namespace (Data Plane)                          │
│                                                          │
│  ens34,35,36,37 ─── XDP dispatcher ─── BPF pipeline    │
│       (same mode as deployment target)                  │
│                                                          │
│  mgmt-br ─── XDP dispatcher (same pipeline)             │
│       (same mode as physical ports)                     │
│       │ veth pair                                        │
│       │                                                  │
│  ┌────┴──── rswitch-mgmt namespace ──────────────────┐  │
│  │  mgmt0 ── dhcpcd ── gets IP from external DHCP    │  │
│  │  rswitch-mgmtd :8080 ── REST API + WebSocket + UI │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

Key design points:

- **Namespace isolation** — mgmtd runs in a dedicated network namespace (`rswitch-mgmt`). Management traffic cannot interfere with data plane forwarding.
- **XDP pipeline participation** — mgmt-br is a regular switch port registered in all BPF maps (devmap, port_config, VLAN membership). L2 flooding/unicast reaches mgmt-br through the same pipeline as physical ports.
- **No dedicated NIC** — DHCP discover/offer flows through XDP broadcast forwarding to/from an external DHCP server connected to any physical port.
- **Same XDP mode** — mgmt-br must use the same XDP mode as physical ports.
- **Native XDP caveat** — when using native XDP, `mgmt0` needs a minimal `XDP_PASS` program to activate the veth receive path used by devmap redirect.
- **Checksum caveat** — disable TX checksum / SG / TSO offload on `mgmt0` and `mgmt-br`, otherwise reply packets may leave with incorrect checksums and TCP services (such as SSH) can fail even though SYN packets are visible.

## Requirements

- Kernel 5.15+ (for `BPF_F_BROADCAST` with `BPF_MAP_TYPE_DEVMAP`)
- `dhcpcd` installed (for DHCP mode)
- Physical ports attached in a mode that matches `mgmt-br` (`xdpgeneric` or native, but consistent)
- External DHCP server reachable on the switch network (for DHCP mode)

## Profile Configuration

Add a `management:` section to your profile YAML:

```yaml
management:
  enabled: true
  port: 8080
  web_root: /path/to/rswitch/web
  use_namespace: true
  namespace_name: rswitch-mgmt
  iface_mode: dhcp
  mgmt_vlan: 1
  auth_enabled: true
  auth_user: admin
  auth_password: rswitch
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable management portal |
| `port` | int | `8080` | HTTP listen port |
| `web_root` | string | `./web` | Path to web asset directory |
| `use_namespace` | bool | `true` | Run in isolated network namespace |
| `namespace_name` | string | `rswitch-mgmt` | Namespace name |
| `iface_mode` | string | `dhcp` | IP mode: `dhcp` or `static` |
| `static_ip` | string | — | Static IP (only if `iface_mode: static`) |
| `mgmt_vlan` | int | `1` | VLAN for management traffic |
| `auth_enabled` | bool | `false` | Require authentication |
| `auth_user` | string | — | Login username |
| `auth_password` | string | — | Login password |

## Startup Sequence

1. **Loader** (`rswitch_loader`) parses the `management:` profile section
2. Creates veth pair: `mgmt-br` (default ns) ↔ `mgmt0` (management ns)
3. Registers `mgmt-br` in BPF maps: `rs_port_config_map`, `rs_ifindex_to_port_map`, `rs_xdp_devmap`, `rs_vlan_map`
4. Attaches XDP dispatcher to `mgmt-br` in the same mode as physical ports
5. Disables TX checksum / SG / TSO offload on `mgmt0` and `mgmt-br`
6. For native XDP, attaches a minimal `XDP_PASS` program to `mgmt0`
7. **mgmtd** (`rswitch-mgmtd`) starts in the namespace
8. Detects loader-managed `mgmt-br`, skips veth creation
9. Runs `dhcpcd` on `mgmt0` — DHCP traffic flows through XDP pipeline
10. Begins serving HTTP on `0.0.0.0:<port>`

## Web Portal

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/index.html` | System overview, port summary, uptime |
| Ports | `/ports.html` | Port status with faceplate grid, link state |
| Modules | `/modules.html` | Pipeline visualization, module table |
| VLANs | `/vlans.html` | VLAN CRUD operations |
| ACLs | `/acls.html` | ACL rule management |
| Routes | `/routes.html` | Routing table management |
| Logs | `/logs.html` | Live event log via WebSocket |

## Authentication

All API endpoints (except `POST /api/auth/login`) require a valid session cookie.

```bash
# Login
curl -c cookies.txt -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"rswitch"}' \
  http://<mgmt-ip>:8080/api/auth/login

# Authenticated request
curl -b cookies.txt http://<mgmt-ip>:8080/api/system/info
```

## REST API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Authenticate, returns session cookie |
| `POST` | `/api/auth/logout` | Invalidate session |
| `GET` | `/api/system/info` | Hostname, version, uptime, port count, management IP |
| `GET` | `/api/ports` | Port list with status and statistics |
| `GET` | `/api/vlans` | VLAN table |
| `POST` | `/api/vlans` | Create/update VLAN |
| `DELETE` | `/api/vlans/:id` | Delete VLAN |
| `GET` | `/api/acls` | ACL rules |
| `POST` | `/api/acls` | Create ACL rule |
| `DELETE` | `/api/acls/:id` | Delete ACL rule |
| `GET` | `/api/routes` | Routing table |
| `POST` | `/api/routes` | Add route |
| `DELETE` | `/api/routes` | Delete route |
| `GET` | `/api/pipeline` | Module pipeline state |
| `GET` | `/api/stats` | Port statistics (RX/TX packets, bytes, errors) |
| `GET` | `/api/mac-table` | Learned MAC addresses |

## Standalone Mode

For development and testing, run mgmtd without namespace isolation:

```bash
./build/rswitch-mgmtd -p 8080 -w ./web -u admin -P rswitch
```

This binds to `0.0.0.0:8080` in the default namespace. No veth or DHCP is involved.

## Troubleshooting

**DHCP timeout — no IP assigned**

Verify XDP mode consistency. All ports (physical + mgmt-br) must use the same XDP mode. Check with:

```bash
ip -d link show mgmt-br | grep xdp
ip -d link show ens34 | grep xdp
```

Both should show the same mode. In native XDP deployments, also verify that `mgmt0` has an attached `xdp_pass` program and that TX offloads are disabled:

```bash
sudo ip netns exec rswitch-mgmt ip -d link show mgmt0 | grep xdp
sudo ip netns exec rswitch-mgmt ethtool -k mgmt0 | grep tx-checksumming
sudo ethtool -k mgmt-br | grep tx-checksumming
```

**Namespace not found**

The loader creates the namespace. If mgmtd starts before the loader, namespace creation fails. Ensure the loader is running first:

```bash
ip netns list | grep rswitch-mgmt
```

**Portal not accessible from network**

The portal is only accessible from devices on the same L2 network as the physical switch ports. It is not reachable from the host's management interface (e.g., `eth0`) unless routed.

Verify mgmt0 has an IP:

```bash
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
```

**BPF maps not readable from namespace**

mgmtd reads BPF maps via pinned paths under `/sys/fs/bpf/`. These paths exist in the default mount namespace and are accessible from within the network namespace. If maps show empty, verify the loader is running and has pinned its maps.
