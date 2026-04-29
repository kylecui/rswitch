> 📖 [English Version](../../deployment/Management_Portal.md)

# 管理门户 (Management Portal)

rSwitch的基于Web的管理UI。在网络namespace内运行嵌入式Mongoose HTTP服务器，通过XDP pipeline进行基于DHCP的IP获取。

## 架构

```
┌─────────────────────────────────────────────────────────┐
│  默认 Namespace (数据平面)                                │
│                                                          │
│  ens34,35,36,37 ─── XDP dispatcher ─── BPF pipeline    │
│       (xdpgeneric)                                       │
│                                                          │
│  mgmt-br ─── XDP dispatcher (相同的 pipeline)            │
│       (xdpgeneric)                                       │
│       │ veth pair                                        │
│       │                                                  │
│  ┌────┴──── rswitch-mgmt namespace ──────────────────┐  │
│  │  mgmt0 ── dhcpcd ── 从外部 DHCP 获取 IP            │  │
│  │  rswitch-mgmtd :8080 ── REST API + WebSocket + UI │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

关键设计点：

- **Namespace隔离** — mgmtd运行在专用的网络namespace (`rswitch-mgmt`) 中。管理流量不会干扰数据平面的转发。
- **参与XDP pipeline** — mgmt-br是一个注册在所有BPF maps（devmap, port_config, VLAN成员身份）中的常规交换机端口。L2泛洪/单播通过与物理端口相同的pipeline到达mgmt-br。
- **无需专用NIC** — DHCP discover/offer流量通过XDP广播转发，发往/来自连接到任何物理端口的外部DHCP服务器。
- **相同的XDP模式** — mgmt-br必须使用 `xdpgeneric`（与物理端口相同），以便 `BPF_F_BROADCAST` 重定向能在所有端口间正常工作。

## 要求

- 内核5.15+（以便在 `BPF_MAP_TYPE_DEVMAP` 中使用 `BPF_F_BROADCAST`）
- 已安装 `dhcpcd`（用于DHCP模式）
- 物理端口以 `xdpgeneric` 模式挂载
- 交换机网络中存在可达的外部DHCP服务器（用于DHCP模式）

## Profile配置

在你的profile YAML中添加 `management:` 部分：

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

| 字段 | 类型 | 默认值 | 描述 |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | 启用管理门户 |
| `port` | int | `8080` | HTTP监听端口 |
| `web_root` | string | `./web` | Web资源目录路径 |
| `use_namespace` | bool | `true` | 在隔离的网络namespace中运行 |
| `namespace_name` | string | `rswitch-mgmt` | Namespace名称 |
| `iface_mode` | string | `dhcp` | IP模式：`dhcp` 或 `static` |
| `static_ip` | string | — | 静态IP（仅当 `iface_mode: static` 时） |
| `mgmt_vlan` | int | `1` | 管理流量的VLAN |
| `auth_enabled` | bool | `false` | 是否需要身份验证 |
| `auth_user` | string | — | 登录用户名 |
| `auth_password` | string | — | 登录密码 |

## 启动序列

1. **Loader** (`rswitch_loader`) 解析profile中的 `management:` 部分
2. 创建veth pair：`mgmt-br` (默认ns) ↔ `mgmt0` (管理ns)
3. 在BPF maps中注册 `mgmt-br`：`rs_port_config_map`, `rs_ifindex_to_port_map`, `rs_xdp_devmap`, `rs_vlan_map`
4. 以SKB/generic模式将XDP dispatcher挂载到 `mgmt-br`
5. **mgmtd** (`rswitch-mgmtd`) 在namespace中启动
6. 检测到由loader管理的 `mgmt-br`，跳过veth创建
7. 在 `mgmt0` 上运行 `dhcpcd` — DHCP流量流经XDP pipeline
8. 开始在 `0.0.0.0:<port>` 提供HTTP服务

## Web门户

| 页面 | 路径 | 描述 |
|------|------|-------------|
| 仪表板 (Dashboard) | `/index.html` | 系统概览、端口摘要、运行时间 |
| 端口 (Ports) | `/ports.html` | 带有面板网格的端口状态、链路状态 |
| Modules | `/modules.html` | Pipeline可视化、module表格 |
| VLANs | `/vlans.html` | VLAN CRUD操作 |
| ACLs | `/acls.html` | ACL规则管理 |
| 路由 (Routes) | `/routes.html` | 路由表管理 |
| 日志 (Logs) | `/logs.html` | 通过WebSocket查看实时事件日志 |

## 身份验证

所有API端点（除了 `POST /api/auth/login`）都需要有效的会话cookie。

```bash
# 登录
curl -c cookies.txt -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"rswitch"}' \
  http://<mgmt-ip>:8080/api/auth/login

# 经过身份验证的请求
curl -b cookies.txt http://<mgmt-ip>:8080/api/system/info
```

## REST API

| 方法 | 路径 | 描述 |
|--------|------|-------------|
| `POST` | `/api/auth/login` | 身份验证，返回会话cookie |
| `POST` | `/api/auth/logout` | 注销会话 |
| `GET` | `/api/system/info` | 主机名、版本、运行时间、端口数量、管理IP |
| `GET` | `/api/ports` | 带有状态和统计信息的端口列表 |
| `GET` | `/api/vlans` | VLAN表 |
| `POST` | `/api/vlans` | 创建/更新VLAN |
| `DELETE` | `/api/vlans/:id` | 删除VLAN |
| `GET` | `/api/acls` | ACL规则 |
| `POST` | `/api/acls` | 创建ACL规则 |
| `DELETE` | `/api/acls/:id` | 删除ACL规则 |
| `GET` | `/api/routes` | 路由表 |
| `POST` | `/api/routes` | 添加路由 |
| `DELETE` | `/api/routes` | 删除路由 |
| `GET` | `/api/pipeline` | Module pipeline状态 |
| `GET` | `/api/stats` | 端口统计信息 (RX/TX数据包, 字节, 错误) |
| `GET` | `/api/mac-table` | 已学习的MAC地址 |

## 独立模式 (Standalone Mode)

为了开发和测试，可以在没有namespace隔离的情况下运行mgmtd：

```bash
./build/rswitch-mgmtd -p 8080 -w ./web -u admin -P rswitch
```

这将在默认namespace中绑定到 `0.0.0.0:8080`。不涉及veth或DHCP。

## 故障排除

**DHCP超时 — 未分配IP**

验证XDP模式的一致性。所有端口（物理端口 + mgmt-br）必须使用相同的XDP模式。检查命令：

```bash
ip -d link show mgmt-br | grep xdp
ip -d link show ens34 | grep xdp
```

两者都应显示 `xdpgeneric`。如果mgmt-br显示 `xdp`（原生模式），则XDP广播重定向会静默失败。

**未找到Namespace**

loader负责创建namespace。如果mgmtd在loader之前启动，则namespace创建会失败。请确保loader先运行：

```bash
ip netns list | grep rswitch-mgmt
```

**无法从网络访问门户**

门户仅能从与物理交换机端口处于同一L2网络中的设备访问。除非经过路由，否则无法从主机的管理接口（例如 `eth0`）访问。

验证 `mgmt0` 是否有IP：

```bash
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
```

**无法从namespace读取BPF maps**

mgmtd通过 `/sys/fs/bpf/` 下的固定路径（pinned paths）读取BPF maps。这些路径存在于默认的挂载namespace中，并且可以从网络namespace内部访问。如果maps显示为空，请验证loader是否正在运行并已固定（pinned）其maps。
