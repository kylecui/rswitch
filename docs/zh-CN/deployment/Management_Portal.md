> 📖 [English Version](../../deployment/Management_Portal.md)

# 管理门户 (Management Portal)

rSwitch 的基于 Web 的管理 UI。在网络 namespace 内运行嵌入式 Mongoose HTTP 服务器，通过 XDP pipeline 进行基于 DHCP 的 IP 获取。

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

- **Namespace 隔离** — mgmtd 运行在专用的网络 namespace (`rswitch-mgmt`) 中。管理流量不会干扰数据平面的转发。
- **参与 XDP pipeline** — mgmt-br 是一个注册在所有 BPF maps（devmap, port_config, VLAN 成员身份）中的常规交换机端口。L2 泛洪/单播通过与物理端口相同的 pipeline 到达 mgmt-br。
- **无需专用 NIC** — DHCP discover/offer 流量通过 XDP 广播转发，发往/来自连接到任何物理端口的外部 DHCP 服务器。
- **相同的 XDP 模式** — mgmt-br 必须使用 `xdpgeneric`（与物理端口相同），以便 `BPF_F_BROADCAST` 重定向能在所有端口间正常工作。

## 要求

- 内核 5.15+（以便在 `BPF_MAP_TYPE_DEVMAP` 中使用 `BPF_F_BROADCAST`）
- 已安装 `dhcpcd`（用于 DHCP 模式）
- 物理端口以 `xdpgeneric` 模式挂载
- 交换机网络中存在可达的外部 DHCP 服务器（用于 DHCP 模式）

## Profile 配置

在你的 profile YAML 中添加 `management:` 部分：

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
| `port` | int | `8080` | HTTP 监听端口 |
| `web_root` | string | `./web` | Web 资源目录路径 |
| `use_namespace` | bool | `true` | 在隔离的网络 namespace 中运行 |
| `namespace_name` | string | `rswitch-mgmt` | Namespace 名称 |
| `iface_mode` | string | `dhcp` | IP 模式：`dhcp` 或 `static` |
| `static_ip` | string | — | 静态 IP（仅当 `iface_mode: static` 时） |
| `mgmt_vlan` | int | `1` | 管理流量的 VLAN |
| `auth_enabled` | bool | `false` | 是否需要身份验证 |
| `auth_user` | string | — | 登录用户名 |
| `auth_password` | string | — | 登录密码 |

## 启动序列

1. **Loader** (`rswitch_loader`) 解析 profile 中的 `management:` 部分
2. 创建 veth pair：`mgmt-br` (默认 ns) ↔ `mgmt0` (管理 ns)
3. 在 BPF maps 中注册 `mgmt-br`：`rs_port_config_map`, `rs_ifindex_to_port_map`, `rs_xdp_devmap`, `rs_vlan_map`
4. 以 SKB/generic 模式将 XDP dispatcher 挂载到 `mgmt-br`
5. **mgmtd** (`rswitch-mgmtd`) 在 namespace 中启动
6. 检测到由 loader 管理的 `mgmt-br`，跳过 veth 创建
7. 在 `mgmt0` 上运行 `dhcpcd` — DHCP 流量流经 XDP pipeline
8. 开始在 `0.0.0.0:<port>` 提供 HTTP 服务

## Web 门户

| 页面 | 路径 | 描述 |
|------|------|-------------|
| 仪表板 (Dashboard) | `/index.html` | 系统概览、端口摘要、运行时间 |
| 端口 (Ports) | `/ports.html` | 带有面板网格的端口状态、链路状态 |
| Modules | `/modules.html` | Pipeline 可视化、module 表格 |
| VLANs | `/vlans.html` | VLAN CRUD 操作 |
| ACLs | `/acls.html` | ACL 规则管理 |
| 路由 (Routes) | `/routes.html` | 路由表管理 |
| 日志 (Logs) | `/logs.html` | 通过 WebSocket 查看实时事件日志 |

## 身份验证

所有 API 端点（除了 `POST /api/auth/login`）都需要有效的会话 cookie。

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
| `POST` | `/api/auth/login` | 身份验证，返回会话 cookie |
| `POST` | `/api/auth/logout` | 注销会话 |
| `GET` | `/api/system/info` | 主机名、版本、运行时间、端口数量、管理 IP |
| `GET` | `/api/ports` | 带有状态和统计信息的端口列表 |
| `GET` | `/api/vlans` | VLAN 表 |
| `POST` | `/api/vlans` | 创建/更新 VLAN |
| `DELETE` | `/api/vlans/:id` | 删除 VLAN |
| `GET` | `/api/acls` | ACL 规则 |
| `POST` | `/api/acls` | 创建 ACL 规则 |
| `DELETE` | `/api/acls/:id` | 删除 ACL 规则 |
| `GET` | `/api/routes` | 路由表 |
| `POST` | `/api/routes` | 添加路由 |
| `DELETE` | `/api/routes` | 删除路由 |
| `GET` | `/api/pipeline` | Module pipeline 状态 |
| `GET` | `/api/stats` | 端口统计信息 (RX/TX 数据包, 字节, 错误) |
| `GET` | `/api/mac-table` | 已学习的 MAC 地址 |

## 独立模式 (Standalone Mode)

为了开发和测试，可以在没有 namespace 隔离的情况下运行 mgmtd：

```bash
./build/rswitch-mgmtd -p 8080 -w ./web -u admin -P rswitch
```

这将在默认 namespace 中绑定到 `0.0.0.0:8080`。不涉及 veth 或 DHCP。

## 故障排除

**DHCP 超时 — 未分配 IP**

验证 XDP 模式的一致性。所有端口（物理端口 + mgmt-br）必须使用相同的 XDP 模式。检查命令：

```bash
ip -d link show mgmt-br | grep xdp
ip -d link show ens34 | grep xdp
```

两者都应显示 `xdpgeneric`。如果 mgmt-br 显示 `xdp`（原生模式），则 XDP 广播重定向会静默失败。

**未找到 Namespace**

loader 负责创建 namespace。如果 mgmtd 在 loader 之前启动，则 namespace 创建会失败。请确保 loader 先运行：

```bash
ip netns list | grep rswitch-mgmt
```

**无法从网络访问门户**

门户仅能从与物理交换机端口处于同一 L2 网络中的设备访问。除非经过路由，否则无法从主机的管理接口（例如 `eth0`）访问。

验证 `mgmt0` 是否有 IP：

```bash
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
```

**无法从 namespace 读取 BPF maps**

mgmtd 通过 `/sys/fs/bpf/` 下的固定路径（pinned paths）读取 BPF maps。这些路径存在于默认的挂载 namespace 中，并且可以从网络 namespace 内部访问。如果 maps 显示为空，请验证 loader 是否正在运行并已固定（pinned）其 maps。
