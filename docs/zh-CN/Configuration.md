# 配置参考

本文档是 rSwitch YAML 配置文件的完整参考。面向使用的指南请参阅 [场景配置](Scenario_Profiles.md)。

## 配置文件格式

配置文件是位于 `etc/profiles/` 的 YAML 文件。它们定义 rSwitch 实例的完整运行时配置。

```yaml
# 必需
name: "配置文件名称"
version: "1.0"

# 可选
description: "人类可读的描述"

# 模块选择（必需）
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1
  - egress_module_2

# 全局设置（可选）
settings:
  key: value

# 端口配置（可选）
ports:
  - interface: "ens34"
    # ...

# VLAN 定义（可选）
vlans:
  - vlan_id: 100
    # ...

# VOQd 配置（可选）
voqd_config:
  enabled: true
  # ...
```

## 模块选择

### 入口模块

在 `ingress:` 下列出模块名称。只有列出的模块才会被加载。执行顺序由 BPF ELF 元数据中嵌入的阶段号决定，**而非** YAML 列表顺序。

```yaml
ingress:
  - vlan         # 阶段 20 — VLAN 处理
  - acl          # 阶段 30 — 访问控制
  - route        # 阶段 50 — 三层路由
  - mirror       # 阶段 70 — 端口镜像
  - l2learn      # 阶段 80 — MAC 学习
  - afxdp_redirect  # 阶段 85 — AF_XDP QoS 重定向
  - lastcall     # 阶段 90 — 最终转发（始终包含）
```

### 出口模块

```yaml
egress:
  - egress_qos    # 阶段 170 — QoS 执行
  - egress_vlan   # 阶段 180 — VLAN 标签插入/移除
  - egress_final  # 阶段 190 — 最终出口（始终包含）
```

### 规则

- `lastcall` 必须是最后一个入口模块。
- `egress_final` 必须是最后一个出口模块。
- 模块名称必须与 `RS_DECLARE_MODULE()` 中的 `name` 参数匹配。
- 目前只支持简单的模块名称列表。模块子字段（阶段覆盖、可选模块、每模块配置）已计划但尚未实现。

## 设置部分

加载时应用的全局行为设置。

```yaml
settings:
  mac_learning: true          # 启用 MAC 地址学习
  mac_aging_time: 300         # MAC 条目老化时间（秒）
  vlan_enforcement: true      # 强制执行 VLAN 成员规则
  default_vlan: 1             # 未标记流量的默认 VLAN
  unknown_unicast_flood: true # 泛洪未知单播数据包
  broadcast_flood: true       # 泛洪广播数据包
  stats_enabled: true         # 启用每端口统计收集
  ringbuf_enabled: true       # 启用事件 ringbuf 用于可观测性
  debug: false                # 启用调试级别 BPF 日志
```

| 键 | 类型 | 默认值 | 描述 |
|----|------|--------|------|
| `mac_learning` | bool | `true` | 全局 MAC 学习开关 |
| `mac_aging_time` | int | `300` | 学习的 MAC 条目过期前的秒数 |
| `vlan_enforcement` | bool | `true` | 丢弃违反 VLAN 成员的数据包 |
| `default_vlan` | int | `1` | 分配给未标记流量的 VLAN |
| `unknown_unicast_flood` | bool | `true` | 泛洪具有未知目的 MAC 的帧 |
| `broadcast_flood` | bool | `true` | 泛洪广播帧到所有端口 |
| `stats_enabled` | bool | `true` | 收集每端口 RX/TX/丢弃统计 |
| `ringbuf_enabled` | bool | `true` | 启用 `rs_event_bus` 环形缓冲区 |
| `debug` | bool | `false` | 启用详细 BPF 调试输出 |

## 端口部分

每接口配置。

```yaml
ports:
  - interface: "ens34"
    enabled: true
    vlan_mode: trunk
    pvid: 1
    native_vlan: 1
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0

  - interface: "ens35"
    enabled: true
    vlan_mode: access
    pvid: 100
    mac_learning: true
    default_priority: 0
```

| 键 | 类型 | 描述 |
|----|------|------|
| `interface` | string | 接口名称（如 `ens34`） |
| `enabled` | bool | 此端口是否激活 |
| `vlan_mode` | string | `off`、`access`、`trunk` 或 `hybrid` |
| `pvid` | int | 端口 VLAN ID（用于 access 模式） |
| `native_vlan` | int | 原生 VLAN（用于 trunk 模式处理未标记帧） |
| `allowed_vlans` | int[] | 允许的 VLAN ID 列表（trunk/hybrid 模式） |
| `mac_learning` | bool | 每端口覆盖 MAC 学习 |
| `default_priority` | int | 默认 QoS 优先级 0-7（7 = 最高） |

### VLAN 模式

| 模式 | 值 | 行为 |
|------|----|----|
| `off` | 0 | 此端口不进行 VLAN 处理 |
| `access` | 1 | 仅未标记流量；分配到 `pvid` |
| `trunk` | 2 | 标记流量；`native_vlan` 用于未标记帧 |
| `hybrid` | 3 | 标记和未标记 VLAN 混合 |

## VLAN 部分

定义跨端口的 VLAN 成员。

```yaml
vlans:
  - vlan_id: 100
    name: "管理"
    tagged_ports: ["ens34", "ens36"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "服务器"
    tagged_ports: ["ens34"]
    untagged_ports: []
```

| 键 | 类型 | 描述 |
|----|------|------|
| `vlan_id` | int | VLAN 标识符（1-4094） |
| `name` | string | 人类可读的 VLAN 名称 |
| `tagged_ports` | string[] | 为此 VLAN 发送/接收标记帧的接口 |
| `untagged_ports` | string[] | 为此 VLAN 发送/接收未标记帧的接口 |

## VOQd 配置部分

配置 VOQd 用户空间 QoS 调度器。部署详情请参阅 [VOQd 设置](VOQd_Setup.md)。

```yaml
voqd_config:
  # 基本
  enabled: true
  mode: active           # bypass | shadow | active
  num_ports: 4
  prio_mask: 0x0C        # 要拦截的优先级（位掩码）

  # AF_XDP
  enable_afxdp: true
  zero_copy: false       # 需要 NIC 驱动支持
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  busy_poll: false

  # 调度器
  enable_scheduler: true
  cpu_affinity: 2        # 将 VOQd 固定到特定 CPU 核心

  # 软件队列（用于没有硬件队列的 NIC）
  software_queues:
    enabled: false
    queue_depth: 1024
    num_priorities: 8
```

| 键 | 类型 | 描述 |
|----|------|------|
| `enabled` | bool | 随加载器自动启动 VOQd |
| `mode` | string | `bypass`（仅快速路径）、`shadow`（观察）、`active`（完整 QoS） |
| `num_ports` | int | VOQd 管理的端口数量 |
| `prio_mask` | hex/int | 要拦截的优先级位掩码 |
| `enable_afxdp` | bool | 启用 AF_XDP 数据平面 |
| `zero_copy` | bool | 零拷贝 AF_XDP（需要 NIC 支持） |
| `rx_ring_size` | int | AF_XDP RX 环大小 |
| `tx_ring_size` | int | AF_XDP TX 环大小 |
| `frame_size` | int | UMEM 帧大小（字节） |
| `batch_size` | int | 每次轮询的数据包批大小 |
| `poll_timeout_ms` | int | 轮询超时（毫秒） |
| `busy_poll` | bool | 启用忙轮询（更低延迟，更高 CPU） |
| `enable_scheduler` | bool | 启用 DRR/WFQ 调度器 |
| `cpu_affinity` | int | 固定 VOQd 线程的 CPU 核心 |
| `software_queues.enabled` | bool | 启用软件队列仿真 |
| `software_queues.queue_depth` | int | 每个软件队列的深度 |
| `software_queues.num_priorities` | int | 优先级级数 |

## 完整示例

```yaml
name: "生产 L3 路由器"
version: "1.0"
description: "带 VLAN、ACL 和 QoS 的三层路由"

ingress:
  - vlan
  - acl
  - route
  - l2learn
  - afxdp_redirect
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final

settings:
  mac_learning: true
  mac_aging_time: 300
  vlan_enforcement: true
  default_vlan: 1
  stats_enabled: true

ports:
  - interface: "ens34"
    enabled: true
    vlan_mode: trunk
    native_vlan: 1
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0

  - interface: "ens35"
    enabled: true
    vlan_mode: access
    pvid: 100
    mac_learning: true

  - interface: "ens36"
    enabled: true
    vlan_mode: access
    pvid: 200

vlans:
  - vlan_id: 100
    name: "用户"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "服务器"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens36"]

voqd_config:
  enabled: true
  mode: active
  num_ports: 3
  prio_mask: 0x0C
  enable_afxdp: true
  zero_copy: false
  rx_ring_size: 2048
  tx_ring_size: 2048
  batch_size: 256
  enable_scheduler: true
  cpu_affinity: 2
```

## 计划的未来配置功能

以下功能已设计但尚未实现：

- **阶段覆盖**：从 YAML 覆盖 ELF 定义的阶段号
- **可选模块**：基于构建标志或运行时条件的条件加载
- **模块子字段**：每模块配置参数（如 ACL 最大规则数）
- **配置文件继承**：`inherits: base-profile.yaml` 用于配置重用
- **模板系统**：带变量替换的参数化配置文件

## 另请参阅

- [场景配置](Scenario_Profiles.md) — 面向使用的配置文件指南
- [VOQd 设置](VOQd_Setup.md) — VOQd 部署
- [网卡配置](NIC_Configuration.md) — NIC 特定设置
- [安装](Installation.md) — 从源代码构建

---

*最后更新: 2026-03-17*
