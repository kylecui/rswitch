> 📖 [English Version](../../deployment/Configuration.md)

# 配置参考

本文档是 rSwitch YAML profile 配置的权威参考。有关面向使用的指南，请参阅 [场景 Profile](../../usage/Scenario_Profiles.md)。

## Profile 文件格式

Profiles 是位于 `etc/profiles/` 中的 YAML 文件。它们定义了 rSwitch 实例的完整运行时配置。

```yaml
# 必填
name: "Profile Name"
version: "1.0"

# 可选
description: "人类可读的描述"

# Module 选择 (必填)
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1
  - egress_module_2

# 全局设置 (可选)
settings:
  key: value

# 端口配置 (可选)
ports:
  - interface: "ens34"
    # ...

# VLAN 定义 (可选)
vlans:
  - vlan_id: 100
    # ...

# VOQd 配置 (可选)
voqd_config:
  enabled: true
  # ...
```

## Module 选择

### Ingress Modules

在 `ingress:` 下列出 module 名称。只有列出的 modules 会被加载。执行顺序由 BPF ELF metadata 中嵌入的 stage 编号决定，**而不是**由 YAML 列表顺序决定。

```yaml
ingress:
  - vlan         # stage 20 — VLAN 处理
  - acl          # stage 30 — 访问控制
  - route        # stage 50 — L3 路由
  - mirror       # stage 70 — 端口镜像
  - l2learn      # stage 80 — MAC 学习
  - afxdp_redirect  # stage 85 — AF_XDP QoS 重定向
  - lastcall     # stage 90 — 最终转发 (务必包含)
```

### Egress Modules

```yaml
egress:
  - egress_qos    # stage 170 — QoS 强制执行
  - egress_vlan   # stage 180 — VLAN 标签插入/移除
  - egress_final  # stage 190 — 最终 egress (务必包含)
```

### 规则

- `lastcall` 必须是最后一个 ingress module。
- `egress_final` 必须是最后一个 egress module。
- Module 名称必须与 `RS_DECLARE_MODULE()` 中的 `name` 参数匹配。
- 目前仅支持简单的 module 名称列表。Module 子字段（stage 覆盖、可选 modules、逐个 module 的配置）已在计划中，但尚未实现。

## Settings 部分

在加载时应用的全局行为设置。

```yaml
settings:
  mac_learning: true          # 启用 MAC 地址学习
  mac_aging_time: 300         # MAC 条目老化时间 (秒)
  vlan_enforcement: true      # 强制执行 VLAN 成员规则
  default_vlan: 1             # 未打标签流量的默认 VLAN
  unknown_unicast_flood: true # 泛洪未知单播数据包
  broadcast_flood: true       # 泛洪广播数据包
  stats_enabled: true         # 启用逐端口统计信息收集
  ringbuf_enabled: true       # 启用事件 ringbuf 以实现可观测性
  debug: false                # 启用 debug 级别的 BPF 日志
```

| 键 (Key) | 类型 | 默认值 | 描述 |
|-----|------|---------|-------------|
| `mac_learning` | bool | `true` | 全局 MAC 学习开关 |
| `mac_aging_time` | int | `300` | 已学习的 MAC 条目过期前的秒数 |
| `vlan_enforcement` | bool | `true` | 丢弃违反 VLAN 成员身份的数据包 |
| `default_vlan` | int | `1` | 分配给未打标签流量的 VLAN |
| `unknown_unicast_flood` | bool | `true` | 泛洪具有未知目的 MAC 的帧 |
| `broadcast_flood` | bool | `true` | 向所有端口泛洪广播帧 |
| `stats_enabled` | bool | `true` | 收集逐端口的 RX/TX/drop 统计信息 |
| `ringbuf_enabled` | bool | `true` | 启用 `rs_event_bus` ring buffer |
| `debug` | bool | `false` | 启用详细的 BPF debug 输出 |

## Ports 部分

逐个接口的配置。

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

| 键 (Key) | 类型 | 描述 |
|-----|------|-------------|
| `interface` | string | 接口名称 (例如 `ens34`) |
| `enabled` | bool | 该端口是否处于活动状态 |
| `vlan_mode` | string | `off`, `access`, `trunk`, 或 `hybrid` |
| `pvid` | int | 端口 VLAN ID (用于 access 模式) |
| `native_vlan` | int | Native VLAN (用于 trunk 模式下的未打标签帧) |
| `allowed_vlans` | int[] | 允许的 VLAN ID 列表 (trunk/hybrid 模式) |
| `mac_learning` | bool | 逐端口覆盖 MAC 学习设置 |
| `default_priority` | int | 默认 QoS 优先级 0–7 (7 = 最高) |

### VLAN 模式

| 模式 | 值 | 行为 |
|------|-------|----------|
| `off` | 0 | 该端口不进行 VLAN 处理 |
| `access` | 1 | 仅限未打标签流量；分配给 `pvid` |
| `trunk` | 2 | 打标签流量；`native_vlan` 用于未打标签帧 |
| `hybrid` | 3 | 混合打标签和未打标签的 VLAN |

## VLANs 部分

定义跨端口的 VLAN 成员身份。

```yaml
vlans:
  - vlan_id: 100
    name: "Management"
    tagged_ports: ["ens34", "ens36"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "Servers"
    tagged_ports: ["ens34"]
    untagged_ports: []
```

| 键 (Key) | 类型 | 描述 |
|-----|------|-------------|
| `vlan_id` | int | VLAN 标识符 (1–4094) |
| `name` | string | 人类可读的 VLAN 名称 |
| `tagged_ports` | string[] | 为该 VLAN 发送/接收打标签帧的接口 |
| `untagged_ports` | string[] | 为该 VLAN 发送/接收未打标签帧的接口 |

## VOQd 配置部分

配置 VOQd 用户空间 QoS 调度器。有关部署详情，请参阅 [VOQd 设置](VOQd_Setup.md)。

```yaml
voqd_config:
  # 基础
  enabled: true
  mode: active           # bypass | shadow | active
  num_ports: 4
  prio_mask: 0x0C        # 要拦截的优先级 (位掩码 bitmask)

  # AF_XDP
  enable_afxdp: true
  zero_copy: false       # 需要 NIC 驱动支持
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  busy_poll: false

  # 调度器 (Scheduler)
  enable_scheduler: true
  cpu_affinity: 2        # 将 VOQd 绑定到特定的 CPU 核心
  
  # 软件队列 (用于没有硬件队列的 NIC)
  software_queues:
    enabled: false
    queue_depth: 1024
    num_priorities: 8
```

| 键 (Key) | 类型 | 描述 |
|-----|------|-------------|
| `enabled` | bool | 随 loader 自动启动 VOQd |
| `mode` | string | `bypass` (仅快路径), `shadow` (观察), `active` (完整 QoS) |
| `num_ports` | int | VOQd 管理的端口数量 |
| `prio_mask` | hex/int | 要拦截的优先级的位掩码 |
| `enable_afxdp` | bool | 启用 AF_XDP 数据平面 |
| `zero_copy` | bool | Zero-copy AF_XDP (需要 NIC 支持) |
| `rx_ring_size` | int | AF_XDP RX ring size |
| `tx_ring_size` | int | AF_XDP TX ring size |
| `frame_size` | int | UMEM 帧大小（字节） |
| `batch_size` | int | 每次 poll 的数据包批处理大小 |
| `poll_timeout_ms` | int | Poll 超时时间（毫秒） |
| `busy_poll` | bool | 启用 busy polling (更低延迟，更高 CPU 占用) |
| `enable_scheduler` | bool | 启用 DRR/WFQ 调度器 |
| `cpu_affinity` | int | 绑定 VOQd 线程的 CPU 核心 |
| `software_queues.enabled` | bool | 启用软件队列模拟 |
| `software_queues.queue_depth` | int | 每个软件队列的深度 |
| `software_queues.num_priorities` | int | 优先级层级数量 |

## 完整示例

```yaml
name: "Production L3 Router"
version: "1.0"
description: "带有 VLAN、ACL 和 QoS 的 L3 路由"

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
    name: "Users"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "Servers"
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

## 未来配置特性（计划中）

以下特性已设计但尚未实现：

- **Stage 覆盖**: 从 YAML 覆盖 ELF 定义的 stage 编号
- **可选 modules**: 根据构建标志或运行时条件进行条件加载
- **Module 子字段**: 逐个 module 的配置参数 (例如 ACL 最大规则数)
- **Profile 继承**: `inherits: base-profile.yaml` 用于配置复用
- **模板系统**: 带有变量替换的参数化 profiles

## 另请参阅

- [场景 Profile](../../usage/Scenario_Profiles.md) — 面向使用的 profile 指南
- [VOQd 设置](VOQd_Setup.md) — VOQd 部署
- [NIC 配置](NIC_Configuration.md) — NIC 特定设置
- [安装](Installation.md) — 从源码构建
