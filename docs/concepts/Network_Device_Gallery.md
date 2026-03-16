# Network Device Gallery / 网络设备类型库

> Build any network device from the same platform — just change the profile.
>
> 使用同一平台构建任何网络设备——只需更改配置文件。

---

## Table of Contents / 目录

1. [Overview / 概述](#1-overview--概述)
2. [L2 Switch / 二层交换机](#2-l2-switch--二层交换机)
3. [L3 Router / 三层路由器](#3-l3-router--三层路由器)
4. [Firewall / 防火墙](#4-firewall--防火墙)
5. [Load Balancer / 负载均衡器](#5-load-balancer--负载均衡器)
6. [NAT Gateway / NAT 网关](#6-nat-gateway--nat-网关)
7. [QoS Gateway / QoS 网关](#7-qos-gateway--qos-网关)
8. [Network Monitor / 网络监控设备](#8-network-monitor--网络监控设备)
9. [VPN Gateway / VPN 网关](#9-vpn-gateway--vpn-网关)
10. [Campus Edge Switch / 校园边缘交换机](#10-campus-edge-switch--校园边缘交换机)
11. [Data Center ToR / 数据中心接入交换机](#11-data-center-tor--数据中心接入交换机)
12. [Module Reference / 模块参考](#12-module-reference--模块参考)

---

## 1. Overview / 概述

**English:**

rSwitch is not a single-purpose network device — it's a platform for building **any** type of network device. By selecting different combinations of BPF modules in your profile, you can create:

- Layer 2 switches (VLAN, STP, MAC learning)
- Layer 3 routers (routing, ARP, ECMP)
- Firewalls (ACL, stateful inspection, rate limiting)
- Load balancers (flow distribution, health checks)
- NAT gateways (SNAT, DNAT, masquerading)
- QoS enforcement points (classification, scheduling)
- Network monitors (mirroring, sFlow, analytics)
- VPN gateways (VXLAN, GRE tunneling)
- Hybrid devices combining multiple functions

**中文:**

rSwitch 不是单一用途的网络设备——它是一个用于构建**任何**类型网络设备的平台。通过在配置文件中选择不同的 BPF 模块组合，您可以创建：

- 二层交换机（VLAN、STP、MAC 学习）
- 三层路由器（路由、ARP、ECMP）
- 防火墙（ACL、状态检测、速率限制）
- 负载均衡器（流分配、健康检查）
- NAT 网关（SNAT、DNAT、伪装）
- QoS 执行点（分类、调度）
- 网络监控设备（镜像、sFlow、分析）
- VPN 网关（VXLAN、GRE 隧道）
- 组合多种功能的混合设备

---

## 2. L2 Switch / 二层交换机

### Basic L2 Switch / 基本二层交换机

```yaml
# etc/profiles/l2-basic.yaml
name: "l2-basic"
description: "Basic L2 learning switch / 基本二层学习交换机"

ingress:
  - vlan           # VLAN classification / VLAN 分类
  - l2learn        # MAC address learning / MAC 地址学习
  - lastcall       # Final forwarding / 最终转发

egress:
  - egress_vlan    # VLAN tag handling / VLAN 标签处理
  - egress_final   # Packet delivery / 数据包传送

settings:
  mac_learning: true
  mac_aging_time: 300    # 5 minutes / 5 分钟
  default_vlan: 1
  unknown_unicast_flood: true
  broadcast_flood: true
```

**Features / 功能:**
- Dynamic MAC address learning / 动态 MAC 地址学习
- VLAN tagging and trunk/access ports / VLAN 标记和 Trunk/Access 端口
- Unknown unicast flooding / 未知单播泛洪
- Broadcast forwarding / 广播转发

### Enterprise L2 Switch with STP / 带 STP 的企业二层交换机

```yaml
# etc/profiles/l2-enterprise.yaml
name: "l2-enterprise"
description: "Enterprise L2 switch with STP and LACP / 带 STP 和 LACP 的企业二层交换机"

ingress:
  - lacp           # Link aggregation / 链路聚合
  - stp            # Spanning tree / 生成树
  - vlan
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Additional features / 额外功能:**
- Loop prevention via STP/RSTP / 通过 STP/RSTP 防止环路
- Link aggregation via LACP / 通过 LACP 链路聚合
- Suitable for multi-switch topologies / 适用于多交换机拓扑

---

## 3. L3 Router / 三层路由器

### Basic L3 Router / 基本三层路由器

```yaml
# etc/profiles/l3-basic.yaml
name: "l3-basic"
description: "Basic L3 router / 基本三层路由器"

ingress:
  - vlan
  - route          # L3 routing with ECMP / 带 ECMP 的三层路由
  - arp_learn      # Dynamic ARP learning / 动态 ARP 学习
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- Static and dynamic routing / 静态和动态路由
- ECMP (Equal Cost Multi-Path) / ECMP（等价多路径）
- ARP resolution / ARP 解析
- Inter-VLAN routing / VLAN 间路由

### High-Performance Router with Flow Table / 带流表的高性能路由器

```yaml
# etc/profiles/l3-highperf.yaml
name: "l3-highperf"
description: "High-performance router with flow caching / 带流缓存的高性能路由器"

ingress:
  - vlan
  - flow_table     # Hardware-style flow caching / 硬件风格流缓存
  - route
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Additional features / 额外功能:**
- Flow-based fast path / 基于流的快速路径
- First packet slow path, subsequent fast path / 首包慢路径，后续快速路径
- Reduced per-packet processing / 减少每包处理

---

## 4. Firewall / 防火墙

### Stateless Firewall / 无状态防火墙

```yaml
# etc/profiles/firewall-stateless.yaml
name: "firewall-stateless"
description: "Stateless packet filter / 无状态包过滤器"

ingress:
  - vlan
  - acl            # Access control lists / 访问控制列表
  - rate_limiter   # Rate limiting / 速率限制
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- 5-tuple ACL matching (src/dst IP, src/dst port, protocol) / 五元组 ACL 匹配
- Rate limiting per-rule / 按规则速率限制
- Deny logging / 拒绝日志记录

### Stateful Firewall / 状态防火墙

```yaml
# etc/profiles/firewall-stateful.yaml
name: "firewall-stateful"
description: "Stateful firewall with connection tracking / 带连接跟踪的状态防火墙"

ingress:
  - vlan
  - acl
  - conntrack      # Stateful connection tracking / 状态连接跟踪
  - rate_limiter
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Additional features / 额外功能:**
- Connection state tracking (NEW, ESTABLISHED, RELATED) / 连接状态跟踪
- Return traffic automatically allowed / 返回流量自动允许
- Connection timeout management / 连接超时管理

---

## 5. Load Balancer / 负载均衡器

```yaml
# etc/profiles/load-balancer.yaml
name: "load-balancer"
description: "L4 load balancer / 四层负载均衡器"

ingress:
  - vlan
  - acl
  - conntrack
  - flow_table     # Consistent hashing / 一致性哈希
  - nat            # DNAT to backend servers / DNAT 到后端服务器
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- L4 (TCP/UDP) load balancing / 四层负载均衡
- Consistent hash-based backend selection / 基于一致性哈希的后端选择
- Session persistence via flow table / 通过流表实现会话保持
- Health check integration (via user-space daemon) / 健康检查集成

**Use cases / 使用场景:**
- Web server farms / Web 服务器集群
- Database clusters / 数据库集群
- Microservice ingress / 微服务入口

---

## 6. NAT Gateway / NAT 网关

### Source NAT (Masquerading) / 源 NAT（伪装）

```yaml
# etc/profiles/nat-snat.yaml
name: "nat-snat"
description: "Source NAT gateway / 源 NAT 网关"

ingress:
  - vlan
  - conntrack
  - nat            # SNAT/masquerade / 源 NAT/伪装
  - route
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- Outbound NAT for private networks / 私有网络出站 NAT
- Port address translation (PAT) / 端口地址转换
- Connection tracking for return traffic / 返回流量连接跟踪

### Destination NAT (Port Forwarding) / 目的 NAT（端口转发）

```yaml
# etc/profiles/nat-dnat.yaml
name: "nat-dnat"
description: "Destination NAT gateway / 目的 NAT 网关"

ingress:
  - vlan
  - conntrack
  - nat            # DNAT/port forwarding / 目的 NAT/端口转发
  - route
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- Inbound port forwarding / 入站端口转发
- Expose internal services externally / 向外部公开内部服务
- 1:1 NAT for DMZ servers / DMZ 服务器 1:1 NAT

---

## 7. QoS Gateway / QoS 网关

```yaml
# etc/profiles/qos-gateway.yaml
name: "qos-gateway"
description: "QoS enforcement gateway / QoS 执行网关"

ingress:
  - vlan
  - qos_classify   # Traffic classification / 流量分类
  - rate_limiter   # Ingress policing / 入口限速
  - acl
  - afxdp_redirect # Redirect to VOQd / 重定向到 VOQd
  - l2learn
  - lastcall

egress:
  - egress_qos     # Egress scheduling / 出口调度
  - egress_vlan
  - egress_final

voqd_config:
  enabled: true
  mode: active
  enable_scheduler: true
```

**Features / 功能:**
- DSCP/PCP-based classification / 基于 DSCP/PCP 分类
- 8 priority queues per port / 每端口 8 个优先级队列
- DRR/WFQ scheduling via VOQd / 通过 VOQd 的 DRR/WFQ 调度
- Token bucket rate limiting / 令牌桶速率限制

**Use cases / 使用场景:**
- VoIP prioritization / VoIP 优先级
- Video conferencing QoS / 视频会议 QoS
- SLA enforcement / SLA 执行

---

## 8. Network Monitor / 网络监控设备

### Traffic Mirror (SPAN) / 流量镜像

```yaml
# etc/profiles/monitor-span.yaml
name: "monitor-span"
description: "Traffic mirroring / 流量镜像"

ingress:
  - vlan
  - acl
  - mirror         # Port mirroring / 端口镜像
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- Local port mirroring (SPAN) / 本地端口镜像
- RSPAN (remote span via VLAN) / 远程 SPAN（通过 VLAN）
- ERSPAN (encapsulated remote span) / 封装远程 SPAN
- Selective mirroring via ACL / 通过 ACL 选择性镜像

### sFlow Collector / sFlow 收集器

```yaml
# etc/profiles/monitor-sflow.yaml
name: "monitor-sflow"
description: "sFlow traffic analysis / sFlow 流量分析"

ingress:
  - vlan
  - acl
  - sflow          # sFlow v5 sampling / sFlow v5 采样
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- sFlow v5 packet sampling / sFlow v5 数据包采样
- Configurable sample rate / 可配置采样率
- Export to sFlow collector / 导出到 sFlow 收集器
- Flow visibility without full capture / 无需完整捕获即可获得流可见性

---

## 9. VPN Gateway / VPN 网关

```yaml
# etc/profiles/vpn-gateway.yaml
name: "vpn-gateway"
description: "VXLAN/GRE tunnel gateway / VXLAN/GRE 隧道网关"

ingress:
  - tunnel         # VXLAN/GRE decapsulation / VXLAN/GRE 解封装
  - vlan
  - acl
  - route
  - l2learn
  - lastcall

egress:
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- VXLAN overlay networking / VXLAN 覆盖网络
- GRE tunneling / GRE 隧道
- Tunnel termination / 隧道终结
- Multi-tenant isolation / 多租户隔离

**Use cases / 使用场景:**
- Data center overlay networks / 数据中心覆盖网络
- Site-to-site VPN / 站点间 VPN
- Cloud connectivity / 云连接

---

## 10. Campus Edge Switch / 校园边缘交换机

```yaml
# etc/profiles/campus-edge.yaml
name: "campus-edge"
description: "Campus network edge switch / 校园网边缘交换机"

ingress:
  - lldp           # Neighbor discovery / 邻居发现
  - stp            # Loop prevention / 环路防止
  - source_guard   # IP source validation / IP 源验证
  - dhcp_snoop     # DHCP snooping / DHCP 监听
  - vlan
  - acl
  - qos_classify
  - l2learn
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final
```

**Features / 功能:**
- IP source guard prevents spoofing / IP 源防护防止欺骗
- DHCP snooping builds binding table / DHCP 监听构建绑定表
- Rogue DHCP server prevention / 恶意 DHCP 服务器防护
- Per-user QoS / 每用户 QoS
- LLDP topology discovery / LLDP 拓扑发现

**Ideal for / 适用于:**
- University networks / 大学网络
- Enterprise access layer / 企业接入层
- Guest network isolation / 访客网络隔离

---

## 11. Data Center ToR / 数据中心接入交换机

```yaml
# etc/profiles/datacenter-tor.yaml
name: "datacenter-tor"
description: "Data center top-of-rack switch / 数据中心机架顶交换机"

ingress:
  - lacp           # Link aggregation / 链路聚合
  - tunnel         # VXLAN overlay / VXLAN 覆盖
  - vlan
  - acl
  - flow_table     # Fast path / 快速路径
  - route
  - qos_classify
  - l2learn
  - lastcall

egress:
  - egress_qos
  - egress_vlan
  - egress_final

voqd_config:
  enabled: true
  mode: active
```

**Features / 功能:**
- VXLAN fabric integration / VXLAN 网络集成
- ECMP to spine layer / ECMP 到脊柱层
- Microsecond latency QoS / 微秒级延迟 QoS
- High-density port aggregation / 高密度端口聚合
- Flow-based optimization / 基于流的优化

**Ideal for / 适用于:**
- Hyperscale data centers / 超大规模数据中心
- Private cloud / 私有云
- Container networking / 容器网络

---

## 12. Module Reference / 模块参考

### Core Modules (Always Required) / 核心模块（始终需要）

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `dispatcher` | 10 | Pipeline entry point / 管道入口点 |
| `lastcall` | 90 | Final forwarding decision / 最终转发决策 |
| `egress` | — | Devmap egress callback / Devmap 出口回调 |
| `egress_final` | 190 | Packet delivery / 数据包传送 |

### L2 Modules / 二层模块

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `vlan` | 20 | VLAN classification and filtering / VLAN 分类和过滤 |
| `egress_vlan` | 180 | VLAN tag insertion/removal / VLAN 标签插入/移除 |
| `l2learn` | 80 | MAC address learning / MAC 地址学习 |
| `stp` | 12 | Spanning Tree Protocol / 生成树协议 |
| `lacp` | 11 | Link Aggregation Control / 链路聚合控制 |
| `lldp` | 11 | Link Layer Discovery / 链路层发现 |

### L3 Modules / 三层模块

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `route` | 50 | L3 routing with ECMP / 带 ECMP 的三层路由 |
| `arp_learn` | 80 | Dynamic ARP learning / 动态 ARP 学习 |
| `conntrack` | 32 | Connection tracking / 连接跟踪 |
| `nat` | 55 | NAT (SNAT/DNAT) / NAT（源/目的） |
| `flow_table` | 60 | Flow-based fast path / 基于流的快速路径 |

### Security Modules / 安全模块

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `acl` | 30 | Access control lists / 访问控制列表 |
| `source_guard` | 18 | IP source validation / IP 源验证 |
| `dhcp_snoop` | 19 | DHCP snooping / DHCP 监听 |
| `rate_limiter` | 28 | Rate limiting / 速率限制 |

### QoS Modules / QoS 模块

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `qos_classify` | 25 | Traffic classification / 流量分类 |
| `egress_qos` | 170 | Egress scheduling / 出口调度 |
| `afxdp_redirect` | 85 | AF_XDP QoS offload / AF_XDP QoS 卸载 |

### Monitoring Modules / 监控模块

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `mirror` | 45 | Traffic mirroring / 流量镜像 |
| `sflow` | 85 | sFlow v5 sampling / sFlow v5 采样 |

### Tunneling Modules / 隧道模块

| Module | Stage | Description / 描述 |
|--------|-------|-------------------|
| `tunnel` | 15 | VXLAN/GRE decap / VXLAN/GRE 解封装 |

---

## Choosing Modules / 选择模块

### Decision Tree / 决策树

```
Start / 开始
    │
    ├── Need L3 routing? / 需要三层路由？
    │   ├── Yes → Add: route, arp_learn
    │   └── No → Basic L2 only
    │
    ├── Need security? / 需要安全？
    │   ├── Yes → Add: acl
    │   │   ├── Stateful? → Add: conntrack
    │   │   └── Rate limiting? → Add: rate_limiter
    │   └── No → Skip ACL
    │
    ├── Need NAT? / 需要 NAT？
    │   ├── Yes → Add: conntrack, nat
    │   └── No → Skip NAT
    │
    ├── Need QoS? / 需要 QoS？
    │   ├── Yes → Add: qos_classify, egress_qos
    │   │   └── Advanced? → Enable VOQd
    │   └── No → Skip QoS
    │
    ├── Need monitoring? / 需要监控？
    │   ├── Mirror → Add: mirror
    │   ├── sFlow → Add: sflow
    │   └── No → Skip monitoring
    │
    └── Special requirements? / 特殊需求？
        ├── Campus security → Add: source_guard, dhcp_snoop
        ├── Loop prevention → Add: stp
        ├── Link aggregation → Add: lacp
        └── Overlay network → Add: tunnel
```

---

## See Also / 另请参阅

- [Reconfigurable Architecture](Reconfigurable_Architecture.md) — Platform concepts / 平台概念
- [Framework Guide](Framework_Guide.md) — How to use the framework / 如何使用框架
- [Scenario Profiles](../usage/Scenario_Profiles.md) — Pre-built profiles / 预置配置文件
- [Module Developer Guide](../development/Module_Developer_Guide.md) — Write custom modules / 编写自定义模块

---

*Last updated / 最后更新: 2026-03-17*
