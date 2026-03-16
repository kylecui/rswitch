# Reconfigurable Architecture / 可重构架构

> **rSwitch** — A software-defined, reconfigurable network device platform built on XDP/eBPF.
>
> **rSwitch** — 基于 XDP/eBPF 构建的软件定义可重构网络设备平台。

---

## Table of Contents / 目录

1. [What is Reconfigurability? / 什么是可重构性？](#1-what-is-reconfigurability--什么是可重构性)
2. [The Problem with Traditional Switches / 传统交换机的问题](#2-the-problem-with-traditional-switches--传统交换机的问题)
3. [How rSwitch Solves It / rSwitch 如何解决](#3-how-rswitch-solves-it--rswitch-如何解决)
4. [Core Design Principles / 核心设计原则](#4-core-design-principles--核心设计原则)
5. [Architecture Overview / 架构概览](#5-architecture-overview--架构概览)
6. [Profile-Driven Configuration / 配置文件驱动](#6-profile-driven-configuration--配置文件驱动)
7. [Module Pipeline / 模块管道](#7-module-pipeline--模块管道)
8. [Benefits / 优势](#8-benefits--优势)
9. [Use Cases / 使用场景](#9-use-cases--使用场景)

---

## 1. What is Reconfigurability? / 什么是可重构性？

**English:**

Reconfigurability means the ability to change a network device's behavior and capabilities at runtime, without replacing hardware or firmware. Instead of fixed-function pipelines burned into ASICs, rSwitch uses software-defined BPF modules that can be loaded, unloaded, and reloaded dynamically.

Think of it like smartphone apps: you don't buy a new phone to get a new feature — you install an app. Similarly, with rSwitch, you don't buy new hardware to add L3 routing, QoS, or firewall capabilities — you load the corresponding modules.

**中文:**

可重构性是指在运行时改变网络设备行为和能力的能力，无需更换硬件或固件。rSwitch 不使用固化在 ASIC 中的固定功能管道，而是使用可以动态加载、卸载和重新加载的软件定义 BPF 模块。

可以把它想象成智能手机应用：您不需要买新手机来获得新功能——只需安装一个应用。同样，使用 rSwitch，您不需要购买新硬件来添加三层路由、QoS 或防火墙功能——只需加载相应的模块。

---

## 2. The Problem with Traditional Switches / 传统交换机的问题

**English:**

Traditional network switches have fixed pipelines implemented in hardware (ASIC/FPGA):

```
┌─────────────────────────────────────────────────┐
│           Traditional Switch (Fixed)             │
├─────────────────────────────────────────────────┤
│  L2 Parse → VLAN → ACL → L3 Route → QoS → Out  │
│                                                  │
│  • All stages always active (even if unused)     │
│  • Cannot add new features without firmware      │
│  • Cannot remove unused features to save CPU     │
│  • Vendor-specific, closed ecosystem             │
│  • Expensive hardware for each capability tier   │
└─────────────────────────────────────────────────┘
```

Problems:
- **Inflexibility**: Need L2-only switch? You still pay for L3 silicon.
- **Upgrade friction**: New feature requires firmware update or hardware swap.
- **Vendor lock-in**: Custom CLI, proprietary protocols, closed APIs.
- **Over-provisioning**: Buy the top-tier model "just in case" you need features later.

**中文:**

传统网络交换机在硬件（ASIC/FPGA）中实现固定管道：

```
┌─────────────────────────────────────────────────┐
│           传统交换机（固定）                      │
├─────────────────────────────────────────────────┤
│  L2解析 → VLAN → ACL → L3路由 → QoS → 输出      │
│                                                  │
│  • 所有阶段始终激活（即使未使用）                 │
│  • 无法在没有固件的情况下添加新功能               │
│  • 无法移除未使用的功能以节省 CPU                │
│  • 厂商特定，封闭生态系统                        │
│  • 每个功能层级都需要昂贵的硬件                  │
└─────────────────────────────────────────────────┘
```

问题：
- **不灵活**：只需要二层交换机？您仍然要为三层芯片付费。
- **升级困难**：新功能需要固件更新或更换硬件。
- **厂商锁定**：自定义 CLI、专有协议、封闭 API。
- **过度配置**：购买顶级型号"以防万一"以后需要功能。

---

## 3. How rSwitch Solves It / rSwitch 如何解决

**English:**

rSwitch inverts the traditional model. Instead of fixed pipelines, it provides a **profile-driven, modular architecture**:

```
┌─────────────────────────────────────────────────┐
│              rSwitch (Reconfigurable)            │
├─────────────────────────────────────────────────┤
│  Profile: campus.yaml                            │
│    modules:                                      │
│      - vlan        # Only load what you need    │
│      - acl                                       │
│      - l2learn                                   │
│      - lastcall                                  │
│                                                  │
│  • No routing? Don't load the route module      │
│  • Need QoS later? Add module, reload profile   │
│  • Hot-reload modules without traffic loss      │
│  • Open standards: YAML, BPF, Linux APIs        │
│  • Runs on commodity x86 with XDP-capable NIC   │
└─────────────────────────────────────────────────┘
```

Key innovations:
- **YAML profiles** select which modules run
- **BPF modules** are self-contained network functions
- **Hot-reload** swaps modules at runtime
- **CO-RE** (Compile Once, Run Everywhere) ensures portability

**中文:**

rSwitch 颠覆了传统模式。它提供**配置文件驱动的模块化架构**，而非固定管道：

```
┌─────────────────────────────────────────────────┐
│              rSwitch（可重构）                   │
├─────────────────────────────────────────────────┤
│  配置文件: campus.yaml                           │
│    modules:                                      │
│      - vlan        # 只加载您需要的              │
│      - acl                                       │
│      - l2learn                                   │
│      - lastcall                                  │
│                                                  │
│  • 不需要路由？不要加载路由模块                  │
│  • 以后需要 QoS？添加模块，重新加载配置文件      │
│  • 热重载模块而不丢失流量                        │
│  • 开放标准：YAML、BPF、Linux API               │
│  • 在支持 XDP 的普通 x86 网卡上运行              │
└─────────────────────────────────────────────────┘
```

关键创新：
- **YAML 配置文件**选择运行哪些模块
- **BPF 模块**是独立的网络功能
- **热重载**在运行时替换模块
- **CO-RE**（一次编译，到处运行）确保可移植性

---

## 4. Core Design Principles / 核心设计原则

### Reconfigurability / 可重构性

| English | 中文 |
|---------|------|
| YAML profiles select modules at load time | YAML 配置文件在加载时选择模块 |
| Hot-reload swaps modules at runtime | 热重载在运行时替换模块 |
| Operators compose custom network functions | 运维人员组合自定义网络功能 |
| No code changes required | 无需代码更改 |

### Modularity / 模块化

| English | 中文 |
|---------|------|
| Each function is an independent BPF program | 每个功能是独立的 BPF 程序 |
| Self-describing metadata embedded in ELF | 自描述元数据嵌入 ELF |
| Modules developed, tested, deployed independently | 模块独立开发、测试、部署 |
| Clean API boundaries | 清晰的 API 边界 |

### Performance / 性能

| English | 中文 |
|---------|------|
| XDP processes packets at driver level | XDP 在驱动级别处理数据包 |
| Zero-copy paths via AF_XDP | 通过 AF_XDP 实现零拷贝路径 |
| Wire-speed on commodity hardware | 在普通硬件上达到线速 |
| Per-CPU state eliminates locks | 每 CPU 状态消除锁竞争 |

### CO-RE Portability / CO-RE 可移植性

| English | 中文 |
|---------|------|
| Compile Once, Run Everywhere | 一次编译，到处运行 |
| Uses vmlinux.h and libbpf | 使用 vmlinux.h 和 libbpf |
| Modules work across kernel versions | 模块跨内核版本工作 |
| No per-kernel recompilation | 无需针对每个内核重新编译 |

### Safety / 安全性

| English | 中文 |
|---------|------|
| BPF verifier enforces memory safety | BPF 验证器强制内存安全 |
| No kernel crashes from module bugs | 模块错误不会导致内核崩溃 |
| Bounded loops, safe pointer arithmetic | 有界循环，安全指针运算 |
| Sandboxed execution | 沙箱化执行 |

### Observability / 可观测性

| English | 中文 |
|---------|------|
| Unified event bus for all modules | 所有模块统一事件总线 |
| Per-module statistics | 每模块统计 |
| Prometheus metrics, sFlow sampling | Prometheus 指标，sFlow 采样 |
| Full pipeline visibility | 完整管道可见性 |

---

## 5. Architecture Overview / 架构概览

**English:**

rSwitch consists of three layers:

```
┌─────────────────────────────────────────────────────────────┐
│                     USER SPACE                               │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │
│  │  Profile │  │  Loader  │  │  CLI     │  │  Daemons     │ │
│  │  (YAML)  │──│ (loader) │  │ (rsctl)  │  │ (voqd,stpd..)│ │
│  └──────────┘  └────┬─────┘  └──────────┘  └──────────────┘ │
│                     │                                        │
│              ┌──────┴──────┐                                 │
│              │  BPF Maps   │  /sys/fs/bpf/rs_*              │
│              └──────┬──────┘                                 │
├─────────────────────┼───────────────────────────────────────┤
│                KERNEL SPACE                                  │
├─────────────────────┼───────────────────────────────────────┤
│                     ▼                                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              XDP INGRESS PIPELINE                       │ │
│  │  dispatcher → vlan → acl → route → l2learn → lastcall  │ │
│  └────────────────────────────────────────────────────────┘ │
│                     │                                        │
│                     ▼ XDP_REDIRECT                           │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              XDP EGRESS PIPELINE                        │ │
│  │  egress → egress_qos → egress_vlan → egress_final      │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**中文:**

rSwitch 由三层组成：

- **用户空间**：配置文件、加载器、CLI 工具、守护进程
- **BPF Maps**：内核和用户空间之间的共享状态
- **内核空间**：XDP 入口和出口管道

---

## 6. Profile-Driven Configuration / 配置文件驱动

**English:**

Profiles are YAML files that define the complete switch personality:

```yaml
# etc/profiles/l2-switch.yaml
name: "l2-switch"
description: "Basic L2 learning switch with VLAN support"

ingress:
  - vlan           # VLAN classification
  - l2learn        # MAC address learning
  - lastcall       # Final forwarding

egress:
  - egress_vlan    # VLAN tag insertion
  - egress_final   # Packet delivery

settings:
  mac_learning: true
  mac_aging_time: 300
  default_vlan: 1

ports:
  - interface: "ens34"
    vlan_mode: trunk
    native_vlan: 1
    allowed_vlans: [1, 100, 200]
```

**中文:**

配置文件是定义完整交换机特性的 YAML 文件：

```yaml
# etc/profiles/l2-switch.yaml
name: "l2-switch"
description: "支持 VLAN 的基本二层学习交换机"

ingress:
  - vlan           # VLAN 分类
  - l2learn        # MAC 地址学习
  - lastcall       # 最终转发

egress:
  - egress_vlan    # VLAN 标签插入
  - egress_final   # 数据包传送

settings:
  mac_learning: true
  mac_aging_time: 300
  default_vlan: 1

ports:
  - interface: "ens34"
    vlan_mode: trunk
    native_vlan: 1
    allowed_vlans: [1, 100, 200]
```

---

## 7. Module Pipeline / 模块管道

**English:**

Modules are chained via BPF tail calls. Each module:
1. Reads shared context (`rs_ctx`)
2. Performs its function
3. Calls `RS_TAIL_CALL_NEXT()` to continue the pipeline

```
Packet → dispatcher → [module1] → [module2] → ... → lastcall → egress
              │            │           │                │
              └────────────┴───────────┴────────────────┘
                    rs_ctx shared across all modules
```

Modules are assigned **stage numbers** that determine execution order:
- Stage 10-19: Entry processing (dispatcher, protocol intercept)
- Stage 20-29: Classification (VLAN, QoS)
- Stage 30-49: Security (ACL, rate limiting)
- Stage 50-79: Forwarding (routing, NAT, flow table)
- Stage 80-89: Learning and monitoring
- Stage 90: Final forwarding (lastcall)
- Stage 170-190: Egress processing

**中文:**

模块通过 BPF 尾调用链接。每个模块：
1. 读取共享上下文（`rs_ctx`）
2. 执行其功能
3. 调用 `RS_TAIL_CALL_NEXT()` 继续管道

模块被分配**阶段号**来决定执行顺序：
- 阶段 10-19：入口处理（调度器、协议拦截）
- 阶段 20-29：分类（VLAN、QoS）
- 阶段 30-49：安全（ACL、速率限制）
- 阶段 50-79：转发（路由、NAT、流表）
- 阶段 80-89：学习和监控
- 阶段 90：最终转发（lastcall）
- 阶段 170-190：出口处理

---

## 8. Benefits / 优势

### For Network Operators / 对于网络运维人员

| Benefit | Description / 描述 |
|---------|-------------------|
| **Flexibility** | Load exactly the features you need / 精确加载您需要的功能 |
| **Cost savings** | Commodity hardware, no vendor lock-in / 普通硬件，无厂商锁定 |
| **Fast updates** | Hot-reload without traffic loss / 热重载无流量丢失 |
| **Easy debugging** | Full observability via event bus / 通过事件总线完全可观测 |

### For Developers / 对于开发者

| Benefit | Description / 描述 |
|---------|-------------------|
| **Clean APIs** | Stable SDK with versioned ABI / 带版本控制 ABI 的稳定 SDK |
| **Independent dev** | Modules built/tested separately / 模块独立构建/测试 |
| **Familiar tools** | Standard Linux, BPF, Prometheus / 标准 Linux、BPF、Prometheus |
| **Open ecosystem** | Contribute modules to marketplace / 向市场贡献模块 |

### For Organizations / 对于组织

| Benefit | Description / 描述 |
|---------|-------------------|
| **Customization** | Tailor network functions to needs / 根据需求定制网络功能 |
| **Future-proof** | Add capabilities without hardware / 无需硬件即可添加功能 |
| **Compliance** | Policy verification before deploy / 部署前策略验证 |
| **Multi-switch** | Centralized management via controller / 通过控制器集中管理 |

---

## 9. Use Cases / 使用场景

### Campus Network Switch / 校园网交换机
```yaml
modules: [vlan, acl, source_guard, dhcp_snoop, l2learn, stp]
```
- VLAN segmentation for departments / 部门 VLAN 分段
- IP source guard against spoofing / IP 源防护防止欺骗
- DHCP snooping for rogue prevention / DHCP 监听防止恶意服务器
- STP for loop prevention / STP 防止环路

### Data Center Top-of-Rack / 数据中心接入层交换机
```yaml
modules: [vlan, acl, route, flow_table, qos_classify, egress_qos]
```
- L3 routing with ECMP / 带 ECMP 的三层路由
- Flow-based fast path / 基于流的快速路径
- QoS for tenant isolation / QoS 实现租户隔离

### Security Gateway / 安全网关
```yaml
modules: [acl, conntrack, nat, rate_limiter, mirror]
```
- Stateful firewall / 状态防火墙
- NAT for address translation / NAT 地址转换
- Rate limiting for DDoS mitigation / 速率限制缓解 DDoS
- Traffic mirroring for IDS / 流量镜像用于入侵检测

### Carrier Edge Router / 运营商边缘路由器
```yaml
modules: [tunnel, route, nat, qos_classify, egress_qos, sflow]
```
- VXLAN/GRE tunneling / VXLAN/GRE 隧道
- Complex routing policies / 复杂路由策略
- Strict QoS enforcement / 严格 QoS 执行
- sFlow for traffic analysis / sFlow 流量分析

---

## See Also / 另请参阅

- [Network Device Gallery](Network_Device_Gallery.md) — Types of devices you can build / 可构建的设备类型
- [Framework Guide](Framework_Guide.md) — How to use the framework / 如何使用框架
- [Platform Architecture](../development/Platform_Architecture.md) — Deep technical details / 深入技术细节
- [Module Developer Guide](../development/Module_Developer_Guide.md) — Write your own modules / 编写自己的模块

---

*Last updated / 最后更新: 2026-03-17*
