> 📖 [English Version](../../development/Architecture.md)

# 架构概览 (Architecture Overview)

本文档描述了 rSwitch 架构 —— 一个基于 XDP/eBPF 构建的可重构网络交换机。理解该架构对于开发 module、扩展平台或为核心代码做贡献至关重要。

---

## 设计理念 (Design Philosophy)

rSwitch 使用软件定义、profile 驱动的数据包处理 pipeline 取代了固定的 ASIC pipeline。设计遵循以下六个原则：

| 原则 | 机制 |
|-----------|-----------|
| **模块化 (Modularity)** | 基于阶段 (Stage) 的 pipeline；module 是独立的 BPF 程序 |
| **可重构性 (Reconfigurability)** | YAML profile 控制加载哪些 module 以及加载顺序 |
| **CO-RE 可移植性 (CO-RE Portability)** | BPF module 使用 CO-RE 模式（`vmlinux.h`, libbpf）以实现跨内核兼容性 |
| **安全性 (Safety)** | 通过边界检查、偏移掩码 (`& 0x3F`) 确保符合 BPF verifier 要求 |
| **性能 (Performance)** | 使用 AF_XDP + VOQd 实现零拷贝路径和基于队列的调度 |
| **可观测性 (Observability)** | 每个 module 拥有 pinning 的 map 和统一的事件总线 (event bus)，为操作员提供可见性 |

> 当源代码与文档冲突时，以 `rswitch/` 下的 C 源码为准。

---

## 系统架构 (System Architecture)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Profile YAML    │───>│  rswitch_loader  │───>│   VOQd (QoS)     │      │
│  │  l3-qos.yaml     │    │  (orchestrator)  │    │  AF_XDP sockets  │      │
│  └──────────────────┘    └────────┬─────────┘    └──────────────────┘      │
│                                   │                                        │
│            ┌──────────────────────┼──────────────────────┐                 │
│            │      BPF Maps (pinned in /sys/fs/bpf)       │                 │
│            │  rs_progs, rs_ctx_map, rs_prog_chain, ...   │                 │
│            └──────────────────────┼──────────────────────┘                 │
│                                   │                                        │
│  ┌──────────────────────────────────────────────────────────┐              │
│  │  CLI Tools: rswitchctl, rsvlanctl, rsaclctl, rsqosctl   │              │
│  └──────────────────────────────────────────────────────────┘              │
│                                                                            │
├────────────────────────────────────┼───────────────────────────────────────┤
│                              KERNEL SPACE                                  │
├────────────────────────────────────┼───────────────────────────────────────┤
│                                    ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        XDP INGRESS PIPELINE                           │ │
│  │  ┌──────────┐  ┌──────┐  ┌─────┐  ┌───────┐  ┌────────┐ ┌────────┐  │ │
│  │  │dispatcher│─>│ vlan │─>│ acl │─>│ route │─>│l2learn │─>│lastcall│  │ │
│  │  │ (entry)  │  │st=20 │  │st=30│  │ st=50 │  │ st=80  │ │ st=90  │  │ │
│  │  └──────────┘  └──────┘  └─────┘  └───────┘  └────────┘ └────────┘  │ │
│  │       │            │         │         │          │           │       │ │
│  │       └────────────┴─────────┴─────────┴──────────┴───────────┘       │ │
│  │                     (tail-call chain via rs_progs)                     │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                    │                                       │
│                                    ▼ XDP_REDIRECT                          │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        XDP EGRESS PIPELINE                            │ │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────────┐                      │ │
│  │  │  egress  │──>│egress_qos│──>│ egress_final │                      │ │
│  │  │ (devmap) │   │ st=170   │   │   st=190     │                      │ │
│  │  └──────────┘   └──────────┘   └──────────────┘                      │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 可重构性的三大支柱 (The Three Pillars of Reconfigurability)

| 支柱 | 机制 | 收益 |
|--------|-----------|---------|
| **Module 自注册 (Module Self-Registration)** | `RS_DECLARE_MODULE()` 宏将元数据嵌入 ELF 的 `.rodata.mod` 节 (section) | Loader 自动发现 module —— 无需硬编码列表 |
| **Profile 驱动加载 (Profile-Driven Loading)** | YAML 文件指定 module 选择和端口配置 | 操作员无需修改代码即可控制 pipeline |
| **动态 Pipeline 构建 (Dynamic Pipeline Construction)** | 在运行时构建 tail-call `rs_progs` 数组 | Pipeline 组合发生在加载时，而非编译时 |

---

## 核心组件 (Core Components)

### 1. Dispatcher (`dispatcher.bpf.o`)

附加到每个网络接口的 XDP 入口点。职责：

- 初始化 per-CPU context (`rs_ctx`)
- 解析 Ethernet 报头
- 执行初始数据包分类
- Tail-call 调用 ingress pipeline 中的第一个 module

### 2. Egress Handler (`egress.bpf.o`)

作为 devmap 回调附加。当数据包通过 `bpf_redirect_map()` 重定向时，egress handler 会：

- 在目标接口接收数据包
- 启动 egress tail-call 链（槽位 255, 254, ...）

### 3. Module Pipeline

Module 通过 BPF tail-call 按阶段编号 (stage-number) 顺序执行：

- **Ingress** (阶段 10-99): `dispatcher → vlan(20) → acl(30) → route(50) → l2learn(80) → lastcall(90)`
- **Egress** (阶段 100-199): `egress(devmap) → egress_qos(170) → egress_vlan(180) → egress_final(190)`

每个 module：
1. 调用 `RS_GET_CTX()` 获取共享的 per-CPU context
2. 执行其处理逻辑
3. 调用 `RS_TAIL_CALL_NEXT()` 调用下一个 module

### 4. VOQd 调度器 (`rswitch-voqd`)

使用 AF_XDP socket 的用户态 QoS 调度器：

| 模式 | 值 | 行为 |
|------|-------|----------|
| BYPASS | 0 | 无 QoS —— 仅走快速路径 (fast path) |
| SHADOW | 1 | 观察模式 —— 监控流量而不影响转发 |
| ACTIVE | 2 | 全量 QoS —— 数据包通过优先级队列和调度 |

特性：DRR/WFQ 调度、零拷贝 AF_XDP、可配置优先级队列、心跳超时自动故障切换。

### 5. Loader (`rswitch_loader`)

将一切联系在一起的用户态编排器：

```
1. DISCOVERY (发现)     — 扫描 build/bpf/*.bpf.o，读取 .rodata.mod ELF 节
2. FILTERING (过滤)     — 将发现的 module 与 YAML profile 进行匹配
3. SORTING (排序)       — 按阶段编号排序（ingress 升序，egress 降序）
4. CONSTRUCTION (构建)  — 加载 BPF 对象，填充 rs_progs 数组，配置 rs_prog_chain
5. ATTACHMENT (挂载)    — 将 dispatcher 附加到接口，配置 devmap，应用端口配置
```

### 6. CLI 工具

| 工具 | 用途 |
|------|---------|
| `rswitchctl` | Pipeline 状态、统计信息、MAC 表管理 |
| `rsvlanctl` | VLAN 配置（添加/删除 VLAN，端口成员关系） |
| `rsaclctl` | ACL 规则管理（添加/删除/显示规则） |
| `rsqosctl` | QoS 统计信息、队列状态、优先级设置 |
| `rsvoqctl` | VOQd 模式控制和监控 |

---

## 阶段编号约定 (Stage Numbering Convention)

### Ingress Pipeline (阶段 10-99)

| 范围 | 阶段 | Module |
|-------|-------|---------|
| 10-19 | 预处理 | 报头校验、归一化 |
| 20-29 | VLAN 处理 | `vlan` (20) |
| 30-39 | 安全 | `acl` (30) |
| 40-49 | 镜像 (Mirroring) | `mirror` (40) |
| 50-69 | 路由 / QoS 分类 | `route` (50) |
| 70-79 | 保留 | — |
| 80-89 | 学习 / AF_XDP | `l2learn` (80), `afxdp_redirect` (85) |
| 90-99 | 最终转发 | `lastcall` (90) — **始终最后** |

### Egress Pipeline (阶段 100-199)

| 范围 | 阶段 | Module |
|-------|-------|---------|
| 100-139 | 保留 | — |
| 140-169 | 策略 | 速率限制、egress ACL |
| 170-179 | QoS | `egress_qos` (170) |
| 180-189 | VLAN 打标 | `egress_vlan` (180) |
| 190-199 | 最终 | `egress_final` (190) — **始终最后** |

### 槽位分配 (内部)

阶段编号定义逻辑顺序。实际的 `rs_progs` 数组槽位是动态分配的：

- **Ingress**: 槽位 0, 1, 2, ... (从 0 开始升序)
- **Egress**: 槽位 255, 254, 253, ... (从 255 开始降序)

这种分离确保了 ingress 和 egress module 永远不会在 prog_array 中发生冲突。

---

## 共享基础设施 (Shared Infrastructure)

### Per-CPU Context (`rs_ctx`)

所有 module 共享一个 per-CPU context，用于零拷贝、无锁的状态传播：

```c
struct rs_ctx {
    __u32 ifindex;              // Ingress 接口
    __u32 timestamp;            // 到达时间
    __u8  parsed, modified;     // 状态标志
    struct rs_layers layers;    // 解析后的 L2/L3/L4 偏移和值
    __u16 ingress_vlan, egress_vlan;
    __u8  prio, dscp, ecn, traffic_class;
    __u32 egress_ifindex;       // 目标输出端口
    __u8  action;               // XDP_PASS / XDP_DROP / XDP_REDIRECT
    __u8  mirror;               // 镜像标志
    __u16 mirror_port;
    __u32 error;                // RS_ERROR_* 代码
    __u32 drop_reason;          // RS_DROP_* 原因
    __u32 next_prog_id;         // 下一个要 tail-call 的 module
    __u32 call_depth;           // 递归保护
};
```

**设计初衷：**
- 无锁 —— 每个 CPU 拥有自己的 context
- 零拷贝 —— context 在 pipeline 处理过程中始终留在处理该包的 CPU 上
- 缓存友好 —— 数据保留在 L1/L2 缓存中

### 核心 Map

| Map | 类型 | 用途 |
|-----|------|---------|
| `rs_ctx_map` | PERCPU_ARRAY | module 之间传递每个数据包的 context |
| `rs_progs` | PROG_ARRAY | tail-call 目标（ingress + egress） |
| `rs_prog_chain` | ARRAY | 用于 egress 链式调用的下一个 module 查找 |
| `rs_port_config_map` | HASH | 每个端口的配置（VLAN 模式、学习等） |
| `rs_stats_map` | PERCPU_ARRAY | 每个接口的数据包/字节统计信息 |
| `rs_event_bus` | RINGBUF (1MB) | 通向用户态的统一事件通道 |
| `rs_mac_table` | HASH | MAC 地址转发表 |
| `rs_vlan_map` | HASH | VLAN 成员配置 |
| `rs_xdp_devmap` | DEVMAP_HASH | 数据包重定向目标 |

所有 map 都 pinning 在 `/sys/fs/bpf/rs_*` 下。

### 事件总线 (Event Bus)

Module 通过统一的 ring buffer 向用户态发送结构化事件：

```c
struct my_event {
    __u16 type;     // RS_EVENT_* 常量
    __u16 len;
    // 事件特定数据
};

RS_EMIT_EVENT(&evt, sizeof(evt));
```

事件发送是尽力而为的 —— 如果 ring buffer 已满，事件可能会被丢弃。

---

## Module 自注册 (Module Self-Registration)

每个 module 使用 `RS_DECLARE_MODULE()` 宏声明自己，该宏在 `.rodata.mod` ELF 节中创建一个 `struct rs_module_desc`：

```c
struct rs_module_desc {
    __u32 abi_version;      // ABI 兼容性检查
    __u32 hook;             // RS_HOOK_XDP_INGRESS 或 RS_HOOK_XDP_EGRESS
    __u32 stage;            // 执行顺序（越小越靠前）
    __u32 flags;            // RS_FLAG_* 能力位
    char  name[32];         // Module 标识符
    char  description[64];  // 易于阅读的描述
};
```

Loader 在加载时读取此元数据 —— 无需硬编码 module 列表，无需单独的注册步骤。

---

## 对比：传统 vs 可重构

| 维度 | 传统交换机 | rSwitch |
|--------|-------------------|---------|
| **Pipeline** | 固化在硬件中 (ASIC/FPGA) | 软件定义，profile 驱动 |
| **添加特性** | 固件更新或硬件更换 | 编写 BPF module，添加到 profile |
| **移除特性** | 通常不可能 | 从 profile 中移除，重新加载 |
| **定制化** | 仅限于厂商提供的选项 | 自定义 BPF module，拥有完整的数据包访问权限 |
| **更新影响** | 完全重启，流量中断 | 热加载单个 module |
| **调试/追踪** | 受限于厂商工具 | 通过事件总线、bpftool、CLI 实现完整可观测性 |
| **部署** | 硬件特定 | 任何具备 XDP 能力网卡的 Linux 机器 |

---

## 目录结构 (Directory Structure)

```
rswitch/
├── bpf/
│   ├── include/          # BPF 头文件 (rswitch_bpf.h, vmlinux.h)
│   ├── core/             # 核心 BPF 程序 (dispatcher.bpf.c, egress.bpf.c, module_abi.h)
│   └── modules/          # BPF module (vlan.bpf.c, acl.bpf.c, route.bpf.c, ...)
├── user/
│   ├── loader/           # rswitch_loader (profile 解析器, module 加载器)
│   ├── voqd/             # VOQd 调度器 (AF_XDP)
│   └── tools/            # CLI 工具 (rswitchctl, rsvlanctl, rsaclctl, rsqosctl)
├── etc/profiles/         # YAML profile 文件 (18 个 profile)
├── scripts/              # 辅助脚本 (启动, 校验)
├── test/                 # 测试
├── docs/                 # 文档
├── examples/             # 示例配置和演示
├── external/libbpf/      # libbpf 子模块
└── build/                # 构建输出 (二进制文件, .bpf.o 文件)
```

---

## 未来演进：网络矩阵 (Network Fabric)

可重构架构旨在演进为完整的 Network Fabric 控制器。计划中的能力包括：

- OpenFlow 风格的流表，包含匹配/动作规则
- 基于流的 QoS 策略
- 带有路径选择的流量工程
- 多交换机编排
- 基于意图的网络 (Intent-based networking) 抽象

详见 [Network_Fabric_Design.md](../../Network_Fabric_Design.md)。

---

## 参考资料 (References)

- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — 如何编写 BPF module
- [API_Reference.md](./API_Reference.md) — 完整 API 参考
- [CO-RE_Guide.md](./CO-RE_Guide.md) — 跨内核可移植性
- [Contributing.md](./Contributing.md) — 如何贡献
- **技术文档** (详细架构深度解析):
  - [Module_Auto-Discovery_System.md](../../paperwork/Module_Auto-Discovery_System.md)
  - [Tail-Call_Pipeline_Architecture.md](../../paperwork/Tail-Call_Pipeline_Architecture.md)
  - [Per-CPU_Context_Management.md](../../paperwork/Per-CPU_Context_Management.md)
  - [BPF_Map_Sharing_Patterns.md](../../paperwork/BPF_Map_Sharing_Patterns.md)
  - [Event_Bus_Architecture.md](../../paperwork/Event_Bus_Architecture.md)
  - [VOQd_State_Machine_Architecture.md](../../paperwork/VOQd_State_Machine_Architecture.md)
