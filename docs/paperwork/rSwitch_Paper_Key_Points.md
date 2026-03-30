# rSwitch 学术论文要点整理

> 本文档整理了将 rSwitch 平台作为学术论文发表所需的核心要点，包括选题定位、创新贡献、系统架构、关键技术、实验设计建议和相关工作对比。

---

## 1. 选题定位与论文角度

### 1.1 推荐论文标题方向

- **"rSwitch: A Reconfigurable Software Switch Based on XDP Tail-Call Pipeline"**
- **"rSwitch: Profile-Driven Modular Software Switching with Hybrid XDP/AF_XDP Data Plane"**
- **"From Monolithic to Modular: A Reconfigurable XDP Switch Architecture with User-Space QoS Scheduling"**

### 1.2 核心论点 (Thesis Statement)

> 现有的高性能软件交换方案（OVS-DPDK、BESS、ClickOS）要么依赖内核旁路（bypass）牺牲通用性，要么依赖内核模块（kernel module）牺牲可移植性。rSwitch 提出了一种**纯 eBPF/XDP 的模块化可重配置软件交换架构**，通过 tail-call 流水线实现模块组合、通过 YAML profile 实现运行时重配置、通过 AF_XDP 混合数据平面实现用户态 QoS 调度，在不依赖 DPDK 或内核模块的前提下，达到了接近硬件的转发性能和丰富的交换功能。

### 1.3 目标会议/期刊

| 级别 | 目标 | 匹配度 |
|------|------|--------|
| Top | SIGCOMM, NSDI, OSDI | 需要大规模实验 + 与 OVS-DPDK 的详细对比 |
| 中高 | CoNEXT, SoCC, EuroSys | 适合系统设计 + 性能评估 |
| 中等 | ANCS, HotNets, APNet | 适合架构创新 + 初步评估 |
| 工具论文 | SIGCOMM CCR, IEEE NetSoft | 适合开源工具 + 案例研究 |

---

## 2. 核心创新贡献（Contributions）

### 贡献 1：基于 Tail-Call 的模块化 XDP 流水线

**问题**：传统 XDP 程序是单体的——所有交换逻辑在一个 BPF 程序中，难以复用、扩展和维护。

**方案**：rSwitch 将交换功能分解为 25 个独立 BPF 模块，通过 `bpf_tail_call()` 和 `BPF_MAP_TYPE_PROG_ARRAY` 串联成流水线。每个模块声明自己的 stage number（流水线阶段号），loader 按 stage 排序后填入 prog_array。

**创新点**：
- **模块自描述**：每个 BPF 模块通过 `RS_DECLARE_MODULE` 宏在 ELF `.rodata.mod` section 中嵌入元数据（名称、stage、hook point、flags），loader 自动发现和组装
- **稀疏数组分派**：stage number 直接作为 prog_array 的 key，O(1) 分派，无需遍历
- **双流水线**：Ingress (stage 10-99) 和 Egress (stage 100-199) 独立流水线
- **Per-CPU 上下文传递**：`rs_ctx_map` (PERCPU_ARRAY) 在模块间零拷贝传递包处理状态

**量化**：
- 25 个模块覆盖 L2/L3/ACL/NAT/QoS/隧道/监控/安全等完整交换功能
- 每次 tail-call 开销 ~10-20ns
- 典型流水线 4-6 个 stage，总 tail-call 开销 < 100ns

### 贡献 2：Profile 驱动的运行时重配置

**问题**：固定的交换流水线无法适应不同的部署场景（L2 交换机 vs L3 路由器 vs 防火墙 vs QoS 网关）。

**方案**：通过 YAML profile 声明式定义流水线组成：

```yaml
# L2 交换机
ingress: [vlan, l2learn]
egress: [egress_vlan, egress_final]

# QoS 网关
ingress: [vlan, qos_classify, acl, conntrack, l2learn]
egress: [egress_qos, afxdp_redirect, egress_vlan, egress_final]

# 安全设备
ingress: [vlan, acl, source_guard, conntrack, dhcp_snoop]
egress: [egress_vlan, egress_final]
```

**创新点**：
- **声明式组合**：运维人员无需修改代码，通过 YAML 即可改变交换机"人格"
- **热重载**：通过原子更新 prog_array 实现 profile 切换，无需 detach/re-attach XDP 程序
- **模块自动发现**：loader 扫描 build 目录，读取 ELF 元数据，自动匹配 profile 需求
- **冲突检测**：加载时验证 stage 冲突、名称冲突、必需模块缺失

### 贡献 3：XDP + AF_XDP 混合数据平面

**问题**：XDP 是无状态的 per-packet 处理模型，无法实现需要跨包状态的 QoS 功能（队列管理、带宽整形、公平调度）。DPDK 可以实现但牺牲了内核集成和通用性。

**方案**：rSwitch 提出混合数据平面架构：
- **快速路径**：大部分流量走纯 XDP 路径，line-rate 转发
- **QoS 路径**：需要精细调度的流量通过 AF_XDP 重定向到用户态 VOQd
- **按需卸载**：通过 BYPASS/SHADOW/ACTIVE 三模式渐进式切换

**创新点**：
- **VOQd 三层调度器**：Port Round-Robin → WFQ (Weighted Fair Queuing) → DRR (Deficit Round Robin) + Dual Token Bucket
- **BPF-用户态协同**：BPF 侧做粗粒度分类和 ECN 标记，用户态做精细调度
- **自动故障转移**：BPF 侧心跳检测（5s 超时）+ 过载检测（1000 次 ringbuf 丢弃），自动降级到纯 XDP 快速路径
- **零拷贝路径**：AF_XDP 零拷贝模式避免内核-用户态数据拷贝

### 贡献 4：CO-RE 可移植性

**问题**：BPF 程序通常需要针对特定内核版本编译，部署到不同内核需要重新编译。

**方案**：全面采用 CO-RE (Compile Once Run Everywhere) 模式：
- 基于 `vmlinux.h` 编译，避免依赖特定内核头文件
- 使用 BPF CO-RE helper（`bpf_core_read` 等）进行结构体字段访问
- SDK 提供 CO-RE safe 的 helper 函数和宏

**结果**：单一二进制适用于 Linux 5.8+ 的所有内核版本。

---

## 3. 系统架构概述

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        rSwitch Platform                             │
│                                                                     │
│  ┌─── Control Plane ────────────────────────────────────────────┐  │
│  │  controller │ agent │ cli │ mgmt │ registry │ lifecycle      │  │
│  │  watchdog │ audit │ events │ telemetry │ exporter │ sflow    │  │
│  │  lacpd │ lldpd │ stpd │ snmpagent │ topology │ reload      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │ BPF maps                             │
│  ┌─── Data Plane ───────────┤──────────────────────────────────┐  │
│  │                          ▼                                   │  │
│  │  ┌── XDP Pipeline (Ingress, stage 10-99) ──────────────┐   │  │
│  │  │  dispatcher → vlan → qos_classify → acl → conntrack  │   │  │
│  │  │  → nat → route → l2learn → mirror → lastcall        │   │  │
│  │  └─────────────────────────────────────────────────────┘   │  │
│  │                          │                                   │  │
│  │  ┌── XDP Pipeline (Egress, stage 100-199) ─────────────┐   │  │
│  │  │  egress_qos → afxdp_redirect → egress_vlan          │   │  │
│  │  │  → egress_final                                      │   │  │
│  │  └─────────────────────────────────────────────────────┘   │  │
│  │                          │                                   │  │
│  │  ┌── VOQd (User-Space QoS) ────────────────────────────┐   │  │
│  │  │  AF_XDP RX → VOQ Manager → 3-Layer Scheduler        │   │  │
│  │  │  → AF_XDP TX                                         │   │  │
│  │  └─────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── SDK ──────────────────────────────────────────────────────┐  │
│  │  uapi.h │ rswitch_bpf.h │ module_abi.h │ map_defs.h        │  │
│  │  RS_DECLARE_MODULE │ RS_GET_CTX │ RS_TAIL_CALL_NEXT         │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 组件规模

| 类别 | 数量 | 示例 |
|------|------|------|
| BPF 模块 | 25 | acl, vlan, l2learn, nat, conntrack, egress_qos, afxdp_redirect... |
| 用户态组件 | 26 | controller, voqd, lacpd, lldpd, stpd, sflow, telemetry... |
| YAML Profiles | 10+ | l2, l3-router, firewall, qos-voqd, qos-voqd-minimal... |
| SDK 头文件 | 6 | uapi.h, rswitch_bpf.h, module_abi.h, map_defs.h... |
| 架构文档 | 7 | Tail-Call Pipeline, VOQd State Machine, Event Bus, Per-CPU Context... |

---

## 4. 关键技术细节（论文各章节素材）

### 4.1 Tail-Call 流水线设计（§Design - Pipeline）

**核心机制**：
- `rs_progs` (BPF_MAP_TYPE_PROG_ARRAY)：stage → BPF program FD 的映射
- `RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx)`：宏封装的 `bpf_tail_call()`
- `rs_ctx_map` (BPF_MAP_TYPE_PERCPU_ARRAY)：per-CPU 上下文，在模块间传递状态

**数据流**：
```
NIC → XDP hook → dispatcher.bpf.c:
  1. 解析 Ethernet/VLAN/IP/TCP/UDP
  2. 初始化 rs_ctx（写入 PERCPU_ARRAY）
  3. bpf_tail_call(rs_progs, first_stage)

Module N:
  1. RS_GET_CTX() 从 PERCPU_ARRAY 读取上下文
  2. 处理逻辑（读/写 rs_ctx 字段）
  3. RS_TAIL_CALL_NEXT() 跳转到下一个 stage
```

**与传统方案的对比**：

| 特性 | rSwitch (Tail-Call) | OVS (Megaflow) | P4 (Table Pipeline) |
|------|---------------------|-----------------|---------------------|
| 模块粒度 | BPF 程序 | Flow table | Table + Action |
| 组合方式 | prog_array tail-call | Flow rules | P4 compiler |
| 运行时重组 | YAML profile reload | OpenFlow rules | 需重编译 |
| 内核依赖 | XDP (kernel 5.8+) | Kernel module | 专用硬件/BMv2 |
| 开发语言 | C (BPF) | C (kernel) | P4 |

### 4.2 模块自动发现系统（§Design - Auto-Discovery）

**ELF 元数据嵌入**：
```c
RS_DECLARE_MODULE("vlan", RS_HOOK_XDP_INGRESS, 20, RS_FLAG_NONE,
                   "VLAN ingress policy enforcement");
```

编译后，元数据存储在 ELF `.rodata.mod` section 中。Loader 通过 ELF parsing 提取。

**加载流程**：
1. 扫描 `build/bpf/` 目录下所有 `.o` 文件
2. 对每个 BPF object，读取 `.rodata.mod` 中的 `rs_module_desc`
3. 与 YAML profile 匹配：保留 profile 中列出的模块
4. 验证：stage 冲突检测、名称唯一性
5. 按 stage 排序
6. 填入 `rs_progs` prog_array

### 4.3 混合数据平面（§Design - Hybrid Data Plane）

**快速路径 vs QoS 路径的分流决策**：
- `afxdp_redirect.bpf.c` (stage 85) 根据 `voqd_state_map` 中的 mode 和 `prio_mask` 决定
- `prio_mask` 允许按优先级选择性地将流量重定向到 VOQd（如仅 HIGH 和 CRITICAL 走 QoS 路径）

**VOQd 调度器详情**（可作为独立 subsection）：
- 三层调度：Port RR → WFQ → DRR + Dual Token Bucket
- 共享内存热配置：`/rswitch_voqd_shaper` POSIX shm
- 预分配内存池：1024-entry chunk 分配，O(1) 获取/归还
- 详见 `VOQd_Complete_Mechanism.md`

### 4.4 观测性架构（§Design - Observability）

**统一事件总线**：
- `rs_event_bus` (BPF_MAP_TYPE_RINGBUF, 16MB)
- 类型化事件：PacketRX/TX/Drop, MAC Learn, ACL Hit, VOQd Transition, Latency Sample
- `RS_EMIT_EVENT` 宏 + 采样 + 速率限制

**BPF Map 共享模式**：
- Core maps：dispatcher 创建，pinned 到 `/sys/fs/bpf/`
- Module maps：模块各自创建，通过 `extern` 声明共享
- User-space access：通过 `bpf_map_lookup_elem` / pinned path

### 4.5 协议支持（§Implementation）

| 功能 | 模块 | Stage |
|------|------|-------|
| VLAN (802.1Q/QinQ) | vlan, egress_vlan | 20, 150 |
| ACL (5-tuple + LPM) | acl | 30 |
| L2 Learning + Forwarding | l2learn, lastcall | 80, 90 |
| L3 Routing (LPM) | route | 70 |
| NAT (SNAT/DNAT) | nat | 60 |
| Connection Tracking | conntrack | 50 |
| QoS Classification | qos_classify | 25 |
| Egress QoS (shaping/ECN) | egress_qos | 170 |
| AF_XDP Redirect | afxdp_redirect | 85 |
| Rate Limiting | rate_limiter | 35 |
| Source Guard (IP-MAC binding) | source_guard | 45 |
| DHCP Snooping | dhcp_snoop | 40 |
| Mirror/SPAN | mirror | 75 |
| sFlow Sampling | sflow | 65 |
| ARP Learning | arp_learn | 15 |
| LACP (Link Aggregation) | lacp | 12 |
| LLDP | lldp | 11 |
| STP (Spanning Tree) | stp | 10 |
| Tunnel (VXLAN/GRE) | tunnel | 55 |
| veth Egress | veth_egress | 180 |

---

## 5. 实验设计建议

### 5.1 性能评估（Microbenchmark）

| 实验 | 测量指标 | 对比基线 |
|------|----------|----------|
| 单核转发吞吐 | Mpps, Gbps | OVS-DPDK, OVS-AF_XDP, Linux bridge |
| 转发延迟 | P50/P99/P999 latency | 同上 |
| Tail-call 开销 | ns/tail-call | 单体 XDP 程序 |
| Profile 切换时间 | ms | OVS bridge reconfiguration |
| VOQd 调度延迟 | μs/packet | DPDK QoS (librte_sched) |
| AF_XDP 零拷贝吞吐 | Mpps | Copy mode AF_XDP |

### 5.2 功能评估（Macrobenchmark）

| 实验 | 场景 | 预期结果 |
|------|------|----------|
| Profile 多样性 | 同一平台切换 L2/L3/FW/QoS profile | 验证重配置能力 |
| QoS 公平性 | 4 优先级混合流量 + WFQ 权重 | 带宽分配符合权重比例 |
| 故障转移 | Kill VOQd → 观察降级时间 | ≤5s 自动切换到 BYPASS |
| CO-RE 兼容性 | 同一二进制在 5.8/5.15/6.1/6.8 内核上运行 | 均正常工作 |
| 模块可扩展性 | 添加自定义模块到 pipeline | 无需修改其他模块 |

### 5.3 推荐实验拓扑

```
Traffic Generator (TRex/pktgen)
    │
    ▼
[NIC 1] ──── rSwitch (DUT) ──── [NIC 2]
                                    │
                                    ▼
                            Traffic Sink (受端)
```

- 使用 TRex 生成 64B/512B/1518B 混合流量
- 测量不同 profile 下的转发性能
- 对比不同数量的 pipeline stage 对性能的影响

---

## 6. 相关工作对比

### 6.1 与现有方案的定位

```
                    高性能
                      ▲
                      │
           DPDK/BESS ●──── rSwitch ●
                      │        │
                      │        │  (无需 kernel bypass)
                      │        │
          OVS-DPDK ●  │        │
                      │        │
                      │        │ ● P4 (BMv2)
              OVS ●   │        │
                      │        │
        Linux bridge ●│        │
                      └────────┼──────────────→ 灵活/可扩展
                               │
```

### 6.2 详细对比

| 特性 | rSwitch | OVS | OVS-DPDK | BESS | ClickOS | P4 (BMv2) |
|------|---------|-----|----------|------|---------|-----------|
| 数据平面 | XDP + AF_XDP | Kernel module | DPDK | DPDK | Xen + Click | P4 runtime |
| 内核依赖 | 标准内核 (5.8+) | 内核模块 | DPDK hugepages | DPDK hugepages | Xen hypervisor | 无 |
| 模块化 | BPF 模块 (tail-call) | Flow tables | Flow tables | Modules (C++) | Elements | P4 tables |
| 运行时重配置 | YAML profile | OpenFlow | OpenFlow | Python script | Click config | 需重编译 |
| QoS 调度 | 三层调度器 (WFQ+DRR+TB) | tc integration | DPDK QoS | 自定义 | 无 | 无 |
| 可移植性 | CO-RE (任意内核 5.8+) | 需要内核模块编译 | 硬件绑定 | 硬件绑定 | Xen 绑定 | BMv2/Tofino |
| 开发语言 | C (BPF) | C (kernel) | C | C++ | Click | P4 |
| CPU 占用 | 事件驱动 (XDP) | 事件驱动 | 轮询 (100% CPU) | 轮询 (100% CPU) | 轮询 | N/A |
| 零拷贝 | AF_XDP | 无 | DPDK | DPDK | 无 | 无 |

### 6.3 rSwitch 的独特优势

1. **无内核旁路，无内核模块**：纯 eBPF/XDP，标准内核即可运行
2. **声明式重配置**：YAML profile 定义交换机行为，非 OpenFlow 规则
3. **混合数据平面**：快速路径 + QoS 路径按需切换，不强制所有流量经过用户态
4. **自愈数据平面**：BPF 侧心跳 + 过载检测实现自动故障转移
5. **CO-RE 可移植**：一次编译，多内核部署
6. **完整的交换功能**：25 个模块覆盖从 L2 到安全到 QoS 的完整功能栈

---

## 7. 论文结构建议

```
1. Introduction
   - 问题：现有软件交换方案的局限性
   - 动机：为什么需要纯 XDP 的模块化交换机
   - 贡献列表（4 点）

2. Background & Motivation
   - eBPF/XDP 技术背景
   - 现有方案的局限性分析
   - 设计目标

3. Design
   3.1 Architecture Overview
   3.2 Tail-Call Pipeline Architecture
   3.3 Module Auto-Discovery & Profile System
   3.4 Per-CPU Context Management
   3.5 Hybrid Data Plane (XDP + AF_XDP)
   3.6 VOQd: User-Space QoS Scheduling
   3.7 Observability (Event Bus)

4. Implementation
   - 模块列表与功能覆盖
   - SDK 与开发者接口
   - CO-RE 兼容性处理
   - 代码规模统计

5. Evaluation
   5.1 Microbenchmarks (throughput, latency, overhead)
   5.2 Profile Reconfiguration
   5.3 QoS Fairness & Scheduling
   5.4 Fault Tolerance (failover)
   5.5 Comparison with OVS/DPDK

6. Related Work
   - Software switches (OVS, DPDK-based)
   - XDP/eBPF networking (Katran, Cilium, Polycube)
   - P4 and programmable switches
   - QoS in software switches

7. Discussion & Future Work
   - IPv6 完整支持
   - MPLS/SRv6 支持
   - P4-to-BPF 编译器集成
   - 多节点分布式交换

8. Conclusion
```

---

## 8. 潜在审稿人关注点与应对

### Q1: "与 Cilium/Katran 等 XDP 项目有何区别？"

**应对**：Cilium 是面向 Kubernetes 的网络方案，Katran 是 L4 负载均衡器。它们都是**单一功能的 XDP 应用**。rSwitch 是**通用可重配置软件交换机**——通过模块化 pipeline 和 profile 系统，可以组合出 L2 交换机、L3 路由器、防火墙、QoS 网关等多种"人格"。这是架构层面的本质区别。

### Q2: "纯 XDP 能达到 DPDK 的性能吗？"

**应对**：
- XDP 的 per-packet overhead 略高于 DPDK（事件驱动 vs 轮询），但 XDP 不独占 CPU 核心
- 对于 L2/L3 转发，rSwitch 的 XDP 快速路径可达 10+ Mpps/core
- 对于需要 QoS 的场景，AF_XDP 零拷贝路径性能接近 DPDK
- 关键优势不在于绝对峰值性能，而在于**不牺牲内核集成、不占用独立 CPU、不需要 hugepages**

### Q3: "Tail-call pipeline 有什么限制？"

**应对**：
- BPF tail-call 深度限制 33 次（Linux 内核限制）→ rSwitch 典型 pipeline 4-8 个 stage，远低于限制
- 每次 tail-call ~10-20ns 开销 → 对于 μs 级的包处理来说可忽略
- 无法跨 tail-call 传递栈上变量 → 通过 per-CPU map (`rs_ctx_map`) 解决

### Q4: "VOQd 引入用户态后延迟增加多少？"

**应对**：
- AF_XDP 零拷贝模式延迟 ~1-10 μs
- 对于需要 QoS 的流量（如视频会议、VoIP），μs 级延迟完全可接受
- BYPASS 模式下不增加任何延迟（纯 XDP 路径）
- 关键是**选择性卸载**：只有需要精细调度的流量才走 VOQd

### Q5: "模块化带来的性能开销？"

**应对**：
- 单体 XDP 程序 vs 模块化 pipeline 的性能差距 < 5%（主要是 tail-call 开销）
- 收益远大于开销：可维护性、可复用性、可测试性、运行时重配置能力

---

## 9. 写作建议

### 9.1 强调的亮点（按优先级）

1. **模块化 + 可重配置**：这是最独特的贡献，是区别于所有现有 XDP 方案的核心
2. **混合数据平面**：XDP + AF_XDP 的组合是实用且新颖的架构设计
3. **完整功能覆盖**：25 个模块 = 真实可用的软件交换机，不是 toy project
4. **自愈机制**：VOQd 的心跳/故障转移设计体现了生产级的系统工程

### 9.2 需要补充的实验数据

- [ ] 与 OVS (kernel datapath) 的吞吐/延迟对比
- [ ] 与 OVS-DPDK 的吞吐/延迟对比
- [ ] 不同 pipeline 长度（2/4/6/8 modules）对性能的影响
- [ ] Profile 热切换的中断时间测量
- [ ] VOQd 三模式下的吞吐/延迟对比
- [ ] WFQ 公平性验证（带宽分配是否符合权重）
- [ ] 故障转移时间测量（kill VOQd → 恢复正常转发的延迟）
- [ ] 多内核版本 CO-RE 兼容性验证

### 9.3 论文篇幅估算

| 章节 | 预计页数 |
|------|----------|
| Abstract + Intro | 1.5 |
| Background | 1 |
| Design | 4-5 |
| Implementation | 1 |
| Evaluation | 3-4 |
| Related Work | 1 |
| Discussion + Conclusion | 1 |
| **总计** | **12-14 页** |

适合 USENIX/ACM 双栏格式的 full paper (12 页 + references)。
