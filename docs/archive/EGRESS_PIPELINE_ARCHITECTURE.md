> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch Egress Pipeline Architecture

## Overview

Egress pipeline 是 rSwitch 中处理出口流量的模块化处理链，与 ingress pipeline 并行运行但具有不同的设计特点。

## 核心设计原则

### 1. Slot 分配策略

为了避免 ingress 和 egress 模块在 `rs_progs` 数组中的冲突，采用**分离式 slot 分配**：

- **Ingress 模块**：使用低位 slot（0, 1, 2, 3, ...），递增分配
- **Egress 模块**：使用高位 slot（255, 254, 253, 252, ...），递减分配

**示例**：
```
rs_progs 数组布局 (256 个 slot):
[0] vlan (ingress, stage 20)
[1] acl (ingress, stage 30)
[2] route (ingress, stage 50)
[3] l2learn (ingress, stage 80)
[4] lastcall (ingress, stage 90)
[5-253] 未使用
[254] egress_final (egress, stage 190)
[255] qos (egress, stage 170)
```

### 2. Stage vs Slot

- **Stage Number**：模块在 YAML profile 中的逻辑顺序号（10-99 ingress, 100-199 egress）
  - 用于**排序**：loader 按 stage 升序排列模块
  - 用于**分类**：stage 范围表示模块功能类别
  - **不影响实际执行**：仅在 loader 配置时使用

- **Slot Number**：模块在 `rs_progs` 数组中的实际索引（0-255）
  - 由 **loader 自动分配**
  - ingress: 按 stage 排序后从 0 开始递增
  - egress: 按 stage 排序后从 255 开始递减
  - **决定执行路径**：BPF tail-call 使用 slot 作为索引

### 3. Tail-Call 链式执行

#### Ingress Pipeline（简单）

使用 `RS_TAIL_CALL_NEXT` 宏，自动递增 slot：

```c
SEC("xdp")
int vlan_ingress(struct xdp_md *xdp_ctx) {
    struct rs_ctx *ctx = RS_GET_CTX();
    // ... 处理逻辑 ...
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);  // 自动调用 rs_progs[ctx->next_prog_id++]
    return XDP_DROP;  // Tail-call 失败时的 fallback
}
```

#### Egress Pipeline（复杂）

使用 `RS_TAIL_CALL_EGRESS` 宏，通过 `prog_chain` 映射查找下一个 slot：

```c
SEC("xdp")
int qos_egress(struct xdp_md *xdp_ctx) {
    struct rs_ctx *ctx = RS_GET_CTX();
    // ... 处理逻辑 ...
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);  // 查找 prog_chain[ctx->next_prog_id] → 下一个 slot
    return XDP_DROP;  // Tail-call 失败或结束时的 fallback
}
```

**为什么 egress 需要 prog_chain？**

因为 **BPF_F_BROADCAST 导致并发执行**：
- Flooding 时，一个数据包被克隆到多个端口
- 每个 CPU 核心同时处理不同端口的副本
- 不能使用递增计数器（会产生竞争）
- 使用 **只读映射** `prog_chain` 查找下一跳（无竞争）

### 4. prog_chain 映射结构

```c
// Key: 当前模块的 slot number
// Value: 下一个模块的 slot number (0 = 结束)

prog_chain[0] = 255        // devmap egress hook 的入口点
prog_chain[255] = 254      // qos → egress_final
prog_chain[254] = 0        // egress_final → 结束
```

**Loader 配置过程**：
1. 按 stage 排序 egress 模块：[qos(170), egress_final(190)]
2. 分配 slot（递减）：qos→255, egress_final→254
3. 构建链：`prog_chain[255]=254, prog_chain[254]=0`
4. 设置入口：`prog_chain[0]=255`

## 执行流程

### 完整的数据包路径

```
┌─────────────────────────────────────────────────────────────┐
│ 1. XDP Ingress Hook (ens34)                                 │
│    └─> dispatcher.bpf.c                                     │
│        └─> rs_progs[0] (vlan, slot 0)                      │
│            └─> rs_progs[1] (acl, slot 1)                   │
│                └─> rs_progs[2] (route, slot 2)             │
│                    └─> rs_progs[3] (l2learn, slot 3)       │
│                        └─> rs_progs[4] (lastcall, slot 4)  │
│                            └─> bpf_redirect_map(...)        │
└─────────────────────────────────────────────────────────────┘
                               │
                               │ BPF_F_BROADCAST (flooding)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Devmap Egress Hook (多核并发执行)                         │
│    ├─> Core 0: egress.bpf.c (port ens35)                   │
│    ├─> Core 1: egress.bpf.c (port ens36)                   │
│    └─> Core 2: egress.bpf.c (port ens37)                   │
│                                                              │
│    每个核心独立执行：                                         │
│    └─> 读取 prog_chain[0] = 255                            │
│        └─> 设置 rs_ctx->next_prog_id = 255                 │
│            └─> tail-call rs_progs[255] (qos)               │
└─────────────────────────────────────────────────────────────┘
                               │
                               │ 每核独立执行
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Egress Pipeline (per-CPU)                                │
│    └─> qos (rs_progs[255])                                 │
│        └─> 读取 prog_chain[255] = 254                      │
│            └─> 设置 rs_ctx->next_prog_id = 254             │
│                └─> tail-call rs_progs[254] (egress_final)  │
│                    └─> 读取 prog_chain[254] = 0 (结束)     │
│                        └─> return XDP_PASS                  │
└─────────────────────────────────────────────────────────────┘
                               │
                               │ 每个端口独立发送
                               ▼
                          网卡 TX 队列
```

### 并发安全性

**关键设计**：
- `rs_ctx_map`: **BPF_MAP_TYPE_PERCPU_ARRAY** - 每个 CPU 独立的 context
- `prog_chain`: **只读查找**，无写操作，无竞争
- `rs_progs`: **只读数组**，加载后不变

**并发场景**：
```
时间轴：Flooding packet (VLAN 10)

T0: Core 0 处理 port 2
    - rs_ctx (Core 0): next_prog_id = 255
    - 读取 prog_chain[255] = 254
    - tail-call rs_progs[254]

T0: Core 1 处理 port 3 (同时发生)
    - rs_ctx (Core 1): next_prog_id = 255
    - 读取 prog_chain[255] = 254 (相同值)
    - tail-call rs_progs[254] (相同目标)

T0: Core 2 处理 port 4 (同时发生)
    - rs_ctx (Core 2): next_prog_id = 255
    - 读取 prog_chain[255] = 254 (相同值)
    - tail-call rs_progs[254] (相同目标)

✓ 无竞争：每个核心使用自己的 rs_ctx 副本
✓ 一致性：所有核心读取相同的 prog_chain 值
✓ 高效：纯读取操作，无锁，无同步开销
```

## Stage 范围规范

### Ingress Stages (10-99)

| Range  | Purpose                      | Example Modules          |
|--------|------------------------------|--------------------------|
| 10-19  | Pre-processing               | header_validate          |
| 20-29  | VLAN processing              | vlan (20)                |
| 30-39  | Access control               | acl (30)                 |
| 40-49  | Routing                      | route (50), arp_learn (25)|
| 50-69  | QoS marking                  | qos_classify             |
| 70-79  | Mirroring                    | mirror (70)              |
| 80-89  | Learning                     | l2learn (80)             |
| 90-99  | Final decision               | lastcall (90)            |

### Egress Stages (100-199)

| Range   | Purpose                      | Example Modules          |
|---------|------------------------------|--------------------------|
| 100-119 | Pre-egress processing        | -                        |
| 120-139 | VLAN manipulation            | -                        |
| 140-169 | Policy enforcement           | -                        |
| 170-179 | **QoS enforcement**          | **qos (170)**            |
| 180-189 | VLAN tagging & Telemetry     | **egress_vlan (180)**    |
| 190-199 | **Final egress**             | **egress_final (190)**   |

## 当前已实现的 Egress 模块

### 1. qos.bpf.c (Stage 170, Slot 255)

**功能**：
- 优先级分类（基于 DSCP、5-tuple）
- 速率限制（Token Bucket）
- DSCP 重标记
- 拥塞检测与 ECN 标记

**Tail-call**：
```c
RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);  // → rs_progs[254] (egress_final)
```

### 2. egress_final.bpf.c (Stage 190, Slot 254)

**功能**：
- 清除 `parsed` 标志
- 更新统计信息
- 返回 `XDP_PASS`

**Tail-call**：
```c
// 不再 tail-call，直接返回 XDP_PASS
```

## 如何添加新的 Egress 模块

### 步骤 1：创建 BPF 模块

```c
// rswitch/bpf/modules/my_egress_module.bpf.c
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// 声明模块元数据
RS_DECLARE_MODULE(
    "my_egress_module",
    RS_HOOK_XDP_EGRESS,        // Egress hook
    175,                       // Stage (170-179 范围)
    RS_FLAG_NEED_L2L3_PARSE,
    "Custom egress processing"
);

SEC("xdp")
int my_egress_module_process(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;
    
    // ... 你的处理逻辑 ...
    
    // 继续到下一个 egress 模块
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);
    return XDP_DROP;  // Fallback
}
```

### 步骤 2：更新 YAML Profile

```yaml
# etc/profiles/my_profile.yaml
egress:
  - qos                   # Stage 170 → Slot 255
  - my_egress_module      # Stage 175 → Slot 254
  - egress_final          # Stage 190 → Slot 253
```

### 步骤 3：编译和加载

```bash
cd rswitch
make  # 自动编译新模块
sudo ./build/rswitch_loader --profile etc/profiles/my_profile.yaml --ifaces ens34,ens35
```

**Loader 会自动**：
1. 发现 `my_egress_module` (stage 175)
2. 按 stage 排序：[qos(170), my_egress_module(175), egress_final(190)]
3. 分配 slot：qos→255, my_egress_module→254, egress_final→253
4. 构建链：`prog_chain[255]=254, prog_chain[254]=253, prog_chain[253]=0`

## 调试技巧

### 1. 检查 Pipeline 配置

```bash
# 查看模块加载情况
sudo bpftool prog list | grep rswitch

# 查看 prog_chain 映射
sudo bpftool map dump name rs_prog_chain | head -20
# 应该看到：
# key: 00 00 00 00  value: ff 00 00 00  # prog_chain[0] = 255
# key: ff 00 00 00  value: fe 00 00 00  # prog_chain[255] = 254
# key: fe 00 00 00  value: 00 00 00 00  # prog_chain[254] = 0

# 查看 rs_progs 数组
sudo bpftool map dump name rs_progs | grep -A 1 "key: ff"  # Slot 255
sudo bpftool map dump name rs_progs | grep -A 1 "key: fe"  # Slot 254
```

### 2. 启用 Debug 日志

```c
// 在模块中添加：
rs_debug("My egress module: processing packet on port %u", ctx->egress_ifindex);
```

```bash
# 查看日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "My egress"
```

### 3. 验证 Tail-Call 执行

```bash
# 应该看到的执行顺序：
[rSwitch] Egress tail-call to prog 255      # egress.bpf.c → qos
[rSwitch] QoS: processing...                # qos.bpf.c
[rSwitch] Egress final: clearing parsed     # egress_final.bpf.c
```

## 常见问题

### Q: 为什么 egress 模块不执行？

**可能原因**：
1. **Devmap egress hook 未附加**
   - 检查：`sudo bpftool map dump name rs_xdp_devmap`
   - 应该看到每个 ifindex 的 value 包含非零的 prog_fd

2. **BPF_F_BROADCAST 不触发 egress（vmxnet3 驱动问题）**
   - 解决：切换回 e1000 驱动，或使用 DEVMAP 而非 DEVMAP_HASH

3. **prog_chain[0] 未设置**
   - 检查：`sudo bpftool map lookup name rs_prog_chain key 0 0 0 0`
   - 应该返回非零值（如 255）

### Q: Tail-call 失败怎么办？

**检查**：
1. Slot 是否正确分配（`bpftool map dump name rs_progs`）
2. prog_chain 链是否完整（每个 slot 都有下一跳）
3. call_depth 是否超过 32（内核限制）

### Q: 如何支持超过 10 个 egress 模块？

**当前设计支持最多 256 个模块**（受 `rs_progs` 数组大小限制）：
- Ingress: 0-127 (128 个 slot)
- Egress: 255-128 (128 个 slot)

实际使用中，通常不会超过 10 个模块。

## 总结

rSwitch egress pipeline 的关键特性：

1. ✅ **Slot 隔离**：Ingress (0↑) vs Egress (255↓)，避免冲突
2. ✅ **自动配置**：Loader 根据 stage 自动分配 slot 和构建 chain
3. ✅ **并发安全**：Per-CPU context + 只读 prog_chain，无竞争
4. ✅ **模块化**：通过 YAML 灵活组合功能
5. ✅ **可扩展**：添加新模块只需实现 BPF 程序和声明元数据

**核心设计哲学**：
> Stage 定义逻辑顺序，Slot 决定物理路径。Loader 自动桥接两者，
> 开发者只需关注模块功能和 stage 范围，无需手动管理 slot 分配。
