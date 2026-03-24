> 📖 [English Version](../../development/Module_Developer_Guide.md)

# Module 开发指南 (Module Developer Guide)

本指南将引导您为 rSwitch pipeline 创建自定义 BPF module —— 从初始设置到生产部署。本指南与 `bpf/modules/` 中的源代码以及 `user/loader/rswitch_loader.c` 中的 loader 保持一致。

---

## 前置条件 (Prerequisites)

在编写 module 之前，您应该了解：

- C 语言编程和 eBPF 基础概念
- [架构文档](./Architecture.md)（pipeline 阶段、tail-call、per-CPU context）
- [API 参考](./API_Reference.md)（宏、数据结构、辅助函数）

构建环境要求：

- Linux 内核 5.8+，且开启 `CONFIG_DEBUG_INFO_BTF=y`
- clang/LLVM 10+, libbpf 0.6+, bpftool 5.8+
- 详见 [安装指南](../../deployment/Installation.md) 获取完整依赖列表

---

## 快速上手：Hello World Module

### 第 1 步：创建源文件

创建 `bpf/modules/hello_world.bpf.c`：

```c
// SPDX-License-Identifier: GPL-2.0
#include "../include/rswitch_common.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

// Module 自注册 (必填)
RS_DECLARE_MODULE(
    "hello_world",              // 名称 — 用于 YAML profile
    RS_HOOK_XDP_INGRESS,        // 挂载点 (Hook point)
    25,                         // 阶段 25 — 位于 VLAN (20) 和 ACL (30) 之间
    RS_FLAG_NEED_L2L3_PARSE,    // 需要解析后的 L2/L3 报头
    "Hello World example"       // 描述
);

// 可选：per-CPU 统计信息
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hello_stats SEC(".maps");

SEC("xdp")
int hello_world(struct xdp_md *xdp_ctx)
{
    // 1. 获取共享 context
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    // 2. 更新统计信息
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&hello_stats, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    // 3. 您的处理逻辑
    if (ctx->layers.eth_proto == bpf_htons(ETH_P_IP)) {
        rs_debug("hello_world: IPv4 packet from ifindex %u", ctx->ifindex);
    }

    // 4. 继续执行下一个 module
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

    // 5. 如果 tail-call 失败的备选方案
    return XDP_PASS;
}
```

### 第 2 步：构建

```bash
cd rswitch/
make
# 输出: build/bpf/hello_world.bpf.o
```

构建系统会自动发现 `bpf/modules/` 中新增的 `.bpf.c` 文件。

### 第 3 步：添加到 Profile

在 `etc/profiles/` 中创建或编辑 YAML profile：

```yaml
name: "Hello World Test"
version: "1.0"

ingress:
  - vlan
  - hello_world    # 您的 module (阶段信息来自 ELF 元数据)
  - acl
  - lastcall

egress:
  - egress_final
```

> **注意：** Module 阶段仅由 BPF 代码中的 `RS_DECLARE_MODULE()` 宏决定。YAML profile 仅列出要加载哪些 module —— 目前不支持在 YAML 中覆盖阶段设置。

### 第 4 步：加载与测试

```bash
sudo ./build/rswitch_loader --profile etc/profiles/hello.yaml --ifaces eth0,eth1 --verbose

# 验证 module 已加载
sudo ./build/rswitchctl show-pipeline

# 检查您的 map
sudo bpftool map dump pinned /sys/fs/bpf/hello_stats
```

---

## Module 结构详解 (Module Structure in Detail)

### 必要元素 (Required Elements)

每个 module 必须包含：

1. **许可证声明 (License declaration)**: `char _license[] SEC("license") = "GPL";`
2. **Module 元数据 (Module metadata)**: `RS_DECLARE_MODULE(...)` — 在 ELF 中嵌入自我描述
3. **XDP 入口点 (XDP entry point)**: `SEC("xdp") int func_name(struct xdp_md *xdp_ctx) { ... }`
4. **Context 获取 (Context retrieval)**: `struct rs_ctx *ctx = RS_GET_CTX();` 并进行空值检查
5. **Pipeline 延续 (Pipeline continuation)**: 在末尾调用 `RS_TAIL_CALL_NEXT(xdp_ctx, ctx);`

### RS_DECLARE_MODULE 参数

```c
RS_DECLARE_MODULE(name, hook, stage, flags, description)
```

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `name` | 字符串 | Module 标识符（最长 31 字符），用于 YAML profile |
| `hook` | 枚举 (enum) | `RS_HOOK_XDP_INGRESS` 或 `RS_HOOK_XDP_EGRESS` |
| `stage` | u32 | 执行顺序：ingress 为 10-99，egress 为 100-199 |
| `flags` | u32 | 能力标志位（通过 OR 组合） |
| `description` | 字符串 | 易于阅读的描述（最长 63 字符） |

### 能力标志位 (Capability Flags)

| 标志位 | 值 | 何时设置 |
|------|-------|-------------|
| `RS_FLAG_NEED_L2L3_PARSE` | `0x01` | Module 从 `ctx->layers` 读取 L2/L3 报头字段 |
| `RS_FLAG_NEED_VLAN_INFO` | `0x02` | Module 读取 VLAN 信息 |
| `RS_FLAG_NEED_FLOW_INFO` | `0x04` | Module 读取五元组流信息 (sport/dport) |
| `RS_FLAG_MODIFIES_PACKET` | `0x08` | Module 可能会修改数据包数据 |
| `RS_FLAG_MAY_DROP` | `0x10` | Module 可能会丢弃数据包 |
| `RS_FLAG_CREATES_EVENTS` | `0x20` | Module 向事件总线 (event bus) 发送事件 |

### 阶段选择指南 (Stage Selection Guide)

根据 module 的功能选择阶段编号：

| 您的 Module 功能... | 推荐范围 | 示例 |
|---------------------|-------------------|---------|
| 报头校验 / 归一化 | 10-19 | 预处理 |
| VLAN 处理 | 20-29 | `vlan` 位于 20 |
| 安全 / 过滤 | 30-39 | `acl` 位于 30 |
| 镜像 / 劫持 (Mirroring / tapping) | 40-49 | `mirror` 位于 40 |
| 路由 / 转发决策 | 50-69 | `route` 位于 50 |
| MAC 学习 / ARP | 80-89 | `l2learn` 位于 80, `afxdp_redirect` 位于 85 |
| 最终转发 | 90-99 | `lastcall` 位于 90 (始终最后) |
| Egress QoS | 170-179 | `egress_qos` 位于 170 |
| Egress VLAN 打标 | 180-189 | `egress_vlan` 位于 180 |
| Egress 最终处理 | 190-199 | `egress_final` 位于 190 (始终最后) |

---

## 使用 Context (Working with Context)

### 读取 Context

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx) return XDP_DROP;

// 数据包元数据
__u32 ifindex = ctx->ifindex;
__u16 eth_proto = ctx->layers.eth_proto;
__be32 src_ip = ctx->layers.saddr;
__be16 dst_port = ctx->layers.dport;

// VLAN 状态
__u16 vlan_id = ctx->ingress_vlan;
__u8 vlan_depth = ctx->layers.vlan_depth;

// QoS 状态
__u8 priority = ctx->prio;
__u8 dscp = ctx->dscp;
```

### 修改 Context

Module 通过更新 context 字段来向下游传递决策：

```c
// 设置转发决策
ctx->egress_ifindex = target_port;
ctx->action = XDP_REDIRECT;

// 设置 QoS 标记
ctx->prio = 7;        // 最高优先级
ctx->traffic_class = 3;

// 设置 egress 的 VLAN
ctx->egress_vlan = 200;

// 发出错误信号（将导致在 lastcall 处丢包）
ctx->error = RS_ERROR_ACL_DENY;
ctx->drop_reason = RS_DROP_ACL_BLOCK;
```

### 条件处理 (Conditional Processing)

跳过无关数据包的处理：

```c
// 仅处理 IPv4 数据包
if (ctx->layers.eth_proto != bpf_htons(ETH_P_IP)) {
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}

// 仅处理特定端口上的数据包
struct rs_port_config *cfg = rs_get_port_config(ctx->ifindex);
if (!cfg || !cfg->enabled) {
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
```

---

## 自定义 Map (Custom Maps)

### 定义 Module 特有的 Map

```c
// Per-CPU 统计信息 (无竞争)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} my_stats SEC(".maps");

// 带有 pinning 的 Hash map (可从用户态访问)
struct my_key {
    __u32 src_ip;
    __u32 dst_ip;
};

struct my_value {
    __u64 packet_count;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct my_key);
    __type(value, struct my_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_flow_table SEC(".maps");
```

### 访问共享 Map

核心基础设施 map 对所有 module 可见：

```c
// 端口配置
struct rs_port_config *cfg = rs_get_port_config(ctx->ifindex);

// MAC 表
struct rs_mac_entry *entry = rs_mac_lookup(dst_mac, vlan_id);

// VLAN 成员关系
int is_tagged;
int is_member = rs_is_vlan_member(vlan_id, ctx->ifindex, &is_tagged);

// 统计信息
rs_stats_update_rx(ctx, packet_bytes);
rs_stats_update_drop(ctx);
```

---

## 发送事件 (Emitting Events)

向用户态发送结构化事件，用于监控和调试：

```c
struct my_event {
    __u16 type;         // 事件类型标识符
    __u16 len;          // 事件总大小
    __u32 ifindex;      // 源接口
    __be32 src_ip;      // 事件特定数据
    __be32 dst_ip;
};

struct my_event evt = {
    .type = RS_EVENT_ACL_BASE + 1,  // 使用合适的事件范围
    .len = sizeof(evt),
    .ifindex = ctx->ifindex,
    .src_ip = ctx->layers.saddr,
    .dst_ip = ctx->layers.daddr,
};
RS_EMIT_EVENT(&evt, sizeof(evt));
```

**最佳实践：**
- 事件发送是尽力而为的 —— 如果 ring buffer 已满，可能会丢弃
- 对于高频事件使用采样（例如：每 1000 个包采样一次）
- 包含时间戳、接口索引和 CPU ID 以便于调试
- 保持事件结构体精简（< 256 字节）

---

## BPF Verifier 合规性 (BPF Verifier Compliance)

BPF verifier 确保您的程序是安全的。常见陷阱及解决方案：

### 边界检查 (Bounds Checking)

```c
// 错误 —— verifier 会拒绝
void *data = (void *)(long)xdp_ctx->data;
struct iphdr *iph = data + ctx->layers.l3_offset;  // 未经检查的偏移量！

// 正确 —— 使用偏移掩码 (offset mask)
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

### Map 查找

```c
// 错误 —— 空指针解引用
__u64 *val = bpf_map_lookup_elem(&map, &key);
*val += 1;  // Verifier 报错！

// 正确 —— 先进行空值检查
__u64 *val = bpf_map_lookup_elem(&map, &key);
if (val)
    __sync_fetch_and_add(val, 1);
```

### 循环边界 (Loop Bounds)

```c
// 错误 —— 无界循环
for (int i = 0; i < count; i++) { ... }

// 正确 —— 带有编译时最大值的有界循环
#pragma unroll
for (int i = 0; i < MAX_ENTRIES; i++) {
    if (i >= count) break;
    // 处理...
}
```

### 偏移掩码参考 (Offset Masks Reference)

| 掩码 | 值 | 使用场景 |
|------|-------|----------|
| `RS_L3_OFFSET_MASK` | `0x3F` (63) | L2 报头大小 (Ethernet + VLAN 标签) |
| `RS_L4_OFFSET_MASK` | `0x7F` (127) | L2 + L3 报头大小 |
| `RS_PAYLOAD_MASK` | `0xFF` (255) | 总报头大小 |

---

## 数据包修改 (Packet Modification)

如果您的 module 修改了数据包，请在 module 声明中设置 `RS_FLAG_MODIFIES_PACKET`：

```c
RS_DECLARE_MODULE("my_modifier", RS_HOOK_XDP_INGRESS, 45,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
    "Packet modifier example");

SEC("xdp")
int my_modifier(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;

    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // 安全地访问 IP 报头
    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    // 修改 TTL
    __u8 old_ttl = iph->ttl;
    if (old_ttl <= 1) {
        ctx->error = RS_ERROR_INTERNAL;
        ctx->drop_reason = RS_DROP_TTL_EXCEEDED;
        return XDP_DROP;
    }
    iph->ttl = old_ttl - 1;

    // 更新校验和 (修改后必须更新)
    // ... 校验和更新逻辑 ...

    ctx->modified = 1;
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
```

---

## Egress Module

Egress module 使用 `RS_HOOK_XDP_EGRESS` 和 100-199 阶段：

```c
RS_DECLARE_MODULE("my_egress", RS_HOOK_XDP_EGRESS, 175,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
    "Custom egress processing");

SEC("xdp")
int my_egress(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_PASS;

    // Egress 处理...

    // 为 egress pipeline 使用 RS_TAIL_CALL_EGRESS
    RS_TAIL_CALL_EGRESS(xdp_ctx, ctx);
    return XDP_PASS;
}
```

与 ingress module 的主要区别：
- 使用 `RS_TAIL_CALL_EGRESS()` 而非 `RS_TAIL_CALL_NEXT()`
- Egress 槽位从 255 开始降序分配
- 使用 `rs_prog_chain` map 进行下一个 module 的查找

---

## VOQd 集成 (VOQd Integration)

对于与 VOQd QoS 调度器交互的 module：

```c
// 在处理前检查 VOQd 状态
struct voqd_state *state = bpf_map_lookup_elem(&voqd_state_map, &key);
if (state && state->mode == VOQD_MODE_ACTIVE) {
    // 全量 QoS 处理 — 重定向到 AF_XDP socket
    redirect_to_voqd(ctx, xdp_ctx);
} else {
    // 快速路径 — 跳过 QoS，继续 pipeline
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
}
```

VOQd 模式：BYPASS (0), SHADOW (1), ACTIVE (2)。

---

## 多阶段 Module (Multi-Stage Modules)

对于需要多个 pipeline 阶段的 complex 处理：

```c
// 文件: bpf/modules/complex_stage1.bpf.c
RS_DECLARE_MODULE("complex_stage1", RS_HOOK_XDP_INGRESS, 35, ...);

// 文件: bpf/modules/complex_stage2.bpf.c
RS_DECLARE_MODULE("complex_stage2", RS_HOOK_XDP_INGRESS, 36, ...);
```

在 YAML profile 中列出两者：
```yaml
ingress:
  - vlan
  - complex_stage1
  - complex_stage2
  - lastcall
```

---

## 测试与调试 (Testing and Debugging)

### 调试日志 (Debug Logging)

```c
// 仅在编译时带有 -DDEBUG 时才会发送
rs_debug("my_module: processed pkt ifindex=%u proto=0x%x",
         ctx->ifindex, ctx->layers.eth_proto);
```

### 检查 Map

```bash
# 列出所有 rSwitch map
sudo bpftool map list | grep rs_

# Dump 特定 map
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table

# Dump 您的自定义 map
sudo bpftool map dump pinned /sys/fs/bpf/my_flow_table
```

### 检查程序 (Inspecting Programs)

```bash
# 列出已加载的程序
sudo bpftool prog list | grep rswitch

# 反汇编程序
sudo bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher

# 显示程序统计信息
sudo bpftool prog show pinned /sys/fs/bpf/rswitch_dispatcher
```

### Pipeline 验证

```bash
# 显示当前 pipeline
sudo ./build/rswitchctl show-pipeline

# 显示每个端口的统计信息
sudo ./build/rswitchctl show-stats

# 监控事件
sudo ./build/rswitchctl show-events
```

---

## 故障排除 (Troubleshooting)

| 问题 | 可能原因 | 解决方案 |
|---------|-------------|----------|
| Verifier 拒绝 | 越界访问、缺少空值检查 | 使用偏移掩码，检查所有 map 查找结果 |
| Module 未被发现 | 缺少 `RS_DECLARE_MODULE()` | 验证宏是否存在，且 `.bpf.o` 构建成功 |
| Tail-call 失败 | 阶段编号冲突、rs_progs 已满 | 检查是否有重复阶段，使用 `show-pipeline` 验证 pipeline |
| Map 未找到 | 未正常关闭导致残留 stale pin | `sudo rm -rf /sys/fs/bpf/rs_*` 并重启 |
| Context 为 NULL | `rs_ctx_map` 未初始化 | 确保在加载您的 module 之前已加载 dispatcher |
| 性能低下 | Map 查找过多、非 CO-RE 访问 | 在 context 中缓存结果，使用 per-CPU map，遵循 CO-RE 模式 |

---

## 参考 Module (Reference Modules)

学习这些现有 module 作为示例：

| Module | 复杂度 | 优秀示例 |
|--------|-----------|-----------------|
| `core_example.bpf.c` | 简单 | 基础 module 结构，CO-RE 模式 |
| `vlan.bpf.c` | 中等 | Context 修改，VLAN 处理，端口配置访问 |
| `acl.bpf.c` | 复杂 | 多 map 架构，L3/L4 过滤，丢包原因 |
| `l2learn.bpf.c` | 中等 | MAC 表更新，事件发送，老化 (aging) |
| `egress_qos.bpf.c` | 复杂 | Egress pipeline，QoS 标记，VOQd 集成 |

所有 module 源文件均位于 `bpf/modules/`。

---

## 另请参阅 (See Also)

- [Architecture.md](./Architecture.md) — 系统架构概览
- [API_Reference.md](./API_Reference.md) — 完整 API 参考
- [CO-RE_Guide.md](./CO-RE_Guide.md) — 跨内核可移植性指南
- [Configuration](../../deployment/Configuration.md) — YAML profile 格式
- **技术文档深度解析**: `docs/paperwork/` 目录
