> 📖 [English Version](../SDK_Quick_Start.md)

# rSwitch SDK 快速入门

rSwitch SDK 允许您在不克隆完整开发树的情况下构建和测试独立的 BPF 模块。

---

## 1. SDK 内容

```
sdk/
├── include/                      # 稳定的平台头文件
│   ├── rswitch_module.h          # 单一入口点（推荐）
│   ├── rswitch_abi.h             # ABI 类型、常量、struct 定义
│   ├── rswitch_helpers.h         # BPF helpers、数据包解析、pipeline 宏
│   ├── rswitch_maps.h            # 共享 map 定义（选择性使用）
│   ├── rswitch_common.h          # 向后兼容 — 包含所有内容
│   ├── rswitch_bpf.h             # 旧版 helpers（优先使用 rswitch_helpers.h）
│   ├── module_abi.h              # 旧版 ABI（优先使用 rswitch_abi.h）
│   ├── uapi.h                    # 旧版类型（优先使用 rswitch_abi.h）
│   └── map_defs.h                # 旧版 maps（优先使用 rswitch_maps.h）
├── templates/                    # 入门模块实现模板
│   ├── simple_module.bpf.c       # 最小化 ingress 模块
│   ├── stateful_module.bpf.c     # 带有私有 BPF map 状态的 ingress 模块
│   └── egress_module.bpf.c       # Egress pipeline 模块
├── Makefile.module               # 独立构建规则
├── rswitch.pc.in                 # pkg-config 模板
├── test/                         # 测试支持
│   ├── test_harness.h            # 单元测试框架 (RS_TEST, RS_ASSERT_*)
│   └── mock_maps.h               # 用于用户态测试的 map mocks
└── docs/
    └── SDK_Quick_Start.md        # 本文件
```

### 包含策略 (Include Strategy)

| 头文件 | 何时使用 |
|--------|-------------|
| `rswitch_module.h` | **默认**: ABI 类型 + helpers + pipeline 宏。不包含共享 maps。 |
| `rswitch_maps.h` | **选择性使用**: 当需要 `rs_port_config_map`、`rs_stats_map`、`rs_mac_table` 等时添加。 |
| `rswitch_common.h` | **旧版**: 包含所有内容 (module.h + maps.h)。仅用于向后兼容。 |

---

## 2. 前提条件

- **clang** (≥ 12) 和 **llvm** (用于 BPF 目标)
- **libbpf** 头文件和库
- 支持 BTF 的 **Linux kernel** (`/sys/kernel/btf/vmlinux`)

如果 `include/vmlinux.h` 不存在，请生成它：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

### 在系统范围内安装 SDK（可选）

如果您想在 rSwitch 源码树之外构建模块：

```bash
# 在 rswitch/ 目录下执行：
sudo make install-sdk

# 验证：
pkg-config --cflags rswitch
# 输出：-I/usr/local/include/rswitch
```

这会将头文件安装到 `/usr/local/include/rswitch/`，pkg-config 安装到 `/usr/local/lib/pkgconfig/rswitch.pc`，模板安装到 `/usr/local/share/rswitch/templates/`。

---

## 3. 构建您的第一个模块

本指南将演示如何使用已安装的 SDK 从头开始构建一个数据包计数器模块。该模块按源 IP 统计数据包，并在发现新源时发出事件。

### 3.1 设置

```bash
mkdir ~/my_rswitch_module && cd ~/my_rswitch_module

# 拷贝简单模板作为起点
cp /usr/local/share/rswitch/templates/simple_module.bpf.c pkt_counter.bpf.c

# 拷贝构建规则
cp /usr/local/share/rswitch/Makefile.module Makefile.module
```

### 3.2 编写模块

将 `pkt_counter.bpf.c` 的内容替换为：

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * pkt_counter — 按源 IP 统计数据包，在新源出现时发出事件。
 *
 * 演示内容：
 *   - 用户阶段范围 (210)
 *   - 私有 BPF map
 *   - 用户事件发送 (RS_EVENT_USER_BASE)
 *   - Pipeline 延续 (RS_TAIL_CALL_NEXT)
 */

#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE(
    "pkt_counter",
    RS_HOOK_XDP_INGRESS,
    210,                                        /* 用户 ingress 阶段 (200-299) */
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_CREATES_EVENTS,
    "Counts packets per source IP"
);

/* 用户事件：发现新源 IP */
#define PKT_COUNTER_EVENT_NEW_SRC  (RS_EVENT_USER_BASE + 0x01)  /* 0x1001 */

/* 私有每源 IP 计数器 map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);             /* 源 IPv4 地址 */
    __type(value, __u64);           /* 数据包计数 */
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_pkt_counter_map SEC(".maps");

/* 新源通知的事件结构 */
struct pkt_counter_event {
    __u16 type;
    __u16 len;
    __u32 src_ip;
    __u64 timestamp;
};

SEC("xdp")
int pkt_counter_func(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_DROP;

    /* 仅统计 IPv4 数据包 */
    if (!ctx->parsed || ctx->layers.eth_proto != __bpf_htons(0x0800))
        goto next;

    __u32 src_ip = ctx->layers.saddr;
    __u64 *count = bpf_map_lookup_elem(&rs_pkt_counter_map, &src_ip);

    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        /* 新源 IP — 初始化计数器并发出事件 */
        __u64 one = 1;
        bpf_map_update_elem(&rs_pkt_counter_map, &src_ip, &one, BPF_ANY);

        struct pkt_counter_event evt = {
            .type = PKT_COUNTER_EVENT_NEW_SRC,
            .len = sizeof(evt),
            .src_ip = src_ip,
            .timestamp = bpf_ktime_get_ns(),
        };
        RS_EMIT_EVENT(&evt, sizeof(evt));
    }

next:
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;
}
```

### 3.3 构建

```bash
make -f Makefile.module MODULE=pkt_counter
```

预期输出：
```
Built: pkt_counter.bpf.o
```

### 3.4 验证模块元数据

```bash
make -f Makefile.module MODULE=pkt_counter verify
```

这将读取 `.rodata.mod` ELF 节，以确认模块名称、ABI 版本、阶段 (stage) 和标志 (flags) 已正确嵌入。

### 3.5 检查对象文件（可选）

```bash
# 检查 ELF 节
llvm-objdump -h pkt_counter.bpf.o

# 您应该看到：
#   .rodata.mod  — 模块元数据 (name, stage, flags)
#   .maps        — BPF map 定义 (rs_pkt_counter_map)
#   xdp          — XDP 程序节
```

### 3.6 安装与加载

```bash
# 安装编译好的模块
sudo make -f Makefile.module MODULE=pkt_counter install
# 安装路径：/usr/local/lib/rswitch/modules/pkt_counter.bpf.o

# 添加到您的 rSwitch profile (YAML)：
# modules:
#   - name: pkt_counter
#     stage: 210

# 或热加载到运行中的 pipeline：
rswitchctl reload pkt_counter
```

### 3.7 监控

```bash
# 检查模块统计信息
rswitchctl show-stats --module pkt_counter

# Dump 计数器 map
rswitchctl dev dump-map rs_pkt_counter_map

# 观察事件
rswitchctl dev trace --module pkt_counter
```

---

## 4. 创建模块

### 4.1 从模板创建

```bash
cp templates/simple_module.bpf.c my_filter.bpf.c
```

编辑文件：
1. 使用您的模块名称、阶段、标志和描述更新 `RS_DECLARE_MODULE()`
2. 重命名 XDP 函数
3. 添加您的数据包处理逻辑
4. 可选地使用 `RS_DEPENDS_ON()` 添加依赖项

### 4.2 使用 rswitchctl 脚手架

如果您安装了完整的 rSwitch，可以使用脚手架 CLI：

```bash
rswitchctl new-module my_filter --stage 210 --hook ingress --flags NEED_L2L3_PARSE,MAY_DROP
```

这将生成一个准备好构建的模块源文件。

### 4.3 模块结构

每个 rSwitch BPF 模块都遵循以下结构：

```c
// SPDX-License-Identifier: GPL-2.0
#include "rswitch_module.h"

char _license[] SEC("license") = "GPL";

// 1. 模块声明（嵌入在 .rodata.mod ELF 节中）
RS_DECLARE_MODULE(
    "my_filter",                                    // 名称（最大 32 字符）
    RS_HOOK_XDP_INGRESS,                            // 挂载点 (Hook point)
    210,                                            // 阶段编号（用户范围：200-299）
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP,     // 能力标志
    "Filters packets by custom criteria"            // 描述
);

// 2. 可选：依赖声明
RS_DEPENDS_ON("vlan");  // 要求在此模块之前进行 VLAN 处理

// 3. XDP 程序入口点
SEC("xdp")
int my_filter_func(struct xdp_md *xdp_ctx)
{
    // 获取 per-CPU 共享上下文
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;

    // 访问解析后的报头
    void *data = (void *)(long)xdp_ctx->data;
    void *data_end = (void *)(long)xdp_ctx->data_end;

    // 使用 verifier 安全的偏移掩码
    struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    // 您的过滤逻辑...

    // 继续执行 pipeline 中的下一个模块
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;  // 默认回退 = drop
}
```

---

## 5. 构建

```bash
make -f Makefile.module MODULE=my_filter
```

输出：`my_filter.bpf.o`

验证模块元数据：

```bash
make -f Makefile.module MODULE=my_filter verify
```

---

## 6. 关键 API 参考

### 6.1 模块声明

| 宏 / 常量 | 描述 |
|-------------------|-------------|
| `RS_DECLARE_MODULE(name, hook, stage, flags, desc)` | 在 `.rodata.mod` 节中声明模块元数据 |
| `RS_HOOK_XDP_INGRESS` | Ingress pipeline 挂载点 |
| `RS_HOOK_XDP_EGRESS` | Egress pipeline 挂载点 |
| `RS_ABI_VERSION` | 当前 ABI 版本 (v2.0 = `0x00020000`) |

### 6.2 能力标志 (Capability Flags)

| 标志 | 含义 |
|------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | 模块需要 `ctx->layers` 中解析好的 L2/L3 报头 |
| `RS_FLAG_NEED_VLAN_INFO` | 模块需要 VLAN 信息 |
| `RS_FLAG_NEED_FLOW_INFO` | 模块需要 5 元组流信息（L4 端口、协议） |
| `RS_FLAG_MODIFIES_PACKET` | 模块可能会修改数据包数据 |
| `RS_FLAG_MAY_DROP` | 模块可能会丢弃数据包 |
| `RS_FLAG_CREATES_EVENTS` | 模块会向 `rs_event_bus` 生成事件 |
| `RS_FLAG_MAY_REDIRECT` | 模块可能会通过 `bpf_redirect_map` 重定向数据包 |

### 6.3 上下文与 Pipeline 宏

| 宏 | 描述 |
|-------|-------------|
| `RS_GET_CTX()` | 从 per-CPU map 返回每个数据包的 `struct rs_ctx *` |
| `RS_TAIL_CALL_NEXT(xdp_ctx, ctx)` | 继续 ingress pipeline（自动增加 slot） |
| `RS_TAIL_CALL_EGRESS(xdp_ctx, ctx)` | 继续 egress pipeline（从 `rs_prog_chain` 读取下一个 slot） |
| `RS_EMIT_EVENT(event_ptr, size)` | 向统一事件总线发送结构化事件 |

### 6.4 依赖声明

| 宏 | 描述 |
|-------|-------------|
| `RS_DEPENDS_ON("mod1")` | 声明一个依赖项 |
| `RS_DEPENDS_ON("mod1", "mod2")` | 声明两个依赖项 |
| `RS_DEPENDS_ON("mod1", "mod2", "mod3")` | 声明三个依赖项 |
| `RS_DEPENDS_ON("mod1", "mod2", "mod3", "mod4")` | 声明四个依赖项（最大值） |

依赖项声明在 `.rodata.moddep` 节中，并由加载器使用拓扑排序进行解析。

### 6.5 API 稳定性分级

| 注解 | 保证 |
|-----------|-----------|
| `RS_API_STABLE` | 跨次要版本不会有破坏性变更 |
| `RS_API_EXPERIMENTAL` | 可能会在次要版本之间发生变化 |
| `RS_API_INTERNAL` | 可能随时更改；请勿在外部模块中使用 |

6.1–6.4 节中的所有宏均为 **RS_API_STABLE**。有关版本语义和弃用规则，请参阅 [ABI 稳定性策略](../../docs/development/ABI_POLICY.md)。

### 6.6 Per-CPU 上下文 (`struct rs_ctx`)

共享上下文由上游模块填充，并由下游模块使用：

| 字段 | 类型 | 设置者 | 描述 |
|-------|------|--------|-------------|
| `ifindex` | `__u32` | dispatcher | Ingress 接口索引 |
| `timestamp` | `__u32` | dispatcher | 数据包到达时间戳 |
| `parsed` | `__u8` | dispatcher | 如果 L2/L3 报头已解析则为 1 |
| `modified` | `__u8` | 任何模块 | 如果数据包数据被修改则为 1 |
| `layers` | `struct rs_layers` | dispatcher/vlan | 解析后的报头偏移量和值 |
| `ingress_vlan` | `__u16` | vlan | 分类的 ingress VLAN |
| `egress_vlan` | `__u16` | vlan/route | 用于 egress 的 VLAN |
| `prio` | `__u8` | qos_classify | 优先级 (0-7) |
| `dscp` | `__u8` | qos_classify | DSCP 值 |
| `traffic_class` | `__u8` | qos_classify | 流量类别 |
| `egress_ifindex` | `__u32` | route/l2learn | 目标输出端口 |
| `action` | `__u8` | 任何模块 | XDP_PASS / XDP_DROP / XDP_REDIRECT 等 |
| `mirror` | `__u8` | mirror | 如果需要镜像则为 1 |
| `mirror_port` | `__u16` | mirror | 镜像目的端口 |
| `error` | `__u32` | 任何模块 | `RS_ERROR_*` 代码 |
| `drop_reason` | `__u32` | 任何模块 | `RS_DROP_*` 原因 |
| `next_prog_id` | `__u32` | pipeline | 下一个模块 slot（由宏管理） |
| `call_depth` | `__u32` | pipeline | 递归保护（最大 32） |
| `reserved[16]` | `__u32[16]` | — | 预留未来使用（64 字节，ABI v2） |

### 6.7 解析层 (`struct rs_layers`)

| 字段 | 类型 | 描述 |
|-------|------|-------------|
| `eth_proto` | `__u16` | 以太网协议 (ETH_P_IP, ETH_P_IPV6 等) |
| `vlan_ids[2]` | `__u16[]` | VLAN ID（外层、内层 — 支持 Q-in-Q） |
| `vlan_depth` | `__u8` | VLAN 标签数量 (0-2) |
| `ip_proto` | `__u8` | IP 协议 (IPPROTO_TCP, IPPROTO_UDP 等) |
| `saddr` | `__be32` | 源 IPv4 地址 |
| `daddr` | `__be32` | 目的 IPv4 地址 |
| `sport` | `__be16` | 源 L4 端口 |
| `dport` | `__be16` | 目的 L4 端口 |
| `l2_offset` | `__u16` | 以太网报头偏移量 |
| `l3_offset` | `__u16` | IP 报头偏移量 |
| `l4_offset` | `__u16` | TCP/UDP 报头偏移量 |
| `payload_offset` | `__u16` | 有效载荷偏移量 |
| `payload_len` | `__u32` | 有效载荷长度 |

### 6.8 Verifier 安全的偏移掩码

在进行指针运算之前，务必对偏移量进行掩码处理，以通过 BPF verifier：

| 掩码 | 值 | 用于 |
|------|-------|---------|
| `RS_L3_OFFSET_MASK` | `0x3F` (63) | L3 报头访问 |
| `RS_L4_OFFSET_MASK` | `0x7F` (127) | L4 报头访问 |
| `RS_PAYLOAD_MASK` | `0xFF` (255) | 有效载荷访问 |

```c
// 正确：在指针运算前掩码偏移量
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end) return XDP_DROP;

// 错误：原始偏移量 — BPF verifier 将拒绝
struct iphdr *iph = data + ctx->layers.l3_offset;  // 被拒绝
```

### 6.9 模块配置

模块可以从 YAML profile 接收每模块配置参数：

```c
#include "rswitch_module.h"
#include "rswitch_maps.h"       /* rs_get_module_config 需要 */

// 读取 profile 设置的配置参数
struct rs_module_config_value *val = rs_get_module_config("my_filter", "threshold");
if (val && val->type == 0 /* int */) {
    __s64 threshold = val->int_val;
    // 使用 threshold...
}
```

Profile YAML:
```yaml
modules:
  - name: my_filter
    stage: 210
    config:
      threshold: 1000
```

### 6.10 每模块统计信息

跟踪您模块的处理统计信息：

```c
#include "rswitch_module.h"
#include "rswitch_maps.h"       /* rs_module_stats_inc 需要 */

// 在模块处理结束时调用
rs_module_stats_inc(ctx, RS_MODULE_STATS_PROCESSED);  // 或 FORWARDED, DROPPED, ERROR
```

统计信息可通过 CLI 访问：
```bash
rswitchctl show-stats --module my_filter
rswitchctl show-stats --module my_filter --json
```

### 6.11 事件总线 (Event Bus)

向用户态发送结构化事件：

```c
struct {
    __u16 type;
    __u16 len;
    __u32 src_ip;
    __u32 reason;
} my_event;

my_event.type = RS_EVENT_USER_BASE + 0x01;  /* 用户事件范围：0x1000-0x7FFF */
my_event.len = sizeof(my_event);
my_event.src_ip = ctx->layers.saddr;
my_event.reason = 42;

RS_EMIT_EVENT(&my_event, sizeof(my_event));
```

事件类型范围（按功能命名空间划分）：
```
0x0000-0x0FFF  核心预留（rSwitch 内部）
0x1000-0x7FFF  用户模块 (RS_EVENT_USER_BASE 到 RS_EVENT_USER_MAX)
0x8000-0xFEFF  预留未来使用
0xFF00-0xFFFF  错误事件（核心）
```

用户模块必须使用 `RS_EVENT_USER_BASE` (0x1000) 到 `RS_EVENT_USER_MAX` (0x7FFF) 范围内的事件类型。请相对于 `RS_EVENT_USER_BASE` 定义您的事件：

```c
#define MY_EVENT_FOO  (RS_EVENT_USER_BASE + 0x01)  /* 0x1001 */
#define MY_EVENT_BAR  (RS_EVENT_USER_BASE + 0x02)  /* 0x1002 */
```

### 6.12 共享 Maps

您的模块可以通过包含 `rswitch_maps.h` 来访问平台范围的共享 maps：

```c
#include "rswitch_module.h"
#include "rswitch_maps.h"
```

| Map | 访问权限 | 用途 |
|-----|--------|---------|
| `rs_port_config_map` | 只读 | 每端口配置 |
| `rs_stats_map` | 读/写 | 每接口统计信息 |
| `rs_module_stats_map` | 读/写 | 每模块统计信息 |
| `rs_vlan_map` | 只读 | VLAN 成员资格位掩码 |
| `rs_mac_table` | 只读 | MAC 转发表 (extern) |
| `rs_module_config_map` | 只读 | 模块配置参数 |
| `rs_event_bus` | 只写 | 事件发送 |

常用操作的辅助函数：
```c
// 端口配置查找
struct rs_port_config *port = rs_get_port_config(ctx->ifindex);

// 统计信息更新
rs_stats_update_rx(ctx, packet_bytes);
rs_stats_update_drop(ctx);

// MAC 表查找
struct rs_mac_entry *entry = rs_mac_lookup(eth->h_dest, ctx->ingress_vlan);

// VLAN 成员资格检查
int is_tagged;
int member = rs_is_vlan_member(vlan_id, ifindex, &is_tagged);
```

如果您的模块**不**需要共享 maps（例如，它仅检查 `ctx` 字段并进行自己的处理），请省略 `rswitch_maps.h` 以保持您的 BPF 对象精简。

---

## 7. 阶段编号约定 (Stage Number Conventions)

模块按阶段编号升序（ingress）或 slot 编号降序（egress）执行。请根据您的模块在处理 pipeline 中的位置选择阶段编号。

### 核心 Ingress Pipeline（阶段 10–99）

| 范围 | 阶段 | 内置模块 |
|-------|-------|------------------|
| 10-12 | 预处理 | `dispatcher`(10), `lacp`(11), `lldp`(11), `stp`(12) |
| 15-19 | 早期过滤 | `tunnel`(15), `source_guard`(18), `dhcp_snoop`(19) |
| 20-29 | VLAN + QoS | `vlan`(20), `qos_classify`(25), `rate_limiter`(28) |
| 30-39 | 访问控制 | `acl`(30), `conntrack`(32) |
| 40-49 | 镜像 | `mirror`(45) |
| 50-59 | 路由 + NAT | `route`(50), `nat`(55) |
| 60-69 | 流加速 | `flow_table`(60) |
| 70-79 | 预留 | — |
| 80-89 | 学习 + 采样 | `l2learn`(80), `arp_learn`(80), `afxdp_redirect`(85), `sflow`(85) |
| 90-99 | 最终阶段 | `lastcall`(90) — **始终最后** |

### 核心 Egress Pipeline（阶段 100–199）

| 范围 | 阶段 | 内置模块 |
|-------|-------|------------------|
| 100-169 | 自定义 egress 处理 | — |
| 170-179 | QoS 强制执行 | `egress_qos`(170) |
| 180-189 | VLAN 打标签 | `egress_vlan`(180) |
| 190-199 | 最终阶段 | `egress_final`(190) — **始终最后** |

### 用户 Ingress 阶段 (200–299) ← 您的模块

| 范围 | 建议用途 |
|-------|---------------|
| 200-219 | 用户预处理（早期过滤、分类） |
| 220-259 | 用户通用处理（主要模块逻辑） |
| 260-289 | 用户后处理（丰富信息、注解） |
| 290-299 | 用户最终阶段（日志、遥测） |

### 用户 Egress 阶段 (400–499) ← 您的模块

| 范围 | 建议用途 |
|-------|---------------|
| 400-419 | 用户 egress 前处理 (egress 过滤) |
| 420-469 | 用户通用 egress（重写、打标签） |
| 470-499 | 用户 egress 最终阶段（计数器、镜像） |

### 选择阶段编号

1. **外部模块必须使用用户范围**: ingress 200-299, egress 400-499
2. 确定您的模块应该在哪些现有模块**之前**和**之后**运行
3. 在适当的用户子范围中选取一个阶段编号
4. 如果您的模块有依赖项，请使用 `RS_DEPENDS_ON()` 声明它们
5. 阶段编号可以在 YAML profile 中覆盖（如果指定，加载器将使用 profile 中的值）

> **为什么要分不同的范围？** 核心阶段 (10-99, 100-199) 预留给 rSwitch 内置模块。使用用户范围 (200-299, 400-499) 可确保您的模块不会与当前或未来的核心模块发生冲突。

---

## 8. 测试

### 8.1 使用 test_harness.h 进行单元测试

```c
#include "../test/test_harness.h"

RS_TEST(test_my_filter_drops_invalid) {
    // 设置测试上下文
    struct rs_ctx ctx = { .layers.saddr = 0x0A000001 };

    // 测试您的过滤逻辑
    int result = my_filter_logic(&ctx);

    RS_ASSERT_EQ(result, XDP_DROP);
    RS_ASSERT_EQ(ctx.drop_reason, RS_DROP_ACL_BLOCK);
}

RS_TEST(test_my_filter_passes_valid) {
    struct rs_ctx ctx = { .layers.saddr = 0xC0A80001 };
    int result = my_filter_logic(&ctx);
    RS_ASSERT_EQ(result, XDP_PASS);
}

int main() {
    RS_RUN_ALL_TESTS();
    return 0;
}
```

可用的断言：
- `RS_ASSERT_EQ(a, b)` — 断言相等
- `RS_ASSERT_NE(a, b)` — 断言不等
- `RS_ASSERT_TRUE(cond)` — 断言条件为真
- `RS_ASSERT_FALSE(cond)` — 断言条件为假

### 8.2 使用 mock_maps.h 进行 Map Mocks

在用户态测试 map 相关逻辑，无需加载内核 map：

```c
#include "../test/mock_maps.h"

RS_TEST(test_flow_tracking) {
    // mock_maps.h 提供模拟的 map 操作
    struct flow_key key = { .src_ip = 0x0A000001 };
    struct flow_value val = { .packets = 0 };

    // 测试您的 map 更新逻辑
    mock_map_update(&key, &val);
    struct flow_value *result = mock_map_lookup(&key);
    RS_ASSERT_TRUE(result != NULL);
}
```

---

## 9. 安装与部署

### 9.1 安装编译好的模块

```bash
sudo make -f Makefile.module MODULE=my_filter install
```

安装到 `/usr/local/lib/rswitch/modules/my_filter.bpf.o`。

### 9.2 打包为 .rsmod

```bash
rswitchctl pack-module ./my_filter.bpf.o
# 创建 my_filter.rsmod
```

从安装包安装：
```bash
rswitchctl install-module my_filter.rsmod
```

列出已安装模块：
```bash
rswitchctl list-modules
```

### 9.3 添加到 Profile

在 YAML profile 中包含您的模块：

```yaml
# 简单形式（使用模块内置的阶段编号）
modules:
  - my_filter

# 扩展形式（带有覆盖和配置）
modules:
  - name: my_filter
    stage: 210                         # 覆盖阶段编号
    optional: true                     # 如果未找到模块则不报错
    condition: "interface:eth2"        # 仅当 eth2 存在时加载
    config:
      threshold: 1000
      mode: "strict"
```

### 9.4 热加载 (Hot-Reload)

在不中断 pipeline 的情况下替换运行中的模块：

```bash
rswitchctl reload my_filter              # 原子切换
rswitchctl reload my_filter --dry-run    # 仅验证
```

---

## 10. Map Pinning 约定

所有核心 rSwitch maps 都通过 `LIBBPF_PIN_BY_NAME` 固定到扁平的 `/sys/fs/bpf/` 目录。用户模块应以同样的方式固定其私有 maps — map 名称应以 `rs_` 或您的模块前缀开头，以避免冲突。

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  /* 固定到 /sys/fs/bpf/rs_my_map */
} rs_my_map SEC(".maps");
```

详情请参阅 [Map Pinning 约定](../../docs/development/MAP_PINNING.md)。

---

## 11. 可用的内置模块

rSwitch 附带 27 个 BPF 模块，涵盖了完整的网络栈：

| 类别 | 模块 |
|----------|---------|
| **核心** (4) | `dispatcher`, `egress`, `egress_final`, `lastcall` |
| **L2 交换** (6) | `vlan`, `egress_vlan`, `l2learn`, `stp`, `lacp`, `lldp` |
| **L3 路由** (4) | `route` (ECMP/ARP), `conntrack`, `nat` (SNAT/DNAT), `flow_table` |
| **安全** (3) | `acl`, `source_guard`, `dhcp_snoop` |
| **QoS** (3) | `qos_classify`, `rate_limiter`, `egress_qos` |
| **监控** (2) | `mirror` (SPAN/RSPAN/ERSPAN), `sflow` |
| **隧道** (1) | `tunnel` (VXLAN/GRE) |
| **工具** (4) | `arp_learn`, `afxdp_redirect`, `core_example`, `veth_egress` |

有关详细说明，请参阅 [平台架构 — 模块分类](../../docs/development/Platform_Architecture.md#9-module-classification)。

---

## 12. CLI 工具参考

### 平台管理

| 命令 | 描述 |
|---------|-------------|
| `rswitchctl show-pipeline` | 显示活动的 pipeline 模块和阶段 |
| `rswitchctl show-stats [--module <name>] [--json]` | 接口或每模块统计信息 |
| `rswitchctl show-abi` | 显示 ABI 版本和模块兼容性 |
| `rswitchctl show-profile <file> [--resolved]` | 显示 profile（包含继承解析） |
| `rswitchctl validate-profile <file> [--json]` | 验证 profile 而不加载 |
| `rswitchctl reload <module> [--dry-run]` | 热加载模块 |
| `rswitchctl health [--json]` | 系统健康检查 |

### 模块管理

| 命令 | 描述 |
|---------|-------------|
| `rswitchctl new-module <name> --stage N --hook <ingress\|egress>` | 从模板生成模块 |
| `rswitchctl pack-module <file.bpf.o>` | 将模块打包为 .rsmod |
| `rswitchctl install-module <file.rsmod>` | 从安装包安装模块 |
| `rswitchctl list-modules` | 列出已安装模块 |

### 开发者工具

| 命令 | 描述 |
|---------|-------------|
| `rswitchctl dev inspect <module.bpf.o>` | 检查模块元数据 (ABI, deps, maps, sections) |
| `rswitchctl dev maps` | 列出所有固定的 BPF maps 及其大小 |
| `rswitchctl dev dump-map <map_name>` | Dump map 内容 |
| `rswitchctl dev trace [--module <name>]` | 实时跟踪数据包通过 pipeline 的过程 |
| `rswitchctl dev perf` | 每模块性能分析 |

### 配置管理

| 命令 | 描述 |
|---------|-------------|
| `rswitchctl apply <profile> [--confirm N]` | 应用 profile 并带有自动回滚定时器 |
| `rswitchctl confirm` | 确认应用更改（取消回滚定时器） |
| `rswitchctl rollback` | 回滚到上一个配置 |
| `rswitchctl snapshot-create [description]` | 创建命名的配置快照 |
| `rswitchctl snapshot-list` | 列出可用快照 |

---

## 13. 延伸阅读

- [ABI 稳定性策略](../../docs/development/ABI_POLICY.md) — 版本语义、稳定性分级、弃用规则
- [Map Pinning 约定](../../docs/development/MAP_PINNING.md) — Map 固定路径标准
- [平台架构](../../docs/development/Platform_Architecture.md) — 完整的平台设计、模块分类和阶段图
- [模块开发者指南](../../docs/development/Module_Developer_Guide.md) — 深入的模块开发模式
- [API 参考](../../docs/development/API_Reference.md) — 完整的 API 文档
- [CO-RE 指南](../../docs/development/CO-RE_Guide.md) — 跨内核可移植性模式
- [贡献指南](../../docs/development/Contributing.md) — 如何为 rSwitch 做出贡献
