# API参考

rSwitch模块开发人员、集成人员和操作人员的完整API参考。本文档涵盖了三个API层的所有公共接口。

---

## API层

| 层 | 受众 | 用途 |
|-------|----------|---------|
| **BPF Module API** | 模块开发人员 | 创建自定义数据包处理模块 |
| **Profile API** | 操作人员 | 通过YAML配置流水线 |
| **Control API** | 应用程序 | 运行时控制和监控 |

---

## 1. BPF Module API

### 头文件

```c
#include "rswitch_bpf.h"    // 主要 BPF 头文件（包含 vmlinux.h, helpers）
#include "module_abi.h"     // 模块自注册 (RS_DECLARE_MODULE)
#include "uapi.h"           // 共享结构体 (rs_ctx, rs_layers)
#include "map_defs.h"       // Map 定义和辅助函数
```

位置：`bpf/include/` 和 `bpf/core/`

---

### 核心宏

#### RS_DECLARE_MODULE

通过在ELF `.rodata.mod` 节中嵌入元数据，将模块注册到自动发现系统。

```c
RS_DECLARE_MODULE(name, hook, stage, flags, description)
```

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `name` | `const char*` | 模块标识符（最多31个字符）—— 与YAML profile条目匹配 |
| `hook` | `enum` | `RS_HOOK_XDP_INGRESS` 或 `RS_HOOK_XDP_EGRESS` |
| `stage` | `__u32` | 执行顺序：10-99 (ingress), 100-199 (egress) |
| `flags` | `__u32` | 能力标志（按位或组合，见下表） |
| `description` | `const char*` | 人类可读的描述（最多63个字符） |

#### RS_GET_CTX

从 `rs_ctx_map` 中检索每个CPU的数据包上下文。

```c
struct rs_ctx *ctx = RS_GET_CTX();
// 返回：指向 struct rs_ctx 的指针，失败时返回 NULL
```

**始终**检查返回值是否为NULL。

#### RS_TAIL_CALL_NEXT

继续执行 **ingress** 流水线中的下一个模块。

```c
RS_TAIL_CALL_NEXT(xdp_ctx, rs_ctx)
```

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `xdp_ctx` | `struct xdp_md *` | XDP上下文 |
| `rs_ctx` | `struct rs_ctx *` | rSwitch每个CPU的上下文 |

行为：递增 `rs_ctx->next_prog_id`，执行 `bpf_tail_call()` 到下一个ingress插槽。如果尾调用失败，控制权将返回给调用者。

#### RS_TAIL_CALL_EGRESS

继续执行 **egress** 流水线中的下一个模块。

```c
RS_TAIL_CALL_EGRESS(xdp_ctx, rs_ctx)
```

行为：从 `rs_prog_chain` map中查找下一个模块。Egress插槽从255开始降序分配。

#### RS_EMIT_EVENT

通过统一的环形缓冲区 (`rs_event_bus`) 向用户空间发送结构化事件。

```c
int RS_EMIT_EVENT(event_ptr, event_size)
// 返回：成功时返回 0，环形缓冲区满时返回 -1
```

---

### 能力标志

| 标志 | 值 | 含义 |
|------|-------|---------|
| `RS_FLAG_NEED_L2L3_PARSE` | `0x01` | 模块需要解析L2/L3头 |
| `RS_FLAG_NEED_VLAN_INFO` | `0x02` | 模块需要VLAN信息 |
| `RS_FLAG_NEED_FLOW_INFO` | `0x04` | 模块需要五元组流信息 |
| `RS_FLAG_MODIFIES_PACKET` | `0x08` | 模块可能会修改数据包数据 |
| `RS_FLAG_MAY_DROP` | `0x10` | 模块可能会丢弃数据包 |
| `RS_FLAG_CREATES_EVENTS` | `0x20` | 模块会生成环形缓冲区事件 |

---

### 数据结构

#### struct rs_module_desc

通过 `RS_DECLARE_MODULE()` 嵌入到ELF `.rodata.mod` 节中：

```c
struct rs_module_desc {
    __u32 abi_version;      // ABI 兼容性检查
    __u32 hook;             // RS_HOOK_XDP_INGRESS 或 RS_HOOK_XDP_EGRESS
    __u32 stage;            // 执行顺序（越低越早）
    __u32 flags;            // RS_FLAG_* 能力位
    char  name[32];         // 模块标识符
    char  description[64];  // 人类可读的描述
};
```

#### struct rs_ctx

跨所有流水线模块共享的每个数据包处理上下文：

```c
struct rs_ctx {
    // 输入元数据
    __u32 ifindex;              // Ingress 接口索引
    __u32 timestamp;            // 数据包到达时间戳

    // 解析状态
    __u8  parsed;               // 0 = 未解析, 1 = L2/L3 已解析
    __u8  modified;             // 0 = 未更改, 1 = 数据包已修改
    struct rs_layers layers;    // 已解析的层信息

    // VLAN 处理
    __u16 ingress_vlan;         // 在 ingress 处确定的 VLAN ID
    __u16 egress_vlan;          // 用于 egress 打标的 VLAN ID

    // QoS 和优先级
    __u8  prio;                 // 优先级 (0-7, 7 = 最高)
    __u8  dscp;                 // DSCP 值
    __u8  ecn;                  // ECN 位
    __u8  traffic_class;        // 用户定义的流量类别

    // 转发决策
    __u32 egress_ifindex;       // 目标 egress 接口
    __u8  action;               // XDP_PASS, XDP_DROP, XDP_REDIRECT
    __u8  mirror;               // 0 = 不镜像, 1 = 需要镜像
    __u16 mirror_port;          // 镜像目的端口

    // 错误处理
    __u32 error;                // 错误码 (RS_ERROR_*)
    __u32 drop_reason;          // 丢弃原因 (RS_DROP_*)

    // 流水线状态
    __u32 next_prog_id;         // 下一个要尾调用的程序插槽
    __u32 call_depth;           // 当前尾调用深度（递归保护）
};
```

#### struct rs_layers

已解析的数据包层信息：

```c
struct rs_layers {
    __u16 eth_proto;            // ETH_P_IP, ETH_P_IPV6, ETH_P_ARP 等
    __u16 vlan_ids[2];          // VLAN ID（外层，内层）
    __u8  vlan_depth;           // VLAN 标签数量 (0-2)
    __u8  ip_proto;             // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP 等

    __be32 saddr;               // 源 IP（网络字节序）
    __be32 daddr;               // 目的 IP（网络字节序）
    __be16 sport;               // 源端口（网络字节序）
    __be16 dport;               // 目的端口（网络字节序）

    __u16 l2_offset;            // 以太网头偏移
    __u16 l3_offset;            // IP 头偏移
    __u16 l4_offset;            // TCP/UDP 头偏移
    __u16 payload_offset;       // 载荷偏移
    __u32 payload_len;          // 载荷长度
};
```

---

### 辅助函数

#### 数据包访问 (CO-RE安全)

```c
struct ethhdr *get_ethhdr(struct xdp_md *ctx);
struct iphdr  *get_iphdr(struct xdp_md *ctx, __u16 offset);
struct ipv6hdr *get_ipv6hdr(struct xdp_md *ctx, __u16 offset);
void *GET_HEADER(struct xdp_md *ctx, __u16 offset, type);
```

#### CO-RE字段操作

```c
READ_KERN(dst, src);                        // CO-RE 字段读取
int FIELD_EXISTS(struct, field);            // 检查运行中的内核中是否存在该字段
size_t FIELD_SIZE(struct, field);           // 获取字段大小
int CHECK_BOUNDS(struct xdp_md *ctx, void *ptr, __u32 size);  // 数据包边界检查
```

#### 端口配置

```c
struct rs_port_config *rs_get_port_config(__u32 ifindex);
```

#### MAC表

```c
struct rs_mac_entry *rs_mac_lookup(__u8 *mac, __u16 vlan);
int rs_mac_update(__u8 *mac, __u16 vlan, __u32 ifindex, __u64 timestamp);
```

#### VLAN成员资格

```c
// 返回：1 表示是成员，0 表示不是
// 设置 *is_tagged：1 = 带标签成员，0 = 不带标签成员
int rs_is_vlan_member(__u16 vlan, __u32 ifindex, int *is_tagged);
```

#### 统计信息

```c
void rs_stats_update_rx(struct rs_ctx *ctx, __u32 bytes);
void rs_stats_update_drop(struct rs_ctx *ctx);
```

#### 调试

```c
// 条件调试输出（仅在带有 -DDEBUG 时）
bpf_debug(fmt, ...);
// 别名：
rs_debug(fmt, ...);
```

---

### 偏移掩码 (验证器安全)

在计算数据包数据指针时使用这些掩码，以满足BPF验证器的要求：

| 掩码 | 值 | 最大偏移 | 使用场景 |
|------|-------|------------|----------|
| `RS_L3_OFFSET_MASK` | `0x3F` | 63字节 | L2头（以太网 + 最多2个VLAN标签） |
| `RS_L4_OFFSET_MASK` | `0x7F` | 127字节 | L2 + L3头 |
| `RS_PAYLOAD_MASK` | `0xFF` | 255字节 | 完整协议栈头 |

使用模式：

```c
void *data = (void *)(long)xdp->data;
void *data_end = (void *)(long)xdp->data_end;

struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

---

### 错误码

#### 模块错误码 (`rs_ctx->error`)

| 代码 | 名称 | 描述 |
|------|------|-------------|
| 0 | `RS_ERROR_NONE` | 无错误 |
| 1 | `RS_ERROR_PARSE_FAILED` | 数据包解析失败 |
| 2 | `RS_ERROR_INVALID_VLAN` | 无效的VLAN配置 |
| 3 | `RS_ERROR_ACL_DENY` | ACL拒绝数据包 |
| 4 | `RS_ERROR_NO_ROUTE` | 无到达目的地的路由 |
| 5 | `RS_ERROR_QUEUE_FULL` | 队列已满 (QoS) |
| 99 | `RS_ERROR_INTERNAL` | 内部错误 |

#### 丢弃原因 (`rs_ctx->drop_reason`)

| 代码 | 名称 | 描述 |
|------|------|-------------|
| 0 | `RS_DROP_NONE` | 未丢弃 |
| 1 | `RS_DROP_PARSE_ERROR` | 数据包解析错误 |
| 2 | `RS_DROP_VLAN_FILTER` | VLAN成员过滤 |
| 3 | `RS_DROP_ACL_BLOCK` | ACL规则阻断 |
| 4 | `RS_DROP_NO_FWD_ENTRY` | MAC/FDB表中无转发条目 |
| 5 | `RS_DROP_TTL_EXCEEDED` | TTL降至零 |
| 6 | `RS_DROP_RATE_LIMIT` | 速率限制器丢弃 |
| 7 | `RS_DROP_CONGESTION` | 拥塞 / 队列溢出 |

---

## 2. Profile API (YAML配置)

### Profile结构

```yaml
name: "Profile Name"          # 必填
version: "1.0"                # 必填
description: "Description"    # 可选

# 模块选择（简单列表 —— 执行阶段顺序来自 ELF 元数据）
ingress:
  - module_name_1
  - module_name_2

egress:
  - egress_module_1
  - egress_module_2

# 全局设置
settings:
  mac_learning: true           # 启用 MAC 学习
  mac_aging_time: 300          # MAC 老化时间（秒）
  vlan_enforcement: true       # 强制执行 VLAN 成员资格
  default_vlan: 1              # 未打标数据包的默认 VLAN
  unknown_unicast_flood: true  # 泛洪未知单播
  broadcast_flood: true        # 泛洪广播
  stats_enabled: true          # 启用统计信息收集
  ringbuf_enabled: true        # 启用事件环形缓冲区
  debug: false                 # 启用调试日志

# 端口配置
ports:
  - interface: "eth0"
    enabled: true
    vlan_mode: trunk           # off | access | trunk | hybrid
    pvid: 1                    # 端口 VLAN ID
    native_vlan: 1             # Trunk 端口的 Native VLAN
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0        # 默认 QoS 优先级 (0-7)

# VLAN 配置
vlans:
  - vlan_id: 100
    name: "Management"
    tagged_ports: ["eth0", "eth1"]
    untagged_ports: []

# VOQd (QoS 调度器) 配置
voqd:
  enabled: false
  mode: 1                      # 0=BYPASS, 1=SHADOW, 2=ACTIVE
  num_ports: 4
  prio_mask: 0xFF
  zero_copy: true
  rx_ring_size: 4096
  tx_ring_size: 4096
  frame_size: 4096
  batch_size: 64
  poll_timeout_ms: 100
  enable_scheduler: true
  cpu_affinity: -1
  busy_poll: false
  enable_afxdp: true
  software_queues:
    enabled: false
    queue_depth: 1024
    num_priorities: 8
```

### VLAN模式

| 模式 | 值 | 行为 |
|------|-------|----------|
| `off` | 0 | 此端口不进行VLAN处理 |
| `access` | 1 | 仅限未打标流量；分配给 `pvid` |
| `trunk` | 2 | 带标签流量；未打标帧使用 `native_vlan` |
| `hybrid` | 3 | 混合带标签和未打标的VLAN |

### 可用模块

#### Ingress (阶段10-99)

| 模块 | 阶段 | 描述 |
|--------|-------|-------------|
| `vlan` | 20 | VLAN标签处理（access/trunk/hybrid模式） |
| `acl` | 30 | L3/L4访问控制列表 |
| `mirror` | 40 | SPAN端口镜像 |
| `route` | 50 | IPv4 LPM路由 |
| `l2learn` | 80 | MAC地址学习和老化 |
| `afxdp_redirect` | 85 | 用于QoS的AF_XDP套接字重定向 |
| `lastcall` | 90 | 最终转发决策（**必须放在最后**） |

#### Egress (阶段100-199)

| 模块 | 阶段 | 描述 |
|--------|-------|-------------|
| `egress_qos` | 170 | QoS分类和标记 |
| `egress_vlan` | 180 | Egress VLAN标签插入/移除 |
| `egress_final` | 190 | 最终egress处理（**必须放在最后**） |

### Profile示例

etc/profiles/中包含18个YAML profile文件。主要示例：

| Profile | 使用场景 |
|---------|----------|
| `dumb.yaml` | 透传（不处理） |
| `l2.yaml` | 基础L2交换机 |
| `l2-vlan.yaml` | 带VLAN的L2交换机 |
| `l3.yaml` | L3路由器 |
| `l3-acl-lab.yaml` | 带ACL过滤的L3路由器 |
| `firewall.yaml` | 基于ACL的防火墙 |
| `l3-qos-voqd-test.yaml` | 带有VOQd调度的完整QoS |
| `all-modules-test.yaml` | 加载所有模块（测试） |

---

## 3. Control API (C库)

### 加载器函数

```c
// 初始化加载器上下文
void loader_ctx_init(struct loader_ctx *ctx);

// 加载并解析 YAML profile
int profile_load(const char *filename, struct rs_profile *profile);

// 释放 profile 资源
void profile_free(struct rs_profile *profile);

// 将 profile 信息打印到 stdout
void profile_print(const struct rs_profile *profile);
```

### BPF Map访问 (通过libbpf)

```c
// 通过路径打开固定的 map
int bpf_obj_get(const char *pathname);

// 对 map 元素进行 CRUD 操作
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_delete_elem(int fd, const void *key);
```

### 固定的Map路径

| Map | 路径 | 类型 |
|-----|------|------|
| Context | `/sys/fs/bpf/rs_ctx_map` | PERCPU_ARRAY |
| Programs | `/sys/fs/bpf/rs_progs` | PROG_ARRAY |
| Program chain | `/sys/fs/bpf/rs_prog_chain` | ARRAY |
| Port config | `/sys/fs/bpf/rs_port_config_map` | HASH |
| Statistics | `/sys/fs/bpf/rs_stats_map` | PERCPU_ARRAY |
| Event bus | `/sys/fs/bpf/rs_event_bus` | RINGBUF |
| MAC table | `/sys/fs/bpf/rs_mac_table` | HASH |
| VLAN map | `/sys/fs/bpf/rs_vlan_map` | HASH |
| Device map | `/sys/fs/bpf/rs_xdp_devmap` | DEVMAP_HASH |

### 事件消费

```c
#include <bpf/libbpf.h>

static int handle_event(void *ctx, void *data, size_t size) {
    struct rs_event_header *hdr = data;
    switch (hdr->type) {
    case RS_EVENT_MAC_LEARNED:
        // 处理 MAC 学习事件
        break;
    case RS_EVENT_ACL_HIT:
        // 处理 ACL 命中事件
        break;
    }
    return 0;
}

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    while (running) {
        ring_buffer__poll(rb, 100);  // 100ms 超时
    }

    ring_buffer__free(rb);
    return 0;
}
```

---

## 4. CLI工具参考

### rswitchctl

```bash
rswitchctl show-pipeline          # 显示已加载的模块和流水线顺序
rswitchctl show-stats             # 显示每个端口的统计信息
rswitchctl stats [interface]      # 显示特定接口的统计信息
rswitchctl mac-table              # 显示 MAC 地址表
rswitchctl mac-add <mac> <vlan> <interface>   # 添加静态 MAC 条目
rswitchctl mac-del <mac> <vlan>               # 删除 MAC 条目
rswitchctl show-events            # 监控事件总线
```

### rsvlanctl

```bash
rsvlanctl show                    # 显示 VLAN 配置
rsvlanctl add <vlan_id> [name]    # 创建 VLAN
rsvlanctl del <vlan_id>           # 删除 VLAN
rsvlanctl add-port <vlan_id> <interface> [tagged|untagged]  # 将端口添加到 VLAN
```

### rsaclctl

```bash
rsaclctl show                     # 显示 ACL 规则
rsaclctl add <priority> <match> <action>   # 添加 ACL 规则
rsaclctl del <priority>           # 删除 ACL 规则
```

### rsqosctl

```bash
rsqosctl stats                    # 显示 QoS 统计信息
rsqosctl queues                   # 显示队列状态
rsqosctl set-prio <interface> <priority>   # 设置端口优先级
```

### rswitch_loader

```bash
rswitch_loader --profile <path>   # 使用指定的 YAML profile 加载
               --ifaces <if1,if2> # 附加到接口（逗号分隔）
               --verbose          # 启用详细输出
               --debug            # 启用调试日志
               --xdp-mode <mode>  # XDP 模式：native, generic, offload
               --detach           # 从接口分离 XDP 程序
```

### rswitch-voqd

```bash
rswitch-voqd -m <mode>            # VOQd 模式：0=BYPASS, 1=SHADOW, 2=ACTIVE
             -q <num>             # 软件队列数量
             -Q <depth>           # 队列深度
             -i <interfaces>     # 逗号分隔的接口列表
             -S <interval>       # 统计报告间隔（秒）
             -p <ports>          # 端口数量
             -P <prio_mask>      # 优先级掩码
```

---

## 5. 版本兼容性

| ABI版本 | rSwitch版本 | 备注 |
|-------------|-----------------|-------|
| 1 | 1.0.0+ | 初始版本 |

加载器在加载时会根据 `RS_ABI_VERSION` 检查 `rs_module_desc.abi_version`。不兼容的模块将被拒绝。

---

## 另请参阅

- [Architecture.md](./Architecture.md) — 系统架构概览
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — 模块开发教程
- [CO-RE_Guide.md](./CO-RE_Guide.md) — 跨内核可移植性
- [Configuration](../deployment/Configuration.md) — YAML profile格式详情
- [CLI_Reference](../usage/CLI_Reference.md) — CLI使用示例
