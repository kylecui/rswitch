# 统一事件总线重构总结

**日期**: 2025-11-05  
**状态**: ✅ 已完成  
**目标**: 创建统一事件总线，优化 Map Pinning 策略

## 重构内容

### 1. 创建统一事件总线 (`rs_event_bus`)

**位置**: `rswitch/bpf/core/uapi.h`

**定义**:
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 1MB ring */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_event_bus SEC(".maps");
```

**优势**:
- **内存效率**: 1MB 共享 vs N×256KB 独立（节省 3/4 内存）
- **简化消费**: 用户态单一读取器（vs 多个 ringbuf 轮询）
- **事件顺序**: 跨模块事件顺序一致
- **可扩展**: 所有模块使用同一总线

### 2. 事件类型命名空间

**事件范围分配**:
```c
#define RS_EVENT_RESERVED       0x0000
#define RS_EVENT_L2_BASE        0x0100  // L2Learn: 0x0100-0x01FF
#define RS_EVENT_ACL_BASE       0x0200  // ACL:     0x0200-0x02FF
#define RS_EVENT_ROUTE_BASE     0x0300  // Route:   0x0300-0x03FF
#define RS_EVENT_MIRROR_BASE    0x0400  // Mirror:  0x0400-0x04FF
#define RS_EVENT_QOS_BASE       0x0500  // QoS:     0x0500-0x05FF
#define RS_EVENT_ERROR_BASE     0xFF00  // Errors:  0xFF00-0xFFFF
```

**L2Learn 事件**:
```c
#define RS_EVENT_MAC_LEARNED    (RS_EVENT_L2_BASE + 1)  // 0x0101
#define RS_EVENT_MAC_MOVED      (RS_EVENT_L2_BASE + 2)  // 0x0102
#define RS_EVENT_MAC_AGED       (RS_EVENT_L2_BASE + 3)  // 0x0103
```

**扩展示例**:
```c
#define RS_EVENT_ACL_HIT        (RS_EVENT_ACL_BASE + 1) // 0x0201
#define RS_EVENT_ACL_DENY       (RS_EVENT_ACL_BASE + 2) // 0x0202
```

### 3. 统一事件发送宏 (`RS_EMIT_EVENT`)

**定义**:
```c
#define RS_EMIT_EVENT(event_ptr, event_size) ({ \
    void *__evt = bpf_ringbuf_reserve(&rs_event_bus, (event_size), 0); \
    int __ret = -1; \
    if (__evt) { \
        __builtin_memcpy(__evt, (event_ptr), (event_size)); \
        bpf_ringbuf_submit(__evt, 0); \
        __ret = 0; \
    } \
    __ret; \
})
```

**使用示例**:
```c
struct mac_learn_event event = {
    .event_type = RS_EVENT_MAC_LEARNED,
    .ifindex = ctx->ifindex,
    .vlan = vlan,
};
__builtin_memcpy(event.mac, mac, 6);

if (RS_EMIT_EVENT(&event, sizeof(event)) < 0) {
    rs_debug("Failed to emit event");
}
```

### 4. `rs_mac_table` 迁移到 L2Learn

**之前** (`map_defs.h`):
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rs_mac_table SEC(".maps");
```

**之后** (`l2learn.bpf.c`):
```c
/* MAC Forwarding Table - Primary Owner */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // 仍然 pinned！
} rs_mac_table SEC(".maps");
```

**保留在 `map_defs.h`**:
```c
/* Struct definitions kept for visibility */
struct rs_mac_key { ... };
struct rs_mac_entry { ... };

/* Helper functions updated with extern notes */
static __always_inline struct rs_mac_entry *rs_mac_lookup(...);
static __always_inline int rs_mac_update(...);
```

### 5. L2Learn 模块更新

**删除**:
- ❌ 独立 `rs_events` ringbuf (256KB, 未 pinned)
- ❌ 本地事件类型定义 (`RS_EVENT_MAC_*`)

**添加**:
- ✅ `rs_mac_table` map 定义（带 pinning）
- ✅ 使用统一 `RS_EMIT_EVENT` 宏

**更新后的 `emit_mac_event`**:
```c
static __always_inline void emit_mac_event(struct rs_ctx *ctx, 
                                           __u32 event_type,
                                           const __u8 *mac,
                                           __u16 vlan,
                                           __u32 ifindex)
{
    struct mac_learn_event event = {
        .event_type = event_type,
        .ifindex = ifindex,
        .vlan = vlan,
        .timestamp = bpf_ktime_get_ns(),
    };
    __builtin_memcpy(event.mac, mac, 6);
    
    if (RS_EMIT_EVENT(&event, sizeof(event)) < 0) {
        rs_debug("Failed to emit MAC event to event bus");
    }
}
```

## Pinning 策略变化

### 之前

| Map | 位置 | Pinning | 理由 |
|-----|------|---------|------|
| `rs_mac_table` | `map_defs.h` | ✅ | 共享基础设施 |
| `rs_events` | `l2learn.bpf.c` | ❌ | 单一所有者 |

### 之后

| Map | 位置 | Pinning | 理由 |
|-----|------|---------|------|
| `rs_mac_table` | `l2learn.bpf.c` | ✅ | 用户态需访问（aging/static entries） |
| `rs_event_bus` | `uapi.h` | ✅ | 跨模块共享基础设施 |

## 其他模块如何使用

### 读取 MAC Table

**在其他模块中（例如 `route.bpf.c`）**:
```c
// 使用 extern 引用 l2learn 定义的 pinned map
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
} rs_mac_table SEC(".maps");

SEC("xdp")
int route_ingress(struct xdp_md *ctx)
{
    // 直接使用 map_defs.h 中的 helper
    struct rs_mac_entry *entry = rs_mac_lookup(mac, vlan);
    if (entry) {
        // 使用查询结果
    }
}
```

### 发送事件到事件总线

**在任何模块中**:
```c
#include "../include/rswitch_common.h"  // 包含 uapi.h

// 定义模块特定事件结构
struct my_module_event {
    __u32 event_type;  // 使用分配的范围
    __u32 data1;
    __u64 timestamp;
};

// 发送事件
struct my_module_event evt = {
    .event_type = RS_EVENT_ACL_HIT,
    .data1 = some_value,
    .timestamp = bpf_ktime_get_ns(),
};

if (RS_EMIT_EVENT(&evt, sizeof(evt)) < 0) {
    rs_debug("Event emission failed");
}
```

## Loader 适配

### 访问 `rs_mac_table`

**之前** (从共享 maps):
```c
int mac_table_fd = bpf_object__find_map_fd_by_name(skel->obj, "rs_mac_table");
```

**之后** (从 l2learn 模块):
```c
// 1. 加载 l2learn 模块
struct bpf_object *l2learn_obj = ...;

// 2. 从 l2learn 对象获取 rs_mac_table FD
int mac_table_fd = bpf_object__find_map_fd_by_name(l2learn_obj, "rs_mac_table");

// 3. 或者从 pinned 路径获取
int mac_table_fd = bpf_obj_get("/sys/fs/bpf/rs_mac_table");
```

### 消费统一事件总线

**单一消费者循环**:
```c
int event_bus_fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
struct ring_buffer *rb = ring_buffer__new(event_bus_fd, handle_event, NULL, NULL);

while (running) {
    ring_buffer__poll(rb, 100 /* timeout_ms */);
}
```

**事件处理器**:
```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    __u32 *event_type = (__u32 *)data;
    
    switch (*event_type & 0xFF00) {  // 检查基础范围
    case RS_EVENT_L2_BASE:
        handle_l2_event(data, data_sz);
        break;
    case RS_EVENT_ACL_BASE:
        handle_acl_event(data, data_sz);
        break;
    case RS_EVENT_ERROR_BASE:
        handle_error_event(data, data_sz);
        break;
    default:
        fprintf(stderr, "Unknown event type: 0x%04x\n", *event_type);
    }
    
    return 0;
}
```

## 验证步骤

### 1. 编译检查

```bash
cd /home/kylecui/dev/rSwitch/rswitch
make clean
make

# 应该无错误编译
```

### 2. 加载后验证

```bash
# 加载 rswitch
sudo ./build/loader/rswitch_loader

# 检查 pinned maps
sudo ls -l /sys/fs/bpf/ | grep rs_

# 应该看到：
# rs_event_bus      <- 新增！
# rs_mac_table      <- 仍然存在（从 l2learn 创建）
# rs_ctx_map
# rs_progs
# rs_port_config_map
# rs_vlan_map
# rs_stats_map

# 验证 event_bus 大小
sudo bpftool map show name rs_event_bus
# max_entries: 1048576 (1MB)
```

### 3. 运行时测试

```bash
# 触发 MAC 学习事件
ping <target>

# 从 event bus 读取事件（user-space tool）
sudo ./build/tools/event_monitor

# 应该看到 MAC learning 事件：
# [0x0101] MAC_LEARNED: 00:11:22:33:44:55 on port 2, VLAN 100
```

## 优势总结

### 内存优化

| 场景 | 之前 | 之后 | 节省 |
|------|------|------|------|
| 单模块 (l2learn) | 256KB | 1MB (共享) | -768KB |
| 4个模块 | 1MB (4×256KB) | 1MB (共享) | **0KB** |
| 8个模块 | 2MB (8×256KB) | 1MB (共享) | **1MB** |

### 简化用户态

**之前**: N 个 ringbuf 消费者
```c
rb1 = ring_buffer__new(l2_events_fd, ...);
rb2 = ring_buffer__new(acl_events_fd, ...);
rb3 = ring_buffer__new(route_events_fd, ...);

// 轮询所有
ring_buffer__poll(rb1, timeout);
ring_buffer__poll(rb2, timeout);
ring_buffer__poll(rb3, timeout);
```

**之后**: 单一消费者
```c
rb = ring_buffer__new(event_bus_fd, handle_event, ...);
ring_buffer__poll(rb, timeout);  // 处理所有事件
```

### 架构清晰度

- **核心基础设施** (`uapi.h`): `rs_ctx_map`, `rs_progs`, `rs_event_bus`
- **共享配置** (`map_defs.h`): `rs_port_config_map`, `rs_vlan_map`, `rs_stats_map`
- **模块私有** (`modules/*.bpf.c`): `rs_mac_table` (l2learn), `rs_xdp_devmap` (lastcall)

## 迁移影响

### PoC 代码 (`src/`)

✅ **完全不受影响** - 独立代码库

### 现有 rSwitch 代码

需要更新的文件：
- ✅ `uapi.h` - 已更新
- ✅ `map_defs.h` - 已更新  
- ✅ `l2learn.bpf.c` - 已更新
- ⚠️ Loader - 需要适配 `rs_mac_table` 访问方式

### 未来模块

**模板代码**:
```c
#include "../include/rswitch_common.h"

// 定义模块事件类型（使用分配的范围）
#define MY_EVENT_TYPE1  (RS_EVENT_XXX_BASE + 1)

struct my_event {
    __u32 event_type;
    // ... 其他字段
};

SEC("xdp")
int my_module_func(struct xdp_md *ctx)
{
    // 发送事件
    struct my_event evt = { .event_type = MY_EVENT_TYPE1 };
    RS_EMIT_EVENT(&evt, sizeof(evt));
    
    // 读取 MAC table（如需要）
    struct rs_mac_entry *entry = rs_mac_lookup(mac, vlan);
    
    return XDP_PASS;
}
```

## 下一步

1. **更新 Loader** - 适配 `rs_mac_table` 从 l2learn 获取 FD
2. **实现事件消费者** - 创建 `event_monitor` 工具
3. **其他模块迁移** - ACL/Route 模块采用 `RS_EMIT_EVENT`
4. **文档更新** - 更新模块开发指南

## 参考

- **Map Pinning 策略**: `rswitch/docs/MAP_PINNING_STRATEGY.md`
- **模块 ABI**: `rswitch/bpf/core/module_abi.h`
- **原始讨论**: Conversation on 2025-11-05
