> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# 用户态统一事件总线更新总结

**日期**: 2025-11-05  
**状态**: ✅ 已完成  
**关联**: EVENT_BUS_REFACTOR.md

## 更新概览

用户态代码已完全适配统一事件总线（`rs_event_bus`）架构，从多个独立 ringbuf 迁移到单一共享事件总线。

## 修改文件

### 1. `user/loader/rswitch_loader.c`

#### 变更内容

**结构体更新**:
```c
struct loader_ctx {
    // 之前
    int rs_events_fd;
    
    // 之后
    int rs_event_bus_fd;     /* Unified event bus */
    int rs_mac_table_fd;     /* MAC table from l2learn module */
};
```

**初始化逻辑**:
```c
// 之前
ctx->rs_events_fd = -1;  /* From l2learn module */

// 之后
ctx->rs_event_bus_fd = -1;  /* From pinned path */
ctx->rs_mac_table_fd = -1;  /* From l2learn module */
```

**加载后获取 FD**:
```c
// 之前: 从 l2learn 模块获取 rs_events
for (int i = 0; i < ctx.num_modules; i++) {
    if (strcmp(ctx.modules[i].name, "l2learn") == 0) {
        struct bpf_map *map = bpf_object__find_map_by_name(
            ctx.modules[i].obj, "rs_events");
        if (map) {
            ctx.rs_events_fd = bpf_map__fd(map);
        }
        break;
    }
}

// 之后: 从 pinned 路径获取 rs_event_bus
ctx.rs_event_bus_fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
if (ctx.rs_event_bus_fd >= 0) {
    printf("Got unified event bus: fd=%d\n", ctx.rs_event_bus_fd);
}

// 从 l2learn 获取 rs_mac_table (优先使用 pinned 路径)
for (int i = 0; i < ctx.num_modules; i++) {
    if (strcmp(ctx.modules[i].name, "l2learn") == 0) {
        ctx.rs_mac_table_fd = bpf_obj_get("/sys/fs/bpf/rs_mac_table");
        if (ctx.rs_mac_table_fd < 0) {
            // Fallback to module object
            struct bpf_map *map = bpf_object__find_map_by_name(
                ctx.modules[i].obj, "rs_mac_table");
            if (map) {
                ctx.rs_mac_table_fd = bpf_map__fd(map);
            }
        }
        break;
    }
}
```

**Cleanup 更新**:
```c
// 之前
if (ctx->rs_events_fd >= 0) {
    close(ctx->rs_events_fd);
}

// 之后
if (ctx->rs_event_bus_fd >= 0) {
    close(ctx->rs_event_bus_fd);
}
if (ctx->rs_mac_table_fd >= 0) {
    close(ctx->rs_mac_table_fd);
}
```

**Pinned Maps 列表**:
```c
const char *pinned_maps[] = {
    "/sys/fs/bpf/rs_ctx_map",
    "/sys/fs/bpf/rs_progs",
    "/sys/fs/bpf/rs_port_config_map",
    "/sys/fs/bpf/rs_vlan_map",
    "/sys/fs/bpf/rs_stats_map",
    "/sys/fs/bpf/rs_event_bus",      // 新增！
    "/sys/fs/bpf/rs_mac_table",      // 新增！
    NULL
};
```

### 2. `user/events/event_consumer.c`

#### 变更内容

**事件类型映射**:
```c
/* Event type range bases (must match uapi.h) */
#define RS_EVENT_L2_BASE        0x0100
#define RS_EVENT_ACL_BASE       0x0200
#define RS_EVENT_ROUTE_BASE     0x0300
#define RS_EVENT_MIRROR_BASE    0x0400
#define RS_EVENT_QOS_BASE       0x0500
#define RS_EVENT_ERROR_BASE     0xFF00
```

**统一 Ringbuf 回调**:
```c
// 之前: 多个专用回调
static int mac_learn_ringbuf_callback(...);
static int policy_ringbuf_callback(...);

// 之后: 单一统一回调
static int unified_ringbuf_callback(void *ctx, void *data, size_t size)
{
    struct event_consumer *consumer = ctx;
    uint32_t *event_type_ptr = (uint32_t *)data;
    enum event_type mapped_type;
    
    // 根据事件类型范围映射
    uint32_t event_type = *event_type_ptr;
    switch (event_type & 0xFF00) {
    case RS_EVENT_L2_BASE:
        if (event_type == (RS_EVENT_L2_BASE + 1))
            mapped_type = EVENT_MAC_LEARNED;
        else if (event_type == (RS_EVENT_L2_BASE + 3))
            mapped_type = EVENT_MAC_AGED;
        break;
    case RS_EVENT_ACL_BASE:
        mapped_type = EVENT_POLICY_HIT;
        break;
    // ...
    }
    
    // 分发给所有注册的处理器
    for (int i = 0; i < consumer->num_handlers; i++) {
        consumer->handlers[i].handler(...);
    }
}
```

**消费者线程**:
```c
// 之前: 轮询多个 ringbuf
static void *consumer_thread(void *arg)
{
    struct ring_buffer *mac_rb = ...;
    struct ring_buffer *policy_rb = ...;
    
    while (consumer->running) {
        if (mac_rb)
            ring_buffer__poll(mac_rb, 100);
        if (policy_rb)
            ring_buffer__poll(policy_rb, 100);
    }
}

// 之后: 单一 ringbuf 轮询
static void *consumer_thread(void *arg)
{
    struct ring_buffer *event_rb = NULL;
    
    if (consumer->event_bus_fd >= 0) {
        event_rb = ring_buffer__new(consumer->event_bus_fd,
                                     unified_ringbuf_callback,
                                     consumer, NULL);
    }
    
    while (consumer->running) {
        ring_buffer__poll(event_rb, 100);
    }
}
```

**初始化**:
```c
// 之前: 打开多个 ringbuf
int event_consumer_init(struct event_consumer *consumer)
{
    consumer->mac_learn_ringbuf_fd = bpf_obj_get(
        "/sys/fs/bpf/rswitch/mac_learn_ringbuf");
    consumer->policy_ringbuf_fd = bpf_obj_get(
        "/sys/fs/bpf/rswitch/policy_ringbuf");
    // 警告但不失败
}

// 之后: 打开单一 event bus
int event_consumer_init(struct event_consumer *consumer)
{
    consumer->event_bus_fd = bpf_obj_get("/sys/fs/bpf/rs_event_bus");
    if (consumer->event_bus_fd < 0) {
        fprintf(stderr, "Error: Failed to open rs_event_bus\n");
        return -errno;  // 失败！
    }
    printf("Event consumer initialized (event_bus_fd=%d)\n", 
           consumer->event_bus_fd);
}
```

**销毁**:
```c
// 之前
void event_consumer_destroy(struct event_consumer *consumer)
{
    if (consumer->mac_learn_ringbuf_fd >= 0)
        close(consumer->mac_learn_ringbuf_fd);
    if (consumer->policy_ringbuf_fd >= 0)
        close(consumer->policy_ringbuf_fd);
    if (consumer->error_ringbuf_fd >= 0)
        close(consumer->error_ringbuf_fd);
}

// 之后
void event_consumer_destroy(struct event_consumer *consumer)
{
    if (consumer->event_bus_fd >= 0)
        close(consumer->event_bus_fd);
}
```

### 3. `user/events/event_consumer.h`

#### 变更内容

**结构体更新**:
```c
// 之前
struct event_consumer {
    int mac_learn_ringbuf_fd;
    int policy_ringbuf_fd;
    int error_ringbuf_fd;
    // ...
};

// 之后
struct event_consumer {
    /* Unified event bus file descriptor */
    int event_bus_fd;
    // ...
};
```

### 4. `user/ctl/rswitchctl_extended.c`

#### 验证状态

✅ 已正确使用 `/sys/fs/bpf/rs_mac_table` 路径（无需修改）

```c
snprintf(path, sizeof(path), "%s/rs_mac_table", BPF_PIN_PATH);
mac_table_fd = bpf_obj_get(path);
```

## 架构改进

### 事件处理流程

**之前**:
```
[l2learn.bpf.c]
    └── rs_events (256KB, unpinned)
            └── event_consumer 线程 1

[acl.bpf.c]
    └── policy_ringbuf (256KB, unpinned)
            └── event_consumer 线程 2

[其他模块]
    └── module_ringbuf (256KB, unpinned)
            └── event_consumer 线程 N
```

**之后**:
```
[uapi.h - Core Infrastructure]
    └── rs_event_bus (1MB, pinned)
            ├── [l2learn.bpf.c] → RS_EMIT_EVENT(MAC_LEARNED)
            ├── [acl.bpf.c] → RS_EMIT_EVENT(ACL_HIT)
            ├── [route.bpf.c] → RS_EMIT_EVENT(ROUTE_ERROR)
            └── [所有模块] → 统一事件总线
                    └── event_consumer 单一线程
                            └── unified_ringbuf_callback
                                    └── 根据事件类型分发
```

### 内存优化

| 场景 | 之前 | 之后 | 节省 |
|------|------|------|------|
| 单模块 (l2learn) | 256KB | 1MB (共享) | -768KB |
| 4个模块 | 1MB (4×256KB) | 1MB (共享) | **0KB** |
| 8个模块 | 2MB (8×256KB) | 1MB (共享) | **1MB (50%)** |

### 用户态简化

**线程数量**:
- 之前: N 个模块 → N 个消费者线程
- 之后: 1 个消费者线程（无论多少模块）

**代码复杂度**:
- 之前: 每个模块需要独立的回调和轮询逻辑
- 之后: 统一回调，基于事件类型自动分发

## 使用示例

### Loader 使用

```bash
# 加载 rSwitch
sudo ./build/loader/rswitch_loader

# 输出应包含：
# Got unified event bus: fd=X
# Got rs_mac_table from pinned path: fd=Y
```

### Event Consumer 使用

```bash
# 启动事件消费者
sudo ./build/events/event_consumer -m -p

# 输出：
# Event consumer initialized (event_bus_fd=5)
# Event consumer thread started (polling rs_event_bus)
# [2025-11-05 10:30:15] MAC LEARNED: aa:bb:cc:dd:ee:ff VLAN=100 Port=2
# [POLICY] Rule=42 Action=DENY Port=3 SRC=...
```

### rswitchctl 使用

```bash
# 查看 MAC 表
sudo ./build/ctl/rswitchctl mac show

# 添加静态 MAC 条目
sudo ./build/ctl/rswitchctl mac add aa:bb:cc:dd:ee:ff 100 2

# 访问路径: /sys/fs/bpf/rs_mac_table (pinned by l2learn)
```

## 验证检查清单

### 编译验证

```bash
cd /home/kylecui/dev/rSwitch/rswitch
make clean
make

# 应该编译成功，无错误
```

### 运行时验证

```bash
# 1. 加载 rSwitch
sudo ./build/loader/rswitch_loader

# 2. 检查 pinned maps
sudo ls -l /sys/fs/bpf/ | grep rs_
# 应该看到:
#   rs_event_bus
#   rs_mac_table
#   rs_ctx_map
#   rs_progs
#   rs_port_config_map
#   rs_vlan_map
#   rs_stats_map

# 3. 验证 event bus 可访问
sudo bpftool map show name rs_event_bus
# 应该显示: type ringbuf, size 1048576

# 4. 启动事件消费者
sudo ./build/events/event_consumer -m
# 应该成功连接到 rs_event_bus

# 5. 触发事件（例如发送流量触发 MAC 学习）
ping <target>

# 6. 观察事件输出
# [2025-11-05 ...] MAC LEARNED: ...
```

### 错误处理

**问题**: `Failed to open rs_event_bus`

**原因**: rSwitch 未加载或 event bus 未 pinned

**解决**:
```bash
# 确保 loader 已运行
sudo ./build/loader/rswitch_loader

# 检查 pinned path
ls -l /sys/fs/bpf/rs_event_bus
```

**问题**: `MAC learn ringbuf not found`

**原因**: 使用旧版 event_consumer 尝试访问旧的 ringbuf

**解决**: 重新编译 event_consumer（已更新代码）

## 兼容性说明

### 向后兼容

❌ **不兼容**: 旧版 event_consumer 无法与新架构配合使用

✅ **兼容**: rswitchctl 无需修改（rs_mac_table 仍然 pinned）

### 升级步骤

1. 停止旧版 rSwitch 和 event_consumer
2. 重新编译所有组件 (`make clean && make`)
3. 启动新版 loader
4. 启动新版 event_consumer

## 未来扩展

### 添加新事件类型

**步骤**:

1. 在 `bpf/core/uapi.h` 中定义事件类型:
   ```c
   #define RS_EVENT_MY_MODULE_BASE  0x0600
   #define RS_EVENT_MY_EVENT        (RS_EVENT_MY_MODULE_BASE + 1)
   ```

2. 在模块中发送事件:
   ```c
   struct my_event evt = {
       .event_type = RS_EVENT_MY_EVENT,
       .data = ...,
   };
   RS_EMIT_EVENT(&evt, sizeof(evt));
   ```

3. 在 `event_consumer.c` 中添加处理:
   ```c
   case RS_EVENT_MY_MODULE_BASE:
       mapped_type = EVENT_MY_TYPE;
       break;
   ```

4. 无需修改 loader（自动使用 rs_event_bus）

## 总结

✅ **完成项**:
- Loader 适配统一 event bus
- Event Consumer 迁移到单一 ringbuf
- 结构体和 API 更新
- 事件类型映射逻辑

✅ **验证项**:
- 编译通过
- Pinned maps 正确
- 事件流转正常

✅ **优势**:
- 内存节省 50% (8模块场景)
- 简化用户态代码
- 统一事件处理流程
- 易于扩展新模块

**下一步**: 实际部署测试和性能基准测试
