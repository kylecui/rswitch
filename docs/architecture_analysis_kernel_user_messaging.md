# rSwitch Architecture Analysis: Kernel-User Messaging & Map Ownership

## Executive Summary

你提出的问题触及了rSwitch架构的核心设计决策：
1. **Ringbuf架构**: 独立ringbuf vs 共享消息总线
2. **Map所有权**: 哪些map应该在全局定义，哪些应该在模块内定义

**核心结论**：
- **Ringbuf**: 应该采用**共享pinned消息总线**，单一user-space消费者
- **Map所有权**: 除了**必须共享的配置和数据平面状态**，其他map应移至单一使用者

---

## 问题1: Ringbuf架构设计

### 当前问题

刚才我们将`rs_events`移到l2learn作为单一所有者，但这引发了更深层的问题：

**MAC学习的ringbuf消耗确实很高**：
```c
// 每学到一个新MAC地址
struct mac_learn_event {
    __u32 event_type;     // 4 bytes
    __u32 ifindex;        // 4 bytes
    __u16 vlan;           // 2 bytes
    __u8  mac[6];         // 6 bytes
    __u64 timestamp;      // 8 bytes
} __attribute__((packed));  // Total: 24 bytes/event
```

**实际场景**：
- 网络启动时可能有数百个设备
- 每个MAC学习事件 = 24 bytes
- 1000个MAC地址 = 24KB ringbuf消耗
- 加上ringbuf overhead，256KB可能不够

### 架构选择对比

#### 选项A: 独立Ringbuf（当前刚实现的）

```
l2learn.bpf.c → rs_events (256KB) → rswitch-events (consumer)
acl.bpf.c → acl_events (128KB) → rswitch-acl-monitor (consumer)
route.bpf.c → route_events (128KB) → rswitch-route-monitor (consumer)
afxdp.bpf.c → voq_ringbuf (512KB) → rswitch-voqd (consumer)
```

**优点**：
- ✅ 隔离性好：不同类型事件不会互相影响
- ✅ 消费者简单：每个工具只处理一种事件
- ✅ 性能可预测：不同模块不竞争ringbuf空间

**缺点**：
- ❌ 资源浪费：多个ringbuf占用更多内存（256+128+128+512=1MB+）
- ❌ User-space复杂：需要多个消费者进程或多线程
- ❌ 事件关联困难：同一个packet的不同事件分散在不同ringbuf
- ❌ 模块可选性差：如果l2learn不加载，rs_events不存在，消费者崩溃

#### 选项B: 共享Pinned消息总线（推荐）

```
                    ┌─ l2learn.bpf.c (MAC_LEARN, MAC_MOVED)
                    ├─ acl.bpf.c (ACL_DENY, ACL_PERMIT)
                    ├─ vlan.bpf.c (VLAN_VIOLATION)
rs_unified_events ──┼─ route.bpf.c (ROUTE_MISS, NH_DOWN)
 (1MB, pinned)      ├─ mirror.bpf.c (MIRROR_DROP)
                    └─ dispatcher.bpf.c (PARSE_ERROR)
                              ↓
                    rswitch-events (single consumer)
                    ├─ Demux by event_type
                    ├─ Update MAC table DB
                    ├─ Log ACL violations
                    ├─ Trigger route updates
                    └─ Send to telemetry system
```

**优点**：
- ✅ **统一消费点**：单一user-space程序处理所有事件
- ✅ **事件关联**：可以关联同一packet的多个事件（时间戳匹配）
- ✅ **资源高效**：1MB总线 vs 多个小ringbuf
- ✅ **模块可选**：即使某些模块未加载，消息总线始终存在
- ✅ **扩展性好**：添加新事件类型不需要新ringbuf

**缺点**：
- ❌ 需要事件类型枚举和demux逻辑
- ❌ 高频事件可能影响低频事件（需要优先级/rate limit）

### 推荐方案：共享Pinned消息总线

#### 实现设计

**1. 在`uapi.h`定义共享事件总线**

```c
/* Unified Event Bus for Kernel→User Messaging
 * 
 * SHARED PINNED MAP - all modules can emit events
 * Single user-space consumer demux by event type
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB - accommodate high-volume MAC learning
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // MUST pin - shared across modules
} rs_event_bus SEC(".maps");

/* Event types - expandable */
enum rs_event_type {
    // L2 Learning events
    RS_EVENT_MAC_LEARNED    = 1,
    RS_EVENT_MAC_MOVED      = 2,
    RS_EVENT_MAC_AGED       = 3,
    
    // VLAN events
    RS_EVENT_VLAN_VIOLATION = 10,
    
    // ACL events
    RS_EVENT_ACL_DENY       = 20,
    RS_EVENT_ACL_PERMIT_LOG = 21,
    
    // Route events
    RS_EVENT_ROUTE_MISS     = 30,
    RS_EVENT_NH_DOWN        = 31,
    
    // System events
    RS_EVENT_PARSE_ERROR    = 90,
    RS_EVENT_DROP           = 91,
};

/* Generic event header */
struct rs_event_hdr {
    __u32 type;           // enum rs_event_type
    __u32 ifindex;        // Source interface
    __u64 timestamp;      // Event timestamp (for correlation)
    __u16 data_len;       // Event-specific data length
    __u16 reserved;
} __attribute__((packed));

/* Event-specific payloads */
struct rs_event_mac {
    __u8 mac[6];
    __u16 vlan;
    __u32 port;
} __attribute__((packed));

struct rs_event_acl {
    __u32 rule_id;
    __be32 saddr;
    __be32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
} __attribute__((packed));

/* Emit event macro */
#define RS_EMIT_EVENT(ctx, evt_type, payload_ptr, payload_size) ({ \
    struct rs_event_hdr *__hdr; \
    void *__buf = bpf_ringbuf_reserve(&rs_event_bus, \
        sizeof(struct rs_event_hdr) + (payload_size), 0); \
    if (__buf) { \
        __hdr = (struct rs_event_hdr *)__buf; \
        __hdr->type = (evt_type); \
        __hdr->ifindex = (ctx)->ifindex; \
        __hdr->timestamp = bpf_ktime_get_ns(); \
        __hdr->data_len = (payload_size); \
        __builtin_memcpy(__buf + sizeof(struct rs_event_hdr), \
                         (payload_ptr), (payload_size)); \
        bpf_ringbuf_submit(__buf, 0); \
    } \
})
```

**2. 模块使用示例**

```c
// l2learn.bpf.c
struct rs_event_mac mac_evt = {
    .mac = {smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]},
    .vlan = vlan,
    .port = ifindex,
};
RS_EMIT_EVENT(ctx, RS_EVENT_MAC_LEARNED, &mac_evt, sizeof(mac_evt));

// acl.bpf.c
struct rs_event_acl acl_evt = {
    .rule_id = rule->id,
    .saddr = ctx->layers.saddr,
    .daddr = ctx->layers.daddr,
    .sport = ctx->layers.sport,
    .dport = ctx->layers.dport,
    .proto = ctx->layers.ip_proto,
};
RS_EMIT_EVENT(ctx, RS_EVENT_ACL_DENY, &acl_evt, sizeof(acl_evt));
```

**3. User-space消费者**

```c
// rswitch-events.c - single consumer for all events
int consume_events(int ringbuf_fd) {
    while (running) {
        struct rs_event_hdr *hdr = ringbuf_peek();
        void *payload = (void *)hdr + sizeof(*hdr);
        
        switch (hdr->type) {
        case RS_EVENT_MAC_LEARNED:
            handle_mac_learn((struct rs_event_mac *)payload);
            break;
        case RS_EVENT_ACL_DENY:
            handle_acl_deny((struct rs_event_acl *)payload);
            break;
        // ... other event types
        }
        
        ringbuf_consume(hdr);
    }
}
```

### 特殊情况：VOQ Ringbuf

**`voq_ringbuf` 应该保持独立**：

原因：
1. **极高频率**：每个高优先级packet都产生元数据
2. **实时性要求**：VOQd需要microsecond级响应
3. **专用消费者**：VOQd是独立的调度器进程
4. **不同用途**：控制平面消息 vs 数据平面元数据

```c
// afxdp_redirect.bpf.c - keep separate voq_ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);  // 512KB for high-freq metadata
    // NO pinning - single owner
} voq_ringbuf SEC(".maps");
```

---

## 问题2: Map所有权重新审视

### 原则

**哪些map应该在全局（map_defs.h）定义？**

只有满足以下**所有条件**的map：
1. **多个模块访问** - 至少2个模块需要读或写
2. **必须共享状态** - 不能有独立副本
3. **模块组合无关** - 无论加载哪些模块都需要存在

### 当前map分析

| Map | 当前位置 | 使用者 | 是否共享必须 | 建议 |
|-----|---------|--------|-------------|------|
| `rs_ctx_map` | uapi.h | dispatcher + all modules | ✅ 是 | ✅ 保持全局+pin |
| `rs_progs` | uapi.h | dispatcher + all modules | ✅ 是 | ✅ 保持全局+pin |
| `rs_port_config_map` | map_defs.h | vlan, acl, l2learn? | ✅ 是 | ✅ 保持全局+pin |
| `rs_vlan_map` | map_defs.h | vlan, egress_vlan | ✅ 是 | ✅ 保持全局+pin |
| `rs_mac_table` | map_defs.h | **只有l2learn** | ❌ 否 | ⚠️ 移到l2learn？ |
| `rs_stats_map` | map_defs.h | all modules (可选更新) | ⚠️ 灰色 | 🤔 讨论 |
| `rs_xdp_devmap` | lastcall.bpf.c | 只有lastcall | ✅ 是 | ✅ 正确位置 |
| `rs_events` | l2learn.bpf.c | 只有l2learn | ❌ 否 | ❌ 应改为共享总线 |

### 详细分析

#### `rs_mac_table` - 应该移到l2learn？

**当前状态**：
- 定义在`map_defs.h`（全局）
- 只有`l2learn.bpf.c`访问（学习 + 查询）
- `lastcall.bpf.c`**不读取**mac_table（依赖l2learn设置`egress_ifindex`）

**问题**：
- 如果不加载l2learn（dumb模式），这个65K entries的hash map浪费内存
- 违反"模块可选"原则

**建议**：
```c
// 移到 l2learn.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ← 仍需pin，user-space查询
} rs_mac_table SEC(".maps");
```

**为什么pin？**
- User-space工具需要查询MAC表（`rswitchctl show mac-table`）
- Telemetry需要导出MAC学习状态
- 虽然只有l2learn写，但user-space要读

#### `rs_stats_map` - 灰色地带

**当前状态**：
- 定义在`map_defs.h`（全局）
- **所有模块**可以更新统计（但都是可选的）
- User-space telemetry读取

**两种观点**：

**观点A - 保持全局**：
- 统计是基础设施，与模块无关
- 即使dumb模式也想看rx/tx统计
- 多个模块更新不同字段（rx_packets vs rx_drops）

**观点B - 移到专门的stats模块**：
- 创建独立的`stats.bpf.c`模块（可选加载）
- 如果不关心统计，不加载此模块节省开销

**建议**：**保持全局+pinned**
- 统计开销极低（per-CPU array，无锁）
- 基础监控功能，几乎总是需要
- 多模块协作更新

#### `rs_port_config_map` - 必须全局

**理由**：
- VLAN模块需要读VLAN配置
- ACL模块需要读安全设置
- L2Learn需要读learning enable/disable
- QoS模块（未来）需要读优先级设置

✅ **保持在map_defs.h + pinned**

### 重构建议

#### 移动`rs_mac_table`到l2learn

```c
// bpf/modules/l2learn.bpf.c

/* MAC Forwarding Table
 * 
 * OWNED BY L2LEARN but pinned for user-space access
 * - L2learn writes: learns and updates MAC entries
 * - User-space reads: rswitchctl, telemetry tools
 * - Lastcall does NOT read (uses egress_ifindex set by l2learn)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct rs_mac_key);
    __type(value, struct rs_mac_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin for user-space tools
} rs_mac_table SEC(".maps");
```

**影响**：
- 需要从`map_defs.h`删除`rs_mac_table`定义
- 但保留`struct rs_mac_key`和`rs_mac_entry`（user-space需要）
- Loader需要从l2learn对象获取mac_table FD

---

## 最终架构建议

### Kernel-User Messaging

```
┌─────────────────────────────────────────────────────────┐
│  Kernel Space                                           │
├─────────────────────────────────────────────────────────┤
│  rs_event_bus (1MB, pinned)                             │
│  ├─ l2learn.bpf.c → MAC_LEARNED, MAC_MOVED              │
│  ├─ vlan.bpf.c → VLAN_VIOLATION                         │
│  ├─ acl.bpf.c → ACL_DENY                                │
│  ├─ route.bpf.c → ROUTE_MISS                            │
│  └─ dispatcher.bpf.c → PARSE_ERROR                      │
│                                                          │
│  voq_ringbuf (512KB, unpinned)                          │
│  └─ afxdp_redirect.bpf.c → VOQ metadata (high-freq)     │
└─────────────────────────────────────────────────────────┘
                    ↓                          ↓
┌─────────────────────────────────────────────────────────┐
│  User Space                                             │
├─────────────────────────────────────────────────────────┤
│  rswitch-events (control plane)                         │
│  ├─ Consume rs_event_bus                                │
│  ├─ Demux by event_type                                 │
│  ├─ Update MAC table DB                                 │
│  ├─ Log violations                                      │
│  └─ Export to telemetry                                 │
│                                                          │
│  rswitch-voqd (data plane)                              │
│  ├─ Consume voq_ringbuf                                 │
│  ├─ Real-time packet scheduling                         │
│  └─ Microsecond-level response                          │
└─────────────────────────────────────────────────────────┘
```

### Map分类

#### Tier 1: 核心共享Maps（始终全局+pinned）
```
rs_ctx_map          - Per-CPU context passing
rs_progs            - Tail-call program array
rs_port_config_map  - Port configuration
rs_vlan_map         - VLAN membership
rs_stats_map        - Interface statistics
rs_event_bus        - Unified event messaging (NEW)
```

#### Tier 2: 模块专属Maps（模块内定义，按需pin）
```
rs_mac_table        - L2learn owns, pinned for user-space
rs_xdp_devmap       - Lastcall owns, unpinned
voq_ringbuf         - AF_XDP owns, unpinned
acl_rules           - ACL owns, pinned for rswitchctl (未来)
route_table         - Route owns, pinned for FIB sync (未来)
```

---

## 实施步骤

### Phase 1: 统一事件总线
1. 在`uapi.h`添加`rs_event_bus`定义（pinned）
2. 定义统一事件类型枚举
3. 修改l2learn使用新事件总线
4. 创建`rswitch-events`消费者

### Phase 2: 重构map所有权
1. 移动`rs_mac_table`到l2learn.bpf.c（保持pinned）
2. 从`map_defs.h`删除mac_table定义
3. 保留struct定义（user-space需要）
4. 更新loader获取mac_table FD的逻辑

### Phase 3: 清理和文档
1. 更新所有模块使用RS_EMIT_EVENT宏
2. 文档化事件类型和payload结构
3. 创建事件消费示例代码

---

## 性能影响分析

### Ringbuf大小选择

**1MB共享事件总线能承载多少？**

假设最坏情况 - MAC学习风暴：
- 事件大小：24 bytes (header) + 16 bytes (payload) = 40 bytes
- 1MB可容纳：1,048,576 / 40 ≈ 26,214 events
- 如果1秒内学习1000个MAC，ringbuf可承载26秒的burst

**正常场景**：
- MAC学习：间歇性（几百个/分钟）
- ACL违规：低频（几个/秒）
- Route miss：中频（几十个/秒）
- Parse error：罕见

**结论**：1MB足够，除非极端网络风暴。

### 与独立Ringbuf对比

| 指标 | 独立Ringbuf | 共享总线 |
|------|------------|----------|
| 总内存 | 1MB+ (多个小ringbuf) | 1MB (单一大ringbuf) |
| User-space进程 | 多个或多线程 | 单一消费者 |
| 事件关联 | 困难（跨ringbuf） | 容易（时间戳匹配） |
| 扩展性 | 每新类型+1 ringbuf | 只需+1 enum |
| CPU开销 | 多个poll/epoll | 单一poll |

**推荐**：共享总线在资源和复杂度上都更优。

---

## 总结

### 核心决策

1. **Ringbuf架构**: ✅ 采用**共享pinned事件总线** (`rs_event_bus`)
   - 除了VOQ ringbuf（极高频，专用消费者）
   - 单一user-space消费者，事件类型demux
   - 1MB容量应对MAC学习burst

2. **Map所有权**:
   - ✅ **全局+pinned**: rs_ctx_map, rs_progs, rs_port_config_map, rs_vlan_map, rs_stats_map
   - ⚠️ **移到l2learn+pinned**: rs_mac_table（单一写者，user-space读）
   - ✅ **模块内+unpinned**: rs_xdp_devmap, voq_ringbuf

### 为什么这样设计

**共享事件总线的理由**：
- MAC学习确实是高频事件，需要足够ringbuf空间
- 统一消费点简化user-space架构
- 事件关联能力（同一packet的多个事件）
- 模块可选性（即使某些模块未加载，总线仍存在）

**Map移动的理由**：
- `rs_mac_table`只有l2learn写，应该归其所有
- 但user-space需要查询，所以仍需pin
- 遵循"配置全局，数据模块内"的原则

这个架构既保持了灵活性，又避免了资源浪费，符合"实用主义"的设计哲学。
