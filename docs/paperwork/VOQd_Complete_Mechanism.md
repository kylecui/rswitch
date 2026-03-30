# VOQd 完整机制：虚拟输出队列守护进程与 QoS 集成

## 1. 概述

VOQd（Virtual Output Queue Daemon）是 rSwitch 平台中的用户态 QoS 调度守护进程。它通过 AF_XDP 从内核 XDP 快速路径接收数据包，在用户态执行精细的多层调度（DRR + WFQ + Token Bucket），再将数据包发回内核完成转发。VOQd 的核心设计目标是：在不依赖 DPDK 的前提下，为纯 XDP 软件交换机提供硬件级别的 QoS 调度能力。

### 1.1 设计动机

传统 XDP 数据路径是"一包一决策"的无状态模型——每个数据包在 BPF 程序中独立处理，不具备跨包的队列状态和调度能力。这意味着 XDP 天然缺乏：

- **队列管理**：无法维护 per-port、per-priority 的包队列
- **带宽整形**：无法实现令牌桶等速率控制算法
- **公平调度**：无法在多个流之间进行加权公平排队
- **拥塞控制**：无法根据队列深度执行 RED/ECN 策略

VOQd 通过将"需要跨包状态"的 QoS 功能卸载到用户态，同时保留 XDP 的零拷贝高性能路径，实现了"快速路径 + 智能调度"的混合数据平面架构。

### 1.2 在 rSwitch 中的定位

```
┌─────────────────────────────────────────────────────────────────┐
│                     rSwitch 数据平面                              │
│                                                                 │
│  ┌──────────────────────── XDP Pipeline ───────────────────────┐│
│  │ dispatcher → vlan → acl → l2learn → ... → afxdp_redirect   ││
│  │                                              │              ││
│  │                                    ┌─────────┤              ││
│  │                                    │ BYPASS  │ ACTIVE       ││
│  │                                    ▼         ▼              ││
│  │                              继续快速路径   AF_XDP → 用户态  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                  │              │
│  ┌──────────────────────── VOQd (用户态) ─────────┤             │
│  │  ringbuf_consumer ← BPF ringbuf (元数据)       │             │
│  │  AF_XDP RX ← xsks_map (数据包)                │             │
│  │       │                                       │             │
│  │       ▼                                       │             │
│  │  ┌─────────────────────────────────┐          │             │
│  │  │ VOQ Manager (voq_mgr)          │          │             │
│  │  │  ├─ Port[0..63] (voq_port)     │          │             │
│  │  │  │   ├─ WFQ Scheduler          │          │             │
│  │  │  │   ├─ Port-level Shaper      │          │             │
│  │  │  │   └─ Queue[0..3] (voq_queue)│          │             │
│  │  │  │       ├─ DRR Scheduler      │          │             │
│  │  │  │       └─ Queue-level Shaper │          │             │
│  │  │  └─ Memory Pool                │          │             │
│  │  └─────────────────────────────────┘          │             │
│  │       │                                       │             │
│  │       ▼                                       │             │
│  │  AF_XDP TX → 内核转发                          │             │
│  └───────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. 核心数据结构

### 2.1 VOQ 条目 (`voq_entry`)

```c
struct voq_entry {
    void *pkt_data;            // 指向数据包数据
    uint32_t pkt_len;          // 数据包长度
    uint8_t priority;          // 优先级 (0=LOW, 1=NORMAL, 2=HIGH, 3=CRITICAL)
    uint32_t port_idx;         // 目标出端口索引
    uint64_t enqueue_time;     // 入队时间戳 (ns)
    struct voq_entry *next;    // 链表指针
};
```

每个 `voq_entry` 代表一个等待调度的数据包。通过链表组织在对应的优先级队列中。

### 2.2 VOQ 队列 (`voq_queue`)

```c
struct voq_queue {
    struct voq_entry *head;    // 队列头
    struct voq_entry *tail;    // 队列尾
    uint32_t depth;            // 当前队列深度（包数）
    uint32_t max_depth;        // 最大队列深度（默认 8192）
    uint64_t enqueued;         // 累计入队统计
    uint64_t dequeued;         // 累计出队统计
    uint64_t dropped;          // 因队满被丢弃的包数

    // DRR 调度状态
    int32_t deficit;           // 当前亏空值（字节）
    uint32_t quantum;          // 每轮调度的字节配额（默认 1500）
    bool active;               // 是否在活跃轮转列表中

    // Per-queue 令牌桶整形器
    struct rs_shaper shaper;   // 队列级速率限制器
};
```

**DRR（Deficit Round Robin）调度**：每轮调度为队列补充 `quantum` 字节的亏空额度。如果队头包的长度小于等于当前亏空值，则出队并扣减亏空；否则跳过该队列，进入下一轮。这保证了字节级别的公平性。

### 2.3 VOQ 端口 (`voq_port`)

```c
struct voq_port {
    struct voq_queue queues[MAX_PRIORITIES];  // 4 个优先级队列
    uint32_t ifindex;                         // 对应的网络接口索引
    bool active;                              // 端口是否活跃

    // WFQ 调度器
    struct rs_wfq_scheduler wfq;              // 加权公平排队调度器

    // 端口级令牌桶整形器
    struct rs_shaper port_shaper;             // 端口级速率限制器

    // 端口统计
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_drops;
};
```

每个出端口拥有 4 个优先级队列（LOW=0, NORMAL=1, HIGH=2, CRITICAL=3），通过 WFQ 或严格优先级方式选择下一个被服务的队列。

### 2.4 VOQ 管理器 (`voq_mgr`)

```c
struct voq_mgr {
    struct voq_port ports[MAX_PORTS];         // 最多 64 个端口
    uint32_t num_ports;                       // 活跃端口数

    // 内存池
    struct voq_entry *pool_head;              // 空闲条目链表头
    uint32_t pool_size;                       // 池中可用条目数
    uint32_t pool_allocated;                  // 已分配总数

    // 调度线程
    pthread_t scheduler_thread;               // 调度线程句柄
    bool scheduler_running;                   // 调度线程运行标志

    // 全局统计
    uint64_t total_enqueued;
    uint64_t total_dequeued;
    uint64_t total_dropped;

    // 锁
    pthread_mutex_t lock;                     // 全局互斥锁
};
```

### 2.5 常量定义

| 常量 | 值 | 含义 |
|------|-----|------|
| `MAX_PORTS` | 64 | 最大端口数 |
| `MAX_PRIORITIES` | 4 | 优先级数（LOW/NORMAL/HIGH/CRITICAL）|
| `MAX_QUEUE_DEPTH` | 8192 | 每队列最大深度 |
| `DEFAULT_QUANTUM` | 1500 | DRR 默认配额（字节，= 1 个标准 MTU）|
| `POOL_CHUNK_SIZE` | 1024 | 内存池每次分配的条目数 |

---

## 3. 三层调度架构

VOQd 的调度是一个三层嵌套结构，从外到内依次为：

```
第1层: 端口轮转（Round-Robin over Ports）
  └─ 第2层: 队列选择（WFQ / Strict Priority over Queues）
       └─ 第3层: 包出队（DRR Deficit Check + Dual Token Bucket Admission）
```

### 3.1 第一层：端口轮转

调度器在所有活跃端口之间进行 Round-Robin 轮转。每一轮：

1. 遍历 `ports[0]` 到 `ports[num_ports-1]`
2. 跳过非活跃端口（`!port->active`）和空端口（所有队列 depth=0）
3. 对每个有包的端口，执行第二层调度

```c
// voq.c 中的核心调度循环
for (uint32_t i = 0; i < mgr->num_ports; i++) {
    struct voq_port *port = &mgr->ports[i];
    if (!port->active) continue;

    // 选择该端口的下一个队列
    struct voq_queue *queue = select_queue(port);
    if (!queue || queue->depth == 0) continue;

    // 尝试出队
    attempt_dequeue(port, queue);
}
```

### 3.2 第二层：队列选择（WFQ）

**WFQ（Weighted Fair Queuing）** 通过虚拟时间（virtual time）实现加权公平：

```c
struct rs_wfq_scheduler {
    uint64_t virtual_time[MAX_PRIORITIES];  // 每个队列的虚拟时间
    uint32_t weights[MAX_PRIORITIES];       // 每个队列的权重
};
```

**选择算法**：
1. 遍历所有非空队列
2. 选择 `virtual_time` 最小的队列（即"最落后"的队列）
3. 出队后，更新该队列的虚拟时间：`virtual_time[q] += 1000000 / weight[q]`

权重越大的队列，虚拟时间增长越慢，因此被选中的频率越高。这实现了按权重的带宽分配。

```c
// shaper.c - WFQ 队列选择
int rs_wfq_select_queue(struct rs_wfq_scheduler *wfq, ...) {
    int selected = -1;
    uint64_t min_vtime = UINT64_MAX;

    for (int i = 0; i < num_queues; i++) {
        if (queue_empty[i]) continue;
        if (wfq->virtual_time[i] < min_vtime) {
            min_vtime = wfq->virtual_time[i];
            selected = i;
        }
    }

    if (selected >= 0) {
        // 更新虚拟时间
        wfq->virtual_time[selected] += 1000000 / wfq->weights[selected];
    }
    return selected;
}
```

### 3.3 第三层：包出队（DRR + 双重令牌桶）

选定队列后，执行两步准入检查：

**步骤 1：DRR 亏空检查**
```c
// 补充亏空
queue->deficit += queue->quantum;

// 检查队头包是否可出队
struct voq_entry *entry = queue->head;
if (entry->pkt_len <= queue->deficit) {
    // 亏空足够，继续到令牌桶检查
    queue->deficit -= entry->pkt_len;
} else {
    // 亏空不足，跳过本轮
    return NULL;
}
```

**步骤 2：双重令牌桶准入**
```c
// 令牌桶结构
struct rs_shaper {
    uint64_t tokens;          // 当前令牌数（字节）
    uint64_t max_tokens;      // 桶容量（突发容量）
    uint64_t rate;            // 令牌生成速率（字节/秒）
    uint64_t last_update;     // 上次更新时间戳
};

// 准入检查：端口级 AND 队列级都必须通过
bool port_admit = rs_shaper_admit(&port->port_shaper, entry->pkt_len);
bool queue_admit = rs_shaper_admit(&queue->shaper, entry->pkt_len);

if (port_admit && queue_admit) {
    // 出队
    dequeue_entry(queue, entry);
} else {
    // 速率超限，等待下一轮
    return NULL;
}
```

**令牌桶更新逻辑**：
```c
int rs_shaper_admit(struct rs_shaper *shaper, uint32_t pkt_len) {
    uint64_t now = get_time_ns();
    uint64_t elapsed = now - shaper->last_update;

    // 补充令牌
    uint64_t new_tokens = elapsed * shaper->rate / 1000000000ULL;
    shaper->tokens = MIN(shaper->tokens + new_tokens, shaper->max_tokens);
    shaper->last_update = now;

    // 准入判断
    if (shaper->tokens >= pkt_len) {
        shaper->tokens -= pkt_len;
        return 1;  // 允许
    }
    return 0;  // 拒绝
}
```

### 3.4 调度总结

| 层级 | 机制 | 目的 |
|------|------|------|
| 第1层：端口轮转 | Round-Robin | 端口间公平性 |
| 第2层：队列选择 | WFQ（虚拟时间） | 优先级间加权公平 |
| 第3层：包出队 | DRR + 双重令牌桶 | 字节级公平 + 速率限制 |

---

## 4. 三种运行模式与状态机

VOQd 支持三种运行模式，通过 BPF map 实现内核态与用户态的状态同步。

### 4.1 模式定义

```c
// afxdp_common.h
#define VOQD_MODE_BYPASS  0   // 旁路模式：VOQd 不参与
#define VOQD_MODE_SHADOW  1   // 影子模式：VOQd 观测但不干预
#define VOQD_MODE_ACTIVE  2   // 主动模式：VOQd 全权调度
```

### 4.2 BYPASS 模式

```
数据包 → XDP Pipeline → 直接转发（跳过 VOQd）
```

- `afxdp_redirect` 模块检查 `voqd_state_map`，发现 mode=BYPASS
- 直接 `return XDP_PASS`，不做任何重定向
- VOQd 完全不参与数据平面
- **适用场景**：不需要 QoS 的简单转发场景；VOQd 故障时的降级模式

### 4.3 SHADOW 模式

```
数据包 → XDP Pipeline → afxdp_redirect:
   ├─ 将包的元数据写入 BPF ringbuf（供 VOQd 观测）
   └─ 数据包继续走 XDP 快速路径转发
```

- VOQd 通过 `ringbuf_consumer` 接收包的元数据（5-tuple、优先级、长度等）
- VOQd 执行调度算法，但**不实际处理数据包**
- 用于验证调度算法的正确性，或收集 QoS 统计数据
- **适用场景**：上线前验证 QoS 策略；性能基线测量；监控和遥测

### 4.4 ACTIVE 模式

```
数据包 → XDP Pipeline → afxdp_redirect:
   ├─ 将包的元数据写入 BPF ringbuf
   └─ 通过 bpf_redirect_map(xsks_map) 将数据包重定向到 AF_XDP socket
                                          │
VOQd 用户态:                              │
   ├─ AF_XDP RX 接收数据包 ◄──────────────┘
   ├─ 解析 DSCP → 优先级映射
   ├─ 入队到对应 port/priority 的 VOQ
   ├─ 三层调度器出队
   └─ AF_XDP TX 发回内核转发
```

- VOQd 完全控制数据包的调度和转发顺序
- 通过 AF_XDP 零拷贝实现高性能内核-用户态数据传输
- **适用场景**：需要精细 QoS 控制的生产环境

### 4.5 状态机与 BPF Map 同步

VOQd 通过两个共享 BPF map 与内核态模块通信：

**`voqd_state_map`**（BPF_MAP_TYPE_ARRAY, max_entries=1）：
```c
struct voqd_state {
    __u32 mode;             // 当前模式 (BYPASS/SHADOW/ACTIVE)
    __u32 prio_mask;        // 活跃优先级位掩码
    __u32 running;          // VOQd 是否运行中
    __u64 heartbeat;        // 最后心跳时间戳 (ns)
    __u32 failover_count;   // 累计故障转移次数
    __u32 overload_drops;   // 过载丢包计数
    __u32 flags;            // 控制标志
};
```

**`qos_config_map`**（BPF_MAP_TYPE_ARRAY, max_entries=1）：
```c
struct qos_config {
    __u8  dscp2prio[64];    // DSCP → 优先级映射表
    __u32 ecn_threshold;    // ECN 标记阈值
    __u32 drop_threshold;   // 主动丢包阈值
};
```

**状态控制器** (`state_ctrl.c`)：
- 使用 `bpf_map_lookup_elem` / `bpf_map_update_elem` 读写 BPF map
- 启动时写入初始模式和优先级掩码
- 运行时通过心跳线程定期更新 `heartbeat` 时间戳
- 检测自动降级：对比本地模式与 BPF map 中的模式，发现不一致时记录降级事件

---

## 5. 心跳与故障转移机制

### 5.1 心跳机制

VOQd 运行一个独立的心跳线程，每 **1 秒** 更新 `voqd_state_map` 中的 `heartbeat` 字段：

```c
// state_ctrl.c - 心跳线程
void *heartbeat_thread(void *arg) {
    while (running) {
        // 更新心跳时间戳
        state.heartbeat = bpf_ktime_get_ns();
        bpf_map_update_elem(state_map_fd, &key, &state, BPF_ANY);

        // 检查 BPF 侧是否发生了自动降级
        struct voqd_state bpf_state;
        bpf_map_lookup_elem(state_map_fd, &key, &bpf_state);
        if (bpf_state.mode != local_mode) {
            log("Auto-degradation detected: BPF mode=%d, local=%d",
                bpf_state.mode, local_mode);
        }

        sleep(1);
    }
}
```

### 5.2 BPF 侧故障检测

`afxdp_redirect.bpf.c` 在每个数据包处理时检查心跳：

```c
// afxdp_redirect.bpf.c
__u64 now = bpf_ktime_get_ns();
__u64 elapsed = now - state->heartbeat;

if (elapsed > HEARTBEAT_TIMEOUT_NS) {  // 5 秒超时
    // VOQd 无响应，自动降级到 BYPASS
    state->mode = VOQD_MODE_BYPASS;
    state->failover_count++;
    return XDP_PASS;  // 走快速路径
}
```

### 5.3 过载降级

当 BPF ringbuf 持续满载（连续 1000+ 次丢弃），触发过载降级：

```c
// afxdp_redirect.bpf.c
int ret = bpf_ringbuf_output(&voq_events, &meta, sizeof(meta), 0);
if (ret < 0) {
    state->overload_drops++;
    if (state->overload_drops > OVERLOAD_THRESHOLD) {  // 1000
        // 过载降级到 BYPASS
        state->mode = VOQD_MODE_BYPASS;
        state->failover_count++;
    }
}
```

### 5.4 优雅降级链

```
ACTIVE ──心跳超时/过载──→ SHADOW ──继续异常──→ BYPASS
  │                          │                    │
  └─ VOQd 全权调度            └─ 观测但不干预       └─ 纯 XDP 快速路径
```

降级是自动的、无需人工干预的。恢复需要手动将模式设回 ACTIVE（通过 `rsvoqctl` 命令行工具或 YAML 配置）。

---

## 6. AF_XDP 数据平面集成

### 6.1 数据包接收路径

```c
// voqd_dataplane.h - 接收线程
void *rx_thread(void *arg) {
    while (running) {
        // 从 AF_XDP socket 接收数据包
        int n = xsk_ring_cons__peek(&rx_ring, BATCH_SIZE, &idx);
        for (int i = 0; i < n; i++) {
            void *pkt = xsk_umem__get_data(umem, addr);
            uint32_t len = desc->len;

            // 解析 DSCP 获取优先级
            uint8_t prio = extract_dscp_priority(pkt, len);

            // 确定目标端口
            uint32_t port_idx = determine_egress_port(pkt, len);

            // 入队到 VOQ
            voq_enqueue(mgr, port_idx, prio, pkt, len);
        }
    }
}
```

### 6.2 DSCP → 优先级映射

VOQd 在两个层面执行优先级分类：

**BPF 侧**（`egress_qos.bpf.c`，Stage 170）：
- 5-tuple 分类 → 优先级
- 基于 `qos_config_map` 中的 `dscp2prio[64]` 映射表

**用户态侧**（`voqd.c` 默认映射）：
```c
// 默认 DSCP → 优先级映射
if (dscp >= 48) prio = QOS_PRIO_CRITICAL;  // EF/CS6/CS7
else if (dscp >= 32) prio = QOS_PRIO_HIGH; // AF4x/CS4/CS5
else if (dscp >= 16) prio = QOS_PRIO_NORMAL; // AF2x/CS2/CS3
else prio = QOS_PRIO_LOW;                    // BE/CS0/CS1
```

优先级值：
- `QOS_PRIO_LOW = 0`
- `QOS_PRIO_NORMAL = 1`
- `QOS_PRIO_HIGH = 2`
- `QOS_PRIO_CRITICAL = 3`

### 6.3 软件队列模拟

对于不支持多硬件队列的 NIC，VOQd 提供软件队列模拟：

```c
// voqd_dataplane.h
struct sw_queue {
    struct sw_queue_entry entries[SW_QUEUE_MAX];
    uint32_t head, tail;
    uint32_t depth;
    pthread_mutex_t lock;
};

struct sw_queue_mgr {
    struct sw_queue queues[MAX_SW_QUEUES];
    uint32_t num_queues;
};
```

---

## 7. 共享内存整形器配置

### 7.1 运行时重配置机制

VOQd 通过 POSIX 共享内存实现运行时整形器参数热更新：

```c
// shaper.c
#define SHAPER_SHM_NAME "/rswitch_voqd_shaper"

struct rs_shaper_shared_config {
    uint32_t generation;              // 配置代数（用于变更检测）
    struct {
        uint64_t rate;                // 速率（字节/秒）
        uint64_t burst;               // 突发容量（字节）
    } port_shapers[MAX_PORTS];
    struct {
        uint64_t rate;
        uint64_t burst;
    } queue_shapers[MAX_PORTS][MAX_PRIORITIES];
};
```

### 7.2 配置更新流程

```
rsvoqctl set-rate --port eth0 --prio HIGH --rate 100Mbps --burst 64KB
    │
    ▼
修改共享内存 /rswitch_voqd_shaper
    │
    ▼ (VOQd 轮询 generation 计数器)
    │
VOQd 检测到 generation 变化
    │
    ▼
更新对应 port/queue 的 rs_shaper 参数
（无需重启 VOQd）
```

---

## 8. QoS 全链路集成

### 8.1 BPF 侧 QoS（内核态）

**Stage 170: `egress_qos.bpf.c`**

1. **流量分类**：5-tuple hash → 查找 `qos_flow_map` → 获取优先级
2. **DSCP → 优先级映射**：通过 `qos_config_map.dscp2prio[dscp]`
3. **Per-priority 令牌桶**：每个优先级独立的速率限制
4. **ECN 标记**：当队列深度超过 `ecn_threshold` 时，设置 IP ECN 字段为 CE (Congestion Experienced)
   - 使用 RFC 1624 增量校验和更新
5. **DSCP 重标记**：根据 QoS 策略修改出站 DSCP 值
6. **拥塞检测**：通过 `qos_qdepth_map` 跟踪队列深度

```c
// egress_qos.bpf.c 核心逻辑
SEC("xdp")
int egress_qos_func(struct xdp_md *ctx) {
    struct rs_ctx *rs_ctx = RS_GET_CTX();

    // 1. 分类
    struct qos_flow_key key = make_5tuple_key(rs_ctx);
    struct qos_flow_info *flow = bpf_map_lookup_elem(&qos_flow_map, &key);
    uint8_t prio = flow ? flow->priority : dscp2prio[dscp];

    // 2. 令牌桶限速
    struct qos_token_bucket *tb = get_token_bucket(prio);
    if (!token_bucket_admit(tb, pkt_len)) {
        return XDP_DROP;  // 超速丢弃
    }

    // 3. ECN 标记
    uint32_t qdepth = get_queue_depth(prio);
    if (qdepth > config->ecn_threshold) {
        mark_ecn_ce(ctx, rs_ctx);  // RFC 1624 增量校验和
    }

    // 4. DSCP 重标记
    remark_dscp(ctx, rs_ctx, new_dscp);

    RS_TAIL_CALL_NEXT(ctx, rs_ctx);
}
```

**Stage 85: `afxdp_redirect.bpf.c`**

根据 VOQd 模式决定数据包走向（详见第 4 节）。

### 8.2 用户态 QoS（VOQd）

VOQd 接管后执行的 QoS 功能：

1. **精细调度**：三层调度器（DRR + WFQ + Token Bucket）
2. **带宽保证**：通过 WFQ 权重保证各优先级的最小带宽
3. **突发控制**：双重令牌桶限制端口和队列的突发流量
4. **队列管理**：MAX_QUEUE_DEPTH=8192，超限时尾丢弃

### 8.3 QoS 分层对比

| 维度 | BPF 侧 (内核态) | VOQd (用户态) |
|------|-----------------|---------------|
| **处理位置** | XDP Pipeline Stage 85/170 | AF_XDP 用户态进程 |
| **调度能力** | Per-packet 无状态限速 | 多层有状态调度 |
| **速率限制** | Per-priority 令牌桶 | Per-port + Per-queue 双重令牌桶 |
| **公平调度** | 无 | WFQ + DRR |
| **队列管理** | 无队列（无状态） | Per-port/per-priority 队列 |
| **ECN/拥塞** | ECN 标记 + 主动丢包 | 队列深度监控 |
| **延迟** | 纳秒级 | 微秒级（经过用户态） |
| **适用流量** | 所有流量（快速路径） | QoS 敏感流量 |

---

## 9. 内存池管理

VOQd 使用预分配内存池避免运行时 malloc 开销：

```c
// voq.c - 内存池
#define POOL_CHUNK_SIZE 1024

static int pool_expand(struct voq_mgr *mgr) {
    // 一次分配 1024 个 voq_entry
    struct voq_entry *chunk = calloc(POOL_CHUNK_SIZE, sizeof(struct voq_entry));
    if (!chunk) return -1;

    // 链接到空闲链表
    for (int i = 0; i < POOL_CHUNK_SIZE; i++) {
        chunk[i].next = mgr->pool_head;
        mgr->pool_head = &chunk[i];
    }

    mgr->pool_size += POOL_CHUNK_SIZE;
    mgr->pool_allocated += POOL_CHUNK_SIZE;
    return 0;
}

// 从池中获取条目（O(1)）
static struct voq_entry *pool_get(struct voq_mgr *mgr) {
    if (!mgr->pool_head) {
        pool_expand(mgr);  // 自动扩展
    }
    struct voq_entry *entry = mgr->pool_head;
    mgr->pool_head = entry->next;
    mgr->pool_size--;
    return entry;
}

// 归还条目到池中（O(1)）
static void pool_put(struct voq_mgr *mgr, struct voq_entry *entry) {
    entry->next = mgr->pool_head;
    mgr->pool_head = entry;
    mgr->pool_size++;
}
```

---

## 10. 启动与配置

### 10.1 命令行选项

```bash
voqd [选项]
  -m <mode>          初始模式: bypass|shadow|active (默认: bypass)
  -P <prio-mask>     优先级位掩码，如 0xf 表示启用全部 4 个优先级
  -i <interfaces>    监听的网络接口列表
  -z                 启用 AF_XDP 零拷贝模式
  -q <num>           软件队列数量
  -Q <depth>         每队列最大深度 (默认: 8192)
```

### 10.2 YAML Profile 配置

```yaml
# etc/profiles/qos-voqd.yaml
name: "QoS VOQd Full"
version: "1.0"
description: "Full QoS pipeline with VOQd active mode"

ingress:
  - vlan
  - qos_classify
  - acl
  - conntrack
  - l2learn

egress:
  - egress_qos
  - afxdp_redirect
  - egress_vlan
  - egress_final
```

### 10.3 VOQd 守护进程上下文

```c
// voqd.c
struct voqd_ctx {
    struct voq_mgr *voq_mgr;                // VOQ 管理器
    struct rb_consumer *rb_consumer;          // Ringbuf 消费者
    struct state_ctrl *state_ctrl;            // 状态控制器
    struct voqd_dataplane *dataplane;         // AF_XDP 数据平面

    // 配置
    int mode;                                 // 初始运行模式
    uint32_t prio_mask;                       // 优先级掩码
    char **interfaces;                        // 接口列表
    int num_interfaces;
    bool zero_copy;                           // 零拷贝标志
    int num_sw_queues;                        // 软件队列数
    int queue_depth;                          // 队列深度
};
```

---

## 11. 设计总结

### 11.1 关键设计决策

1. **混合数据平面**：XDP 快速路径处理大部分流量，仅将需要精细调度的流量卸载到用户态 VOQd。这在保持高吞吐的同时实现了复杂的 QoS 策略。

2. **三模式状态机**：BYPASS/SHADOW/ACTIVE 的渐进式部署模型，允许在不影响生产流量的情况下验证 QoS 策略。

3. **自动故障转移**：BPF 侧心跳检测 + 过载检测实现了无人值守的优雅降级，保证了数据面的高可用性。

4. **三层调度**：Port Round-Robin → WFQ → DRR + Dual Token Bucket 的嵌套调度，在公平性、优先级保证和速率控制之间取得了平衡。

5. **共享内存配置**：通过 POSIX shm 实现运行时整形器参数热更新，无需重启进程。

6. **预分配内存池**：chunk 式分配 + 空闲链表复用，消除了数据平面上的动态内存分配开销。

### 11.2 性能特征

| 指标 | 值 |
|------|-----|
| XDP 快速路径延迟 | ~100-500 ns/包 |
| VOQd 用户态调度延迟 | ~1-10 μs/包 |
| AF_XDP 零拷贝吞吐 | ~10+ Mpps |
| 心跳间隔 | 1 秒 |
| 故障转移时间 | ≤ 5 秒 |
| 过载阈值 | 1000 次连续 ringbuf 丢弃 |
| 最大端口数 | 64 |
| 最大队列深度 | 8192 包/队列 |
| 内存池块大小 | 1024 条目/chunk |
