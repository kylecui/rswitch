> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch 剩余模块开发路线图

> **当前版本**: v1.1-dev  
> **更新日期**: 2024-11-04  
> **状态**: 规划中

---

## 📊 模块开发优先级矩阵

| 版本 | 模块 | 功能 | 优先级 | 难度 | 工作量 | 依赖 |
|------|------|------|--------|------|--------|------|
| **v1.1** | route.bpf.c | IPv4 LPM 路由 | P0 - 高 | 中 | 2-3 周 | - |
| **v1.2** | qos.bpf.c | 流量分类和标记 | P1 - 中 | 中 | 1-2 周 | VLAN PCP |
| **v1.2** | Stateful ACL | 连接跟踪 | P1 - 中 | 高 | 2-3 周 | ACL 模块 |
| **v1.2** | QinQ 支持 | 802.1ad 双标签 | P2 - 低 | 中 | 1-2 周 | VLAN 模块 |
| **v2.0** | stp.bpf.c | 生成树协议 | P3 - 低 | 高 | 3-4 周 | L2 基础 |
| **v2.0** | lacp.bpf.c | 链路聚合 | P3 - 低 | 高 | 3-4 周 | L2 基础 |
| **v2.0** | lldp.bpf.c | 拓扑发现 | P3 - 低 | 低 | 1 周 | - |

---

## 🎯 v1.1 - Route 模块（IPv4 LPM 路由）

### 功能目标

实现基础的 IPv4 路由功能，支持 L3 交换和静态路由。

### 核心功能

1. **IPv4 LPM 查找**:
   - 使用 `BPF_MAP_TYPE_LPM_TRIE` 存储路由表
   - 最长前缀匹配 (Longest Prefix Match)
   - 支持默认路由 (0.0.0.0/0)

2. **路由表管理**:
   - 静态路由配置
   - 路由优先级 (Metric)
   - 下一跳 (Next Hop) 管理

3. **ARP 处理** (简化版):
   - ARP 表 (IP → MAC 映射)
   - ARP 请求/响应处理
   - ARP 老化机制

4. **TTL 处理**:
   - TTL 递减
   - TTL=0 丢弃
   - ICMP Time Exceeded (可选)

### 技术实现

#### BPF Maps

```c
// 路由表 (LPM Trie)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(struct route_entry));
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} route_table SEC(".maps");

struct lpm_key {
    __u32 prefixlen;  // 前缀长度 (0-32)
    __be32 addr;      // IP 地址（网络字节序）
};

struct route_entry {
    __be32 nexthop;   // 下一跳 IP
    __u32 ifindex;    // 出接口
    __u32 metric;     // 路由优先级
    __u8 type;        // 路由类型 (DIRECT/STATIC/DYNAMIC)
};

// ARP 表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);            // IP 地址
    __type(value, struct arp_entry);
    __uint(max_entries, 1024);
} arp_table SEC(".maps");

struct arp_entry {
    __u8 mac[6];      // MAC 地址
    __u32 ifindex;    // 接口
    __u64 timestamp;  // 学习时间
    __u8 state;       // REACHABLE/STALE/INCOMPLETE
};

// 路由统计
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct route_stats);
    __uint(max_entries, 1);
} route_stats_map SEC(".maps");

struct route_stats {
    __u64 lookups;       // 查找次数
    __u64 hits;          // 命中次数
    __u64 misses;        // 未命中次数
    __u64 ttl_exceeded;  // TTL 超时
    __u64 arp_lookups;   // ARP 查找
    __u64 arp_hits;      // ARP 命中
};
```

#### 核心逻辑

```c
SEC("xdp")
int route_ingress(struct xdp_md *ctx) {
    struct rs_context *rs_ctx;
    struct iphdr *iph;
    struct lpm_key key;
    struct route_entry *route;
    struct arp_entry *arp;
    
    // 1. 获取上下文
    rs_ctx = get_rs_context(ctx);
    if (!rs_ctx)
        return XDP_PASS;
    
    // 2. 检查是否需要路由（目的 MAC 是本机 MAC）
    if (!is_for_routing(ctx, rs_ctx))
        return XDP_PASS;
    
    // 3. 解析 IP 头
    iph = get_iphdr(ctx, rs_ctx);
    if (!iph)
        return XDP_PASS;
    
    // 4. TTL 检查和递减
    if (iph->ttl <= 1) {
        update_stats_ttl_exceeded();
        return XDP_DROP;  // 或发送 ICMP Time Exceeded
    }
    iph->ttl--;
    update_ip_checksum(iph);  // 重新计算校验和
    
    // 5. 路由表查找
    key.prefixlen = 32;
    key.addr = iph->daddr;
    
    route = bpf_map_lookup_elem(&route_table, &key);
    if (!route) {
        update_stats_miss();
        return XDP_DROP;  // 无路由，丢弃
    }
    update_stats_hit();
    
    // 6. ARP 查找（获取下一跳 MAC）
    __be32 nexthop = route->nexthop ? route->nexthop : iph->daddr;
    arp = bpf_map_lookup_elem(&arp_table, &nexthop);
    if (!arp) {
        // TODO: 触发 ARP 请求
        update_stats_arp_miss();
        return XDP_DROP;
    }
    update_stats_arp_hit();
    
    // 7. 修改以太网头（MAC 地址）
    struct ethhdr *eth = (struct ethhdr *)(void *)ctx->data;
    if ((void *)(eth + 1) > (void *)ctx->data_end)
        return XDP_DROP;
    
    // 源 MAC = 出接口 MAC（从配置获取）
    __builtin_memcpy(eth->h_source, get_iface_mac(route->ifindex), 6);
    // 目的 MAC = ARP 表中的 MAC
    __builtin_memcpy(eth->h_dest, arp->mac, 6);
    
    // 8. 设置出接口
    rs_ctx->egress_ifindex = route->ifindex;
    
    return XDP_PASS;  // 传递给下一个模块
}
```

#### ARP 处理

```c
SEC("xdp")
int arp_handler(struct xdp_md *ctx) {
    struct ethhdr *eth;
    struct arphdr *arp;
    
    // 解析 ARP
    eth = (struct ethhdr *)(void *)ctx->data;
    if ((void *)(eth + 1) > (void *)ctx->data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;
    
    arp = (struct arphdr *)(eth + 1);
    if ((void *)(arp + 1) > (void *)ctx->data_end)
        return XDP_PASS;
    
    // 处理 ARP 请求
    if (arp->ar_op == bpf_htons(ARPOP_REQUEST)) {
        // 如果是请求本机 IP，发送 ARP 响应
        return handle_arp_request(ctx, arp);
    }
    
    // 处理 ARP 响应
    if (arp->ar_op == bpf_htons(ARPOP_REPLY)) {
        // 学习 ARP 表项
        return handle_arp_reply(ctx, arp);
    }
    
    return XDP_PASS;
}
```

### rswitchctl 命令

```bash
# 路由表管理
rswitchctl route-add <CIDR> <NEXTHOP> [--ifindex <N>] [--metric <M>]
rswitchctl route-del <CIDR>
rswitchctl route-show [--json]

# ARP 表管理
rswitchctl arp-add <IP> <MAC> <IFINDEX>
rswitchctl arp-del <IP>
rswitchctl arp-show [--json]

# 统计
rswitchctl route-show-stats
```

### 配置示例

```yaml
# /etc/rswitch/routes.yaml
routes:
  - dest: 192.168.1.0/24
    nexthop: 0.0.0.0        # 直连网络
    ifindex: 1
    metric: 0
    type: direct
  
  - dest: 10.0.0.0/8
    nexthop: 192.168.1.1    # 下一跳路由
    ifindex: 1
    metric: 10
    type: static
  
  - dest: 0.0.0.0/0         # 默认路由
    nexthop: 192.168.1.254
    ifindex: 1
    metric: 100
    type: static

# ARP 静态表项（可选）
arp_entries:
  - ip: 192.168.1.1
    mac: "00:11:22:33:44:55"
    ifindex: 1
```

### 测试计划

1. **基础路由测试**:
   - 直连网络路由
   - 静态路由
   - 默认路由

2. **ARP 测试**:
   - ARP 请求/响应
   - ARP 表学习
   - ARP 老化

3. **TTL 测试**:
   - TTL 递减
   - TTL=0 丢弃

4. **性能测试**:
   - LPM 查找性能
   - 吞吐量影响
   - 延迟测试

### 已知限制

- 仅支持 IPv4（IPv6 需要 v2.0）
- 简化的 ARP 处理（无 Gratuitous ARP）
- 无 ICMP Redirect
- 无动态路由协议（OSPF/BGP）

### 工作量估算

- **实现**: 1-2 周
- **测试**: 1 周
- **文档**: 3 天
- **总计**: 2-3 周

---

## 🎨 v1.2 - QoS 模块（流量分类和标记）

### 功能目标

基于流量特征进行分类，并标记 DSCP/PCP，为 VOQd 提供更细粒度的 QoS 控制。

### 核心功能

1. **流量分类**:
   - L3 分类：DSCP, ToS
   - L4 分类：端口范围、协议
   - L2 分类：VLAN PCP
   - 应用分类：DPI (Deep Packet Inspection) - 简化版

2. **流量标记**:
   - DSCP 标记（IPv4）
   - VLAN PCP 标记
   - 内部优先级映射（给 VOQd）

3. **流量整形**:
   - Token Bucket (简化版)
   - Rate Limiting per class
   - Burst control

### 技术实现

#### BPF Maps

```c
// QoS 分类规则
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct qos_key);
    __type(value, struct qos_action);
    __uint(max_entries, 256);
} qos_rules SEC(".maps");

struct qos_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u16 vlan_id;
};

struct qos_action {
    __u8 dscp;         // DSCP 值 (0-63)
    __u8 pcp;          // VLAN PCP (0-7)
    __u8 internal_prio;// 内部优先级 (0-7)
    __u32 rate_limit;  // 速率限制 (bps)
    __u32 burst_size;  // 突发大小 (bytes)
};

// DSCP → Priority 映射表
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);          // DSCP (0-63)
    __type(value, __u8);         // Priority (0-7)
    __uint(max_entries, 64);
} dscp_to_prio SEC(".maps");

// Token Bucket 状态
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);          // Flow ID
    __type(value, struct token_bucket);
    __uint(max_entries, 1024);
} token_buckets SEC(".maps");

struct token_bucket {
    __u64 tokens;        // 当前 token 数量
    __u64 last_update;   // 上次更新时间 (ns)
    __u32 rate;          // 速率 (tokens/sec)
    __u32 capacity;      // 容量 (tokens)
};
```

#### 核心逻辑

```c
SEC("xdp")
int qos_classify(struct xdp_md *ctx) {
    struct rs_context *rs_ctx;
    struct iphdr *iph;
    struct qos_key key = {};
    struct qos_action *action;
    
    // 1. 获取上下文
    rs_ctx = get_rs_context(ctx);
    if (!rs_ctx)
        return XDP_PASS;
    
    // 2. 提取分类字段
    iph = get_iphdr(ctx, rs_ctx);
    if (iph) {
        key.src_ip = iph->saddr;
        key.dst_ip = iph->daddr;
        key.protocol = iph->protocol;
        
        // 提取 L4 端口
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = get_tcphdr(ctx, rs_ctx);
            if (tcp) {
                key.src_port = tcp->source;
                key.dst_port = tcp->dest;
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = get_udphdr(ctx, rs_ctx);
            if (udp) {
                key.src_port = udp->source;
                key.dst_port = udp->dest;
            }
        }
    }
    
    key.vlan_id = rs_ctx->vlan_id;
    
    // 3. 查找 QoS 规则
    action = bpf_map_lookup_elem(&qos_rules, &key);
    if (!action) {
        // 使用 DSCP 默认映射
        if (iph) {
            __u8 dscp = (iph->tos >> 2) & 0x3F;
            __u8 *prio = bpf_map_lookup_elem(&dscp_to_prio, &dscp);
            if (prio)
                rs_ctx->prio = *prio;
        }
        return XDP_PASS;
    }
    
    // 4. 应用 QoS 动作
    
    // 4.1 标记 DSCP
    if (action->dscp && iph) {
        __u8 old_tos = iph->tos;
        iph->tos = (iph->tos & 0x03) | (action->dscp << 2);
        update_ip_checksum_diff(iph, old_tos, iph->tos);
    }
    
    // 4.2 标记 VLAN PCP
    if (action->pcp) {
        rs_ctx->pcp = action->pcp;
        // Egress VLAN 模块会使用此值
    }
    
    // 4.3 设置内部优先级
    rs_ctx->prio = action->internal_prio;
    
    // 4.4 速率限制
    if (action->rate_limit) {
        if (!check_rate_limit(ctx, action))
            return XDP_DROP;
    }
    
    return XDP_PASS;
}

static __always_inline bool 
check_rate_limit(struct xdp_md *ctx, struct qos_action *action) {
    __u32 flow_id = compute_flow_hash(ctx);
    struct token_bucket *bucket;
    __u64 now = bpf_ktime_get_ns();
    
    bucket = bpf_map_lookup_elem(&token_buckets, &flow_id);
    if (!bucket) {
        // 初始化新的 token bucket
        struct token_bucket new_bucket = {
            .tokens = action->burst_size,
            .last_update = now,
            .rate = action->rate_limit,
            .capacity = action->burst_size,
        };
        bpf_map_update_elem(&token_buckets, &flow_id, &new_bucket, BPF_ANY);
        return true;
    }
    
    // 更新 tokens
    __u64 elapsed = now - bucket->last_update;
    __u64 new_tokens = (elapsed * bucket->rate) / 1000000000ULL;  // ns → s
    bucket->tokens = min(bucket->tokens + new_tokens, bucket->capacity);
    bucket->last_update = now;
    
    // 检查是否有足够的 tokens
    __u32 pkt_len = ctx->data_end - ctx->data;
    if (bucket->tokens >= pkt_len) {
        bucket->tokens -= pkt_len;
        return true;
    }
    
    return false;  // 速率超限
}
```

### rswitchctl 命令

```bash
# QoS 规则管理
rswitchctl qos-add-rule \
  --src <IP> --dst <IP> \
  --src-port <PORT> --dst-port <PORT> \
  --protocol <tcp|udp> \
  --dscp <DSCP> \
  --pcp <PCP> \
  --prio <PRIO> \
  --rate-limit <BPS>

rswitchctl qos-del-rule <ID>
rswitchctl qos-show-rules
rswitchctl qos-show-stats

# DSCP 映射配置
rswitchctl qos-set-dscp-map <DSCP> <PRIO>
rswitchctl qos-show-dscp-map
```

### 配置示例

```yaml
# /etc/rswitch/qos.yaml
qos:
  # DSCP → Priority 映射
  dscp_map:
    - dscp: 46  # EF (Expedited Forwarding)
      prio: 7
    - dscp: 34  # AF41
      prio: 6
    - dscp: 26  # AF31
      prio: 5
    - dscp: 0   # Best Effort
      prio: 0
  
  # 分类规则
  rules:
    - name: "voip-high-prio"
      match:
        dst_port: 5060-5100  # SIP/RTP
        protocol: udp
      action:
        dscp: 46
        pcp: 7
        internal_prio: 7
    
    - name: "video-medium-prio"
      match:
        dst_port: 8080
        protocol: tcp
      action:
        dscp: 34
        pcp: 5
        internal_prio: 5
        rate_limit: 50000000  # 50 Mbps
        burst: 1000000        # 1 MB
    
    - name: "bulk-low-prio"
      match:
        dst_port: 21  # FTP
      action:
        dscp: 8
        pcp: 1
        internal_prio: 1
        rate_limit: 10000000  # 10 Mbps
```

### 测试计划

1. **分类测试**: DSCP, 端口, 协议
2. **标记测试**: DSCP 重写, PCP 设置
3. **速率限制测试**: Token Bucket 正确性
4. **性能测试**: 分类开销

### 工作量估算

- **实现**: 1 周
- **测试**: 1 周
- **总计**: 1-2 周

---

## 🔒 v1.2 - Stateful ACL（连接跟踪）

### 功能目标

实现有状态的 ACL，支持连接跟踪和状态防火墙功能。

### 核心功能

1. **连接跟踪 (Connection Tracking)**:
   - TCP 连接状态跟踪
   - UDP 伪连接跟踪
   - ICMP 会话跟踪

2. **状态检测**:
   - NEW: 新建连接
   - ESTABLISHED: 已建立连接
   - RELATED: 相关连接
   - INVALID: 非法连接

3. **TCP 状态机**:
   - SYN → SYN-ACK → ESTABLISHED
   - FIN → FIN-ACK → CLOSED
   - RST 处理

### 技术实现

#### BPF Maps

```c
// 连接跟踪表
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // 使用 LRU 自动老化
    __type(key, struct ct_key);
    __type(value, struct ct_entry);
    __uint(max_entries, 65536);
} conntrack_table SEC(".maps");

struct ct_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct ct_entry {
    __u8 state;          // NEW/ESTABLISHED/RELATED/INVALID
    __u8 tcp_state;      // TCP 状态机
    __u64 last_seen;     // 最后活动时间
    __u64 packets;       // 包计数
    __u64 bytes;         // 字节计数
    __u32 timeout;       // 超时时间 (seconds)
};

// TCP 状态定义
#define TCP_STATE_CLOSED       0
#define TCP_STATE_SYN_SENT     1
#define TCP_STATE_SYN_RECV     2
#define TCP_STATE_ESTABLISHED  3
#define TCP_STATE_FIN_WAIT     4
#define TCP_STATE_CLOSE_WAIT   5
#define TCP_STATE_CLOSING      6
#define TCP_STATE_TIME_WAIT    7

// 连接状态定义
#define CT_STATE_NEW           0
#define CT_STATE_ESTABLISHED   1
#define CT_STATE_RELATED       2
#define CT_STATE_INVALID       3
```

#### 核心逻辑

```c
SEC("xdp")
int stateful_acl(struct xdp_md *ctx) {
    struct rs_context *rs_ctx;
    struct ct_key key = {};
    struct ct_entry *ct;
    __u8 ct_state;
    
    // 1. 提取五元组
    if (!extract_5tuple(ctx, &key))
        return XDP_PASS;
    
    // 2. 查找连接跟踪表
    ct = bpf_map_lookup_elem(&conntrack_table, &key);
    
    if (!ct) {
        // 新连接
        ct_state = CT_STATE_NEW;
        
        // 创建新的连接跟踪项
        struct ct_entry new_ct = {
            .state = CT_STATE_NEW,
            .tcp_state = TCP_STATE_CLOSED,
            .last_seen = bpf_ktime_get_ns(),
            .packets = 1,
            .bytes = ctx->data_end - ctx->data,
            .timeout = get_default_timeout(key.protocol),
        };
        
        // TCP 特殊处理
        if (key.protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = get_tcphdr(ctx, rs_ctx);
            if (tcp) {
                if (tcp->syn && !tcp->ack)
                    new_ct.tcp_state = TCP_STATE_SYN_SENT;
                else if (tcp->rst)
                    return XDP_DROP;  // 拒绝非法 TCP
            }
        }
        
        bpf_map_update_elem(&conntrack_table, &key, &new_ct, BPF_ANY);
    } else {
        // 已有连接
        ct->last_seen = bpf_ktime_get_ns();
        ct->packets++;
        ct->bytes += ctx->data_end - ctx->data;
        
        // 更新 TCP 状态
        if (key.protocol == IPPROTO_TCP) {
            update_tcp_state(ctx, ct);
        }
        
        // 判断连接状态
        if (ct->tcp_state == TCP_STATE_ESTABLISHED ||
            ct->tcp_state == TCP_STATE_CLOSE_WAIT)
            ct_state = CT_STATE_ESTABLISHED;
        else
            ct_state = ct->state;
    }
    
    // 3. 应用状态化 ACL 规则
    return apply_stateful_rules(ctx, ct_state, &key);
}

static __always_inline void 
update_tcp_state(struct xdp_md *ctx, struct ct_entry *ct) {
    struct tcphdr *tcp = get_tcphdr(ctx, NULL);
    if (!tcp)
        return;
    
    switch (ct->tcp_state) {
    case TCP_STATE_CLOSED:
        if (tcp->syn && !tcp->ack)
            ct->tcp_state = TCP_STATE_SYN_SENT;
        break;
    
    case TCP_STATE_SYN_SENT:
        if (tcp->syn && tcp->ack)
            ct->tcp_state = TCP_STATE_SYN_RECV;
        else if (tcp->rst)
            ct->tcp_state = TCP_STATE_CLOSED;
        break;
    
    case TCP_STATE_SYN_RECV:
        if (tcp->ack && !tcp->syn)
            ct->tcp_state = TCP_STATE_ESTABLISHED;
        break;
    
    case TCP_STATE_ESTABLISHED:
        if (tcp->fin)
            ct->tcp_state = TCP_STATE_FIN_WAIT;
        else if (tcp->rst)
            ct->tcp_state = TCP_STATE_CLOSED;
        break;
    
    case TCP_STATE_FIN_WAIT:
        if (tcp->fin && tcp->ack)
            ct->tcp_state = TCP_STATE_CLOSING;
        else if (tcp->ack)
            ct->tcp_state = TCP_STATE_TIME_WAIT;
        break;
    
    case TCP_STATE_CLOSING:
        if (tcp->ack)
            ct->tcp_state = TCP_STATE_TIME_WAIT;
        break;
    
    case TCP_STATE_TIME_WAIT:
        // 等待超时自动关闭
        break;
    }
}
```

### rswitchctl 命令

```bash
# 连接跟踪管理
rswitchctl ct-show [--state <NEW|ESTABLISHED|...>]
rswitchctl ct-flush
rswitchctl ct-show-stats

# 状态化 ACL 规则
rswitchctl acl-add-rule \
  --src 192.168.1.0/24 \
  --action pass \
  --state established,related  # 仅允许已建立连接
```

### 配置示例

```yaml
# 状态化防火墙规则
acl_stateful:
  # 默认策略：拒绝所有新连接，允许已建立连接
  default_policy:
    new: drop
    established: pass
    related: pass
    invalid: drop
  
  # 规则
  rules:
    - name: "allow-ssh-new"
      match:
        dst_port: 22
        protocol: tcp
        state: new
      action: pass
    
    - name: "allow-established"
      match:
        state: established,related
      action: pass
    
    - name: "drop-invalid"
      match:
        state: invalid
      action: drop
```

### 测试计划

1. **TCP 状态机测试**: SYN/ACK/FIN/RST
2. **连接跟踪测试**: NEW/ESTABLISHED/RELATED
3. **性能测试**: Hash 查找开销

### 工作量估算

- **实现**: 2 周
- **测试**: 1 周
- **总计**: 2-3 周

---

## 🏷️ v1.2 - QinQ 支持（802.1ad 双标签）

### 功能目标

支持 IEEE 802.1ad QinQ（Q-in-Q）双 VLAN 标签，用于运营商以太网场景。

### 核心功能

1. **双标签解析**:
   - Outer Tag (S-TAG): Service VLAN
   - Inner Tag (C-TAG): Customer VLAN

2. **标签操作**:
   - Push/Pop S-TAG
   - Push/Pop C-TAG
   - VLAN Translation

3. **端口模式**:
   - Customer Port: 单标签
   - Provider Port: 双标签
   - Hybrid Port: 混合模式

### 技术实现

```c
// QinQ 配置
struct qinq_config {
    __u8 mode;           // CUSTOMER/PROVIDER/HYBRID
    __u16 s_vlan;        // S-TAG VLAN ID
    __u16 c_vlan_min;    // C-TAG 范围最小值
    __u16 c_vlan_max;    // C-TAG 范围最大值
};

SEC("xdp")
int qinq_ingress(struct xdp_md *ctx) {
    struct ethhdr *eth;
    struct vlan_hdr *outer_vlan, *inner_vlan;
    
    // 1. 检查是否有 VLAN 标签
    eth = (struct ethhdr *)(void *)ctx->data;
    if ((void *)(eth + 1) > (void *)ctx->data_end)
        return XDP_DROP;
    
    // 2. 第一层 VLAN (S-TAG)
    if (eth->h_proto == bpf_htons(ETH_P_8021AD)) {
        outer_vlan = (struct vlan_hdr *)(eth + 1);
        if ((void *)(outer_vlan + 1) > (void *)ctx->data_end)
            return XDP_DROP;
        
        __u16 s_vlan = bpf_ntohs(outer_vlan->h_vlan_TCI) & 0x0FFF;
        
        // 3. 第二层 VLAN (C-TAG)
        if (outer_vlan->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q)) {
            inner_vlan = (struct vlan_hdr *)(outer_vlan + 1);
            if ((void *)(inner_vlan + 1) > (void *)ctx->data_end)
                return XDP_DROP;
            
            __u16 c_vlan = bpf_ntohs(inner_vlan->h_vlan_TCI) & 0x0FFF;
            
            // 保存双标签信息
            rs_ctx->s_vlan = s_vlan;
            rs_ctx->c_vlan = c_vlan;
            rs_ctx->qinq = 1;
        }
    }
    
    return XDP_PASS;
}
```

### 配置示例

```yaml
# QinQ 配置
qinq:
  ports:
    - id: 1
      mode: customer        # 客户端口（单标签）
      c_vlan: 100
    
    - id: 10
      mode: provider        # 运营商端口（双标签）
      s_vlan: 1000
      c_vlan_range: 1-4094  # 透传所有 C-TAG
    
    - id: 20
      mode: hybrid
      rules:
        - c_vlan: 100-200
          s_vlan: 1000
        - c_vlan: 300-400
          s_vlan: 2000
```

### 工作量估算

- **实现**: 1 周
- **测试**: 1 周
- **总计**: 1-2 周

---

## 🌳 v2.0 - STP 模块（生成树协议）

### 功能目标

实现 IEEE 802.1D STP / 802.1w RSTP（快速生成树），防止 L2 环路。

### 核心功能

1. **BPDU 处理**:
   - Configuration BPDU
   - Topology Change BPDU
   - RSTP BPDU

2. **端口状态机**:
   - Blocking → Listening → Learning → Forwarding
   - RSTP: Discarding → Learning → Forwarding

3. **角色选举**:
   - Root Bridge 选举
   - Root Port 选举
   - Designated Port 选举

### 已知限制

- STP/RSTP 需要定时器（BPF 中实现复杂）
- 可能需要用户空间辅助守护进程

### 工作量估算

- **实现**: 3-4 周（复杂度高）
- **测试**: 1-2 周
- **总计**: 4-6 周

---

## 🔗 v2.0 - LACP 模块（链路聚合）

### 功能目标

实现 IEEE 802.3ad LACP（链路聚合控制协议）。

### 核心功能

1. **LACPDU 处理**
2. **链路状态检测**
3. **负载均衡**:
   - 基于 MAC 地址
   - 基于 IP 地址
   - 基于五元组

### 工作量估算

- **实现**: 3-4 周
- **测试**: 1-2 周
- **总计**: 4-6 周

---

## 📡 v2.0 - LLDP 模块（拓扑发现）

### 功能目标

实现 IEEE 802.1AB LLDP（链路层发现协议）。

### 核心功能

1. **LLDP 帧发送**:
   - Chassis ID TLV
   - Port ID TLV
   - TTL TLV
   - System Name/Description

2. **LLDP 帧接收和解析**

3. **邻居信息维护**

### 工作量估算

- **实现**: 1 周（相对简单）
- **测试**: 3 天
- **总计**: 1-2 周

---

## 📅 开发时间线

### v1.1 (2024-11 ~ 2025-01, 3 个月)

| 周次 | 任务 | 交付物 |
|------|------|--------|
| Week 2-3 | Route 模块基础实现 | route.bpf.c, LPM 查找, ARP 表 |
| Week 4 | Route 模块完善 | TTL 处理, 统计, rswitchctl 命令 |
| Week 5 | Route 模块测试 | 功能测试, 性能测试, 文档 |
| Week 6-8 | Week 1 成果集成测试 | ACL + Mirror + VLAN 完整测试 |

### Profile System Enhancements (2025-01 ~ 2025-04, 4 个月)

| 月份 | 任务 | 交付物 |
|------|------|--------|
| 01 月 | Advanced YAML parsing | stage overrides, optional modules |
| 02 月 | Module configuration parameters | 模块特定配置支持 |
| 03 月 | Profile inheritance | 模板系统, 参数化配置 |
| 04 月 | 集成测试和文档 | 完整测试, 文档更新 |

### v1.2 (2025-02 ~ 2025-04, 3 个月)

| 月份 | 任务 | 交付物 |
|------|------|--------|
| 02 月 | QoS 模块 | qos.bpf.c, 流量分类, DSCP/PCP 标记 |
| 03 月 | Stateful ACL | 连接跟踪, TCP 状态机 |
| 04 月 | QinQ 支持 | 双标签解析, S-TAG/C-TAG 处理 |

### v2.0 (2025-05 ~ 2025-08, 4 个月)

| 月份 | 任务 | 交付物 |
|------|------|--------|
| 05-06 月 | STP/RSTP | stp.bpf.c, 生成树协议 |
| 06-07 月 | LACP | lacp.bpf.c, 链路聚合 |
| 07-08 月 | LLDP | lldp.bpf.c, 拓扑发现 |

---

## 🎯 开发建议

### 优先级建议

1. **立即开始** (P0):
   - Route 模块（v1.1 核心功能）

2. **Week 1 成果巩固** (P0):
   - 完成 ACL + Mirror + VLAN 完整测试
   - 修复 Mirror redirect vs clone 问题

3. **Profile System Enhancements** (P1):
   - Advanced YAML profile support（stage overrides, optional modules）
   - Module configuration parameters
   - Profile inheritance and templates

4. **v1.2 规划** (P1):
   - QoS 模块（依赖 VLAN PCP）
   - Stateful ACL（依赖 ACL 模块）

5. **v2.0 长期** (P2-P3):
   - STP/LACP/LLDP（企业级特性）

### 技术风险

1. **Route 模块**:
   - ARP 处理复杂度
   - TTL 和校验和更新
   - 性能影响

2. **Stateful ACL**:
   - 连接跟踪表大小
   - TCP 状态机复杂度
   - 内存开销

3. **STP/LACP**:
   - 需要定时器（BPF 限制）
   - 可能需要用户空间守护进程
   - 状态机复杂

### 测试策略

1. **单元测试**: 每个模块独立测试
2. **集成测试**: 模块间协作测试
3. **性能测试**: 吞吐量和延迟
4. **互操作测试**: 与商业交换机互通

---

## 📝 总结

### 总工作量估算

| 版本 | 模块数量 | 预计工作量 |
|------|---------|-----------|
| v1.1 | 1 (route) | 2-3 周 |
| Profile Enhancements | 3 (yaml, config, templates) | 4-5 周 |
| v1.2 | 3 (qos, stateful acl, qinq) | 4-6 周 |
| v2.0 | 3 (stp, lacp, lldp) | 8-12 周 |
| **总计** | **10** | **18-26 周（4.5-6.5 个月）** |

### 下一步行动

1. **本周** (Week 2):
   - 完成 Week 1 成果测试（ACL + Mirror + VLAN）
   - 开始 Route 模块设计文档

2. **Week 3-5**:
   - 实现和测试 Route 模块

3. **Week 6-8**:
   - v1.1 集成测试和性能优化
   - Profile System Enhancements 设计规划

4. **2025 Q1**:
   - 实现 Advanced YAML profile support
   - 添加 module configuration parameters
   - 实现 profile inheritance and templates

---

**文档版本**: v1.0  
**创建日期**: 2024-11-04  
**作者**: rSwitch Development Team
