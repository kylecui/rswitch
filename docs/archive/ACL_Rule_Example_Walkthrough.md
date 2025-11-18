# ACL规则示例详解：阻止HTTPS到恶意站点

## 示例规则

```bash
sudo ./build/rsaclctl add-5t \
    --proto tcp \
    --src 0.0.0.0 \
    --sport 0 \
    --dst 203.0.113.5 \
    --dport 443 \
    --action drop \
    --log
```

**目标：** 阻止所有到 `203.0.113.5:443` 的HTTPS连接（无论源IP和源端口）

## 完整执行流程

### 阶段1：控制平面 - 规则安装（rsaclctl）

#### 1.1 参数解析 (`cmd_add_5tuple()`)

```c
// 解析命令行参数
proto_str = "tcp"         → key.proto = 6 (IPPROTO_TCP)
src_str = "0.0.0.0"       → key.src_ip = 0x00000000 (网络字节序)
sport = 0                 → key.sport = htons(0) = 0x0000
dst_str = "203.0.113.5"   → key.dst_ip = inet_pton("203.0.113.5") = 0x050571CB (网络字节序)
dport = 443               → key.dport = htons(443) = 0xBB01 (网络字节序)
action_str = "drop"       → result.action = ACL_ACTION_DROP (1)
--log 标志                → result.log_event = 1
```

**关键点：**
- `0.0.0.0` 和 `sport=0` 表示通配符（匹配任意源IP和源端口）
- 端口号转换为网络字节序：`htons(443)` = `0x01BB`（大端序）
- IP地址用 `inet_pton()` 转换为32位整数

#### 1.2 构造Map Key和Value

```c
struct acl_5tuple_key key = {
    .proto = 6,              // TCP
    .pad = {0, 0, 0},
    .src_ip = 0x00000000,    // 0.0.0.0 (任意源)
    .dst_ip = 0xCB710500,    // 203.0.113.5 (网络字节序，小端机器上)
    .sport = 0x0000,         // 任意源端口
    .dport = 0xBB01,         // 443 (网络字节序)
};

struct acl_result result = {
    .action = ACL_ACTION_DROP,    // 1
    .log_event = 1,                // 启用日志
    .redirect_ifindex = 0,
    .stats_id = 0,
};
```

#### 1.3 写入BPF Map

```c
// 打开pinned map
fd = bpf_obj_get("/sys/fs/bpf/rswitch/acl_5tuple_map");

// 插入规则到hash map
bpf_map_update_elem(fd, &key, &result, BPF_ANY);
// 内核HASH表现在包含：
// acl_5tuple_map[key] = result
```

**输出确认：**
```
Added 5-tuple rule: proto=6 0.0.0.0:0 -> 203.0.113.5:443 action=DROP (log)
```

---

### 阶段2：数据平面 - 包处理（acl.bpf.c）

假设数据包：`192.168.1.100:54321 → 203.0.113.5:443 (TCP SYN)`

#### 2.1 Dispatcher预处理（Phase 0已完成）

```c
// dispatcher.bpf.c 已经解析L3/L4头部
ctx->layers = {
    .eth_proto = 0x0800,           // IPv4
    .ip_proto = 6,                  // TCP
    .saddr = 0x6401A8C0,           // 192.168.1.100 (网络字节序)
    .daddr = 0xCB710500,           // 203.0.113.5
    .sport = htons(54321),         // 0x31D4 (网络字节序)
    .dport = htons(443),           // 0xBB01
};
```

#### 2.2 ACL模块入口 (`acl_filter()`)

```c
SEC("xdp")
int acl_filter(struct xdp_md *xdp_ctx)
{
    // 1. 获取per-CPU上下文
    struct rs_ctx *ctx = RS_GET_CTX();
    
    // 2. 检查ACL是否启用
    struct acl_config *cfg = bpf_map_lookup_elem(&acl_config_map, &0);
    if (!cfg || !cfg->enabled) {
        // ACL禁用，跳过处理
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
    
    // 3. 只处理IPv4
    if (ctx->layers.eth_proto != 0x0800) {
        RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
        return XDP_DROP;
    }
```

#### 2.3 Level 1：5-Tuple精确匹配

```c
    /* 从已解析的上下文构造查找key */
    struct acl_5tuple_key key = {
        .proto = ctx->layers.ip_proto,     // 6 (TCP)
        .src_ip = ctx->layers.saddr,       // 0x6401A8C0 (192.168.1.100)
        .dst_ip = ctx->layers.daddr,       // 0xCB710500 (203.0.113.5)
        .sport = ctx->layers.sport,        // 0x31D4 (54321)
        .dport = ctx->layers.dport,        // 0xBB01 (443)
    };
    
    /* Level 1查找 */
    result = bpf_map_lookup_elem(&acl_5tuple_map, &key);
```

**匹配逻辑分析：**

```
规则中的key:
  proto=6, src_ip=0.0.0.0, dst_ip=203.0.113.5, sport=0, dport=443

数据包的key:
  proto=6, src_ip=192.168.1.100, dst_ip=203.0.113.5, sport=54321, dport=443

是否匹配？ ❌ 不匹配！

原因：HASH查找是精确匹配（exact match），必须所有字段完全相同
- proto: 6 == 6 ✅
- src_ip: 0.0.0.0 != 192.168.1.100 ❌
- dst_ip: 203.0.113.5 == 203.0.113.5 ✅
- sport: 0 != 54321 ❌
- dport: 443 == 443 ✅

BPF HASH表不支持通配符！0.0.0.0 和 0 不是特殊值！
```

**问题发现：当前实现的局限性！**

#### 2.4 后续Level 2/3处理

```c
    if (result) {
        // 如果Level 1命中，执行动作
        // 但在本例中，result = NULL（未命中）
    }
    
    /* Level 2a: LPM源IP前缀匹配 */
    struct acl_lpm_key lpm_key = {
        .prefixlen = 32,
        .ip = ctx->layers.saddr,  // 192.168.1.100
    };
    result = bpf_map_lookup_elem(&acl_lpm_src_map, &lpm_key);
    if (result) { ... }  // 没有匹配的LPM规则
    
    /* Level 2b: LPM目标IP前缀匹配 */
    lpm_key.ip = ctx->layers.daddr;  // 203.0.113.5
    result = bpf_map_lookup_elem(&acl_lpm_dst_map, &lpm_key);
    if (result) { ... }  // 没有匹配的LPM规则
    
    /* Level 3: 默认策略 */
    if (cfg->default_action == ACL_ACTION_DROP) {
        return XDP_DROP;  // 如果默认是DROP
    }
    
    // 默认PASS - 包会被允许通过！❌
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
}
```

---

## 问题分析：为什么规则不生效？

### 当前实现的局限

**BPF HASH Map特性：**
- `BPF_MAP_TYPE_HASH` 使用精确匹配（exact match）
- Key的所有字段必须完全相同才能命中
- **不支持通配符或部分匹配**

**示例中的问题：**
```c
// 用户期望：匹配"任意源"到特定目标
规则: src=0.0.0.0, sport=0, dst=203.0.113.5, dport=443

// 实际情况：只会匹配这个精确的5元组
实际包: src=192.168.1.100, sport=54321, dst=203.0.113.5, dport=443

// 结果：不匹配！因为src和sport不同
```

---

## 解决方案

### 方案1：多条精确规则（不实用）

为每个可能的源IP+源端口组合添加规则：

```bash
# 需要添加大量规则，不可行
for src_ip in all_possible_ips; do
    for src_port in 1-65535; do
        rsaclctl add-5t --src $src_ip --sport $src_port \
                        --dst 203.0.113.5 --dport 443 --action drop
    done
done
```

**问题：** 需要数百万条规则，不现实

### 方案2：增加Protocol+Port专用Map（推荐）✅

添加新的查找级别：匹配协议+目标IP+目标端口（忽略源）

#### 2.1 新增Map定义

```c
/* Level 1.5: Protocol + Dst IP + Dst Port Match
 * 匹配特定协议到特定目标IP:Port（忽略源IP和源端口）
 * Use case: Block all HTTPS to malicious site
 */
struct acl_proto_dstip_port_key {
    __u8  proto;
    __u8  pad[3];
    __u32 dst_ip;
    __u16 dst_port;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct acl_proto_dstip_port_key);
    __type(value, struct acl_result);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_proto_dstip_port_map SEC(".maps");
```

#### 2.2 修改匹配逻辑

```c
    /* Level 1: 完整5-tuple匹配（最高优先级） */
    result = bpf_map_lookup_elem(&acl_5tuple_map, &key);
    if (result) {
        return apply_action(result);
    }
    
    /* Level 1.5: Protocol + Dst IP + Dst Port（新增）*/
    struct acl_proto_dstip_port_key pdp_key = {
        .proto = ctx->layers.ip_proto,
        .dst_ip = ctx->layers.daddr,
        .dst_port = ctx->layers.dport,
    };
    result = bpf_map_lookup_elem(&acl_proto_dstip_port_map, &pdp_key);
    if (result) {
        return apply_action(result);  // ✅ 在这里命中！
    }
    
    /* Level 2a/2b: LPM前缀匹配 */
    ...
```

#### 2.3 新的控制命令

```bash
# 新命令：add-proto-dst（匹配协议+目标IP+端口，忽略源）
sudo rsaclctl add-proto-dst \
    --proto tcp \
    --dst 203.0.113.5 \
    --dport 443 \
    --action drop \
    --log

# 等效于：阻止所有到该目标的TCP 443连接
# 匹配任意 src_ip:src_port → 203.0.113.5:443 (TCP)
```

### 方案3：使用LPM + 端口后处理（部分解决）

结合LPM目标IP匹配 + 用户空间端口过滤：

```bash
# 先用LPM阻止整个目标IP
sudo rsaclctl add-lpm-dst --prefix 203.0.113.5/32 --action drop

# 问题：会阻止所有端口，不仅仅是443
```

---

## 当前ACL架构总结

### 支持的场景

| 场景 | 当前是否支持 | 示例 |
|------|------------|------|
| 阻止特定5元组连接 | ✅ 完全支持 | `10.1.2.3:12345 → 192.168.1.1:22` |
| 阻止源IP段 | ✅ LPM | `10.0.0.0/8 → *` |
| 阻止目标IP段 | ✅ LPM | `* → 192.168.0.0/16` |
| 阻止任意源到特定IP:Port | ❌ **不支持** | `* → 203.0.113.5:443` |
| 阻止特定协议 | ⚠️ 需要大量规则 | 所有UDP 443（QUIC） |
| 端口范围 | ❌ 不支持 | `dst_port=1024-65535` |

### 优先级顺序（当前）

```
1. Level 1: 5-tuple完全匹配 (O(1)) ← 需要精确匹配所有字段
2. Level 2a: LPM源IP前缀 (O(log N))
3. Level 2b: LPM目标IP前缀 (O(log N))
4. Level 3: 默认策略
```

### 建议改进（优先级顺序）

```
1. Level 1: 5-tuple完全匹配 (O(1))
   → 示例: 10.1.2.3:12345 → 192.168.1.1:22

2. Level 1.5: Proto + Dst IP + Dst Port (O(1)) ← 新增
   → 示例: * → 203.0.113.5:443 (TCP)
   
3. Level 1.6: Proto + Src IP + Src Port (O(1)) ← 可选新增
   → 示例: 10.1.2.3:* (TCP) → *
   
4. Level 2a: LPM源IP前缀 (O(log N))
5. Level 2b: LPM目标IP前缀 (O(log N))
6. Level 3: 默认策略
```

---

## 实现建议

要使示例规则生效，需要添加 **Level 1.5 map**：

### 代码修改清单

1. **`acl.bpf.c`** - 添加新map和匹配逻辑
2. **`rsaclctl.c`** - 添加 `add-proto-dst` 命令
3. **`ACL_Architecture.md`** - 更新文档说明新的匹配级别

### 预期效果

```bash
# 添加规则
sudo rsaclctl add-proto-dst \
    --proto tcp \
    --dst 203.0.113.5 \
    --dport 443 \
    --action drop

# 测试（从任意源）
curl https://203.0.113.5  # ← 被阻止
ssh 203.0.113.5           # ← 正常（端口22不受影响）

# 调试日志
ACL: Proto+DstIP+Port hit
ACL: DROP packet proto=6 192.168.1.100:54321 -> 203.0.113.5:443
```

---

## 结论

**当前规则不会生效**，因为：
1. BPF HASH不支持通配符（0.0.0.0和0不是特殊值）
2. 需要所有5个字段精确匹配才能命中
3. 缺少"部分匹配"的查找级别

**推荐解决方案：** 添加 Level 1.5 map专门处理"任意源到特定目标"的常见场景。
