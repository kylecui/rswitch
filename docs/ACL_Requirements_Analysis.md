# ACL完整需求分析与设计方案

## 真实场景的ACL需求

### 场景分类

#### 1. 安全防护类
```
✓ 阻止SSH暴力破解：任意源 → 服务器:22 (高频连接)
✓ 阻止恶意站点：任意源 → 恶意IP:* 
✓ 阻止QUIC协议：任意源:* → 任意目标:443/UDP
✓ 阻止特定攻击者：攻击者IP:* → 任意目标:*
✓ 允许管理访问：管理网段:* → 服务器:22/SSH
```

#### 2. 流量控制类
```
✓ 限制P2P流量：任意源:高端口 ↔ 任意目标:高端口
✓ 限制视频流量：任意源 → CDN网段:80,443
✓ 优先级控制：VoIP端口(5060) 高优先级
```

#### 3. 合规审计类
```
✓ 记录敏感访问：任意源 → 数据库服务器:3306,5432
✓ 阻止未授权协议：任意源 → 任意目标:非标准端口
✓ VLAN隔离：VLAN10:* ↔ VLAN20:* (禁止跨VLAN)
```

### 匹配字段需求矩阵

| 场景 | Proto | Src IP | Src Port | Dst IP | Dst Port | VLAN | 其他 |
|------|-------|--------|----------|--------|----------|------|------|
| 阻止SSH暴力破解 | ✓ TCP | ✗ 任意 | ✗ 任意 | ✓ 特定 | ✓ 22 | - | 频率限制 |
| 阻止恶意站点 | ✗ 任意 | ✗ 任意 | ✗ 任意 | ✓ 特定 | ✗ 任意 | - | - |
| 阻止QUIC | ✓ UDP | ✗ 任意 | ✗ 任意 | ✗ 任意 | ✓ 443 | - | - |
| 阻止攻击者 | ✗ 任意 | ✓ 特定 | ✗ 任意 | ✗ 任意 | ✗ 任意 | - | - |
| P2P限制 | ✗ 任意 | ✗ 任意 | ✓ >1024 | ✗ 任意 | ✓ >1024 | - | - |
| VLAN隔离 | ✗ 任意 | ✗ 任意 | ✗ 任意 | ✗ 任意 | ✗ 任意 | ✓ 特定 | - |

**结论：需要支持任意字段组合的部分匹配！**

---

## 当前设计的问题

### 问题1：HASH Map只支持精确匹配

```c
// 当前5-tuple map
struct acl_5tuple_key {
    proto, src_ip, dst_ip, sport, dport  // 必须全部匹配
};

// 无法表达：
// - "任意源 → 特定目标:端口"
// - "特定协议 + 任意IP + 特定端口"
```

### 问题2：LPM只能匹配IP前缀

```c
// 当前LPM map
struct acl_lpm_key {
    prefixlen, ip  // 只能做IP前缀匹配
};

// 无法结合：
// - "特定IP段 + 特定端口"
// - "特定协议 + IP段"
```

### 问题3：缺少组合匹配能力

无法表达逻辑：
```
IF proto=TCP AND dst_port=22 THEN DROP
IF src_ip IN 10.0.0.0/8 AND dst_port IN [80,443] THEN RATE_LIMIT
```

---

## 业界解决方案参考

### 方案A：多级索引表（Cisco ASA/PIX风格）

```
Level 1: 5-tuple精确匹配 (最高优先级)
Level 2: 4-tuple匹配 (proto + src_ip + dst_ip + dst_port)
Level 3: 3-tuple匹配 (proto + dst_ip + dst_port)
Level 4: 2-tuple匹配 (proto + dst_port)
Level 5: IP前缀匹配 (src/dst LPM)
Level 6: 协议匹配 (proto only)
Level 7: 默认策略
```

**优点：** 覆盖常见场景，查找快速
**缺点：** Map数量爆炸（组合太多），不够灵活

### 方案B：位掩码通配符（iptables风格）

```c
struct acl_rule {
    struct {
        proto, src_ip, dst_ip, sport, dport  // 匹配值
    } match;
    struct {
        proto_mask, src_mask, dst_mask, sport_mask, dport_mask  // 掩码
    } mask;
};

// 匹配逻辑：
if ((packet.field & rule.mask.field) == (rule.match.field & rule.mask.field))
```

**优点：** 灵活，单个规则表达能力强
**缺点：** 需要遍历所有规则（回到O(N)问题）

### 方案C：决策树/Trie（OVS风格）

```
        [proto]
       /   |   \
     TCP  UDP  ICMP
      |    |
  [dst_port]
   /   |   \
  22  80  443
   |
[src_ip prefix]
   /   \
10.0/8  192.168/16
```

**优点：** 高效，支持任意字段组合
**缺点：** 实现复杂，eBPF中难以构建

### 方案D：Tuple Space Search（Google Maglev风格）

预先计算所有可能的字段组合空间：
```
Space[proto]
Space[proto, dst_port]
Space[proto, dst_ip, dst_port]
Space[src_ip, dst_ip]
...
```

**优点：** O(1)查找，支持任意组合
**缺点：** 空间开销大，需要预定义组合

---

## 推荐方案：分层哈希 + 优先级

### 核心思想

**不追求完美灵活性，而是覆盖95%的真实场景**

根据真实需求频率，设计**7个专用HASH表**：

```
┌─────────────────────────────────────────────────────────┐
│  Priority Level  │  Match Fields              │  Use Case │
├─────────────────────────────────────────────────────────┤
│  1 (Highest)     │  5-tuple完全匹配             │  精确流控制 │
│  2               │  proto+dst_ip+dst_port      │  阻止特定服务 │
│  3               │  proto+src_ip+dst_port      │  限制特定源 │
│  4               │  proto+dst_port             │  协议端口过滤 │
│  5               │  src_ip (LPM)               │  源IP段过滤 │
│  6               │  dst_ip (LPM)               │  目标IP段过滤 │
│  7 (Lowest)      │  default_policy             │  兜底策略 │
└─────────────────────────────────────────────────────────┘
```

### 详细设计

#### Level 1: 5-Tuple精确匹配 (已实现)

```c
struct acl_5tuple_key {
    __u8  proto;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
};
// 匹配：10.1.2.3:12345 → 192.168.1.1:22 (TCP)
// 场景：特定连接的QoS、镜像、精确阻止
```

#### Level 2: Proto + Dst IP + Dst Port

```c
struct acl_proto_dstip_port_key {
    __u8  proto;
    __u32 dst_ip;
    __u16 dst_port;
};
// 匹配：* → 203.0.113.5:443 (TCP)
// 场景：阻止访问恶意站点HTTPS、阻止特定服务
```

#### Level 3: Proto + Src IP + Dst Port

```c
struct acl_proto_srcip_port_key {
    __u8  proto;
    __u32 src_ip;
    __u16 dst_port;
};
// 匹配：10.1.2.3:* → *:22 (TCP)
// 场景：限制特定主机的SSH访问
```

#### Level 4: Proto + Dst Port

```c
struct acl_proto_port_key {
    __u8  proto;
    __u16 dst_port;
};
// 匹配：* → *:443 (UDP)
// 场景：全局阻止QUIC协议、阻止特定端口
```

#### Level 5: Src IP LPM (已实现)

```c
struct acl_lpm_key {
    __u32 prefixlen;
    __u32 ip;
};
// 匹配：10.0.0.0/8 → *
// 场景：阻止攻击者网段
```

#### Level 6: Dst IP LPM (已实现)

```c
// 同Level 5结构
// 匹配：* → 192.168.0.0/16
// 场景：保护内网网段
```

#### Level 7: 默认策略 (已实现)

```c
struct acl_config {
    __u8 default_action;  // PASS or DROP
};
```

### 匹配流程伪代码

```c
SEC("xdp")
int acl_filter(struct xdp_md *xdp_ctx)
{
    struct rs_ctx *ctx = RS_GET_CTX();
    struct acl_result *result = NULL;
    
    // 提取包字段
    __u8  proto = ctx->layers.ip_proto;
    __u32 sip = ctx->layers.saddr;
    __u32 dip = ctx->layers.daddr;
    __u16 sport = ctx->layers.sport;
    __u16 dport = ctx->layers.dport;
    
    // Level 1: 5-tuple精确匹配
    struct acl_5tuple_key k1 = {proto, sip, dip, sport, dport};
    if ((result = bpf_map_lookup_elem(&acl_5tuple_map, &k1))) {
        return apply_action(result, ACL_STAT_L1_HIT);
    }
    
    // Level 2: Proto + Dst IP + Dst Port
    struct acl_proto_dstip_port_key k2 = {proto, dip, dport};
    if ((result = bpf_map_lookup_elem(&acl_proto_dstip_port_map, &k2))) {
        return apply_action(result, ACL_STAT_L2_HIT);
    }
    
    // Level 3: Proto + Src IP + Dst Port
    struct acl_proto_srcip_port_key k3 = {proto, sip, dport};
    if ((result = bpf_map_lookup_elem(&acl_proto_srcip_port_map, &k3))) {
        return apply_action(result, ACL_STAT_L3_HIT);
    }
    
    // Level 4: Proto + Dst Port
    struct acl_proto_port_key k4 = {proto, dport};
    if ((result = bpf_map_lookup_elem(&acl_proto_port_map, &k4))) {
        return apply_action(result, ACL_STAT_L4_HIT);
    }
    
    // Level 5: Src IP LPM
    struct acl_lpm_key k5 = {32, sip};
    if ((result = bpf_map_lookup_elem(&acl_lpm_src_map, &k5))) {
        return apply_action(result, ACL_STAT_L5_HIT);
    }
    
    // Level 6: Dst IP LPM
    struct acl_lpm_key k6 = {32, dip};
    if ((result = bpf_map_lookup_elem(&acl_lpm_dst_map, &k6))) {
        return apply_action(result, ACL_STAT_L6_HIT);
    }
    
    // Level 7: 默认策略
    return default_action;
}
```

**性能分析：**
- 最坏情况：7次map查找 (~70ns)
- 典型情况：1-2次查找命中 (~10-20ns)
- 仍然是O(1)复杂度，无循环

---

## 控制平面命令设计

### rsaclctl扩展命令

```bash
# Level 1: 5-tuple精确匹配 (已有)
rsaclctl add-5t --proto tcp --src 10.1.2.3 --sport 12345 \
                --dst 192.168.1.1 --dport 22 --action drop

# Level 2: Proto + Dst IP + Dst Port
rsaclctl add-proto-dst --proto tcp --dst 203.0.113.5 --dport 443 --action drop

# Level 3: Proto + Src IP + Dst Port
rsaclctl add-proto-src --proto tcp --src 10.1.2.3 --dport 22 --action drop

# Level 4: Proto + Dst Port (全局端口过滤)
rsaclctl add-proto-port --proto udp --dport 443 --action drop  # 阻止QUIC

# Level 5/6: LPM (已有)
rsaclctl add-lpm-src --prefix 10.0.0.0/8 --action drop
rsaclctl add-lpm-dst --prefix 192.168.0.0/16 --action pass

# Level 7: 默认策略 (已有)
rsaclctl set-default --action pass
```

### 统一命令接口（可选优化）

```bash
# 统一语法：rsaclctl add <match-spec> <action-spec>
rsaclctl add --match "proto=tcp,dst=203.0.113.5,dport=443" --action drop
rsaclctl add --match "proto=udp,dport=443" --action drop
rsaclctl add --match "src=10.0.0.0/8" --action drop

# 自动选择最优Level
```

---

## 特殊场景处理

### 1. 端口范围

**问题：** 如何匹配 `dport=1024-65535`？

**方案A：范围分段**
```bash
# 将范围分成几个大段
rsaclctl add-proto-port --proto tcp --dport 1024 --action drop
rsaclctl add-proto-port --proto tcp --dport 2048 --action drop
...
```

**方案B：专用范围map**
```c
struct acl_port_range {
    __u16 min_port;
    __u16 max_port;
    __u8  proto;
};

// 查找时遍历（数量有限，可接受）
#pragma unroll
for (int i = 0; i < MAX_PORT_RANGES; i++) {
    if (dport >= range[i].min && dport <= range[i].max) {
        return range[i].action;
    }
}
```

**推荐：** 方案B，但限制最多32个范围规则

### 2. VLAN隔离

**需求：** 阻止VLAN 10和VLAN 20之间的通信

**方案：** 增加VLAN字段到Level 1

```c
struct acl_5tuple_vlan_key {
    __u8  proto;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
    __u16 src_vlan;  // 新增
    __u16 dst_vlan;  // 新增（egress时填充）
};
```

或使用专用map：
```c
struct acl_vlan_pair_key {
    __u16 src_vlan;
    __u16 dst_vlan;
};
// 匹配：VLAN 10 → VLAN 20 (DROP)
```

### 3. 多协议组合

**需求：** 阻止TCP或UDP的端口53（DNS）

**方案：** 添加两条规则
```bash
rsaclctl add-proto-port --proto tcp --dport 53 --action drop
rsaclctl add-proto-port --proto udp --dport 53 --action drop
```

或扩展proto字段支持位掩码：
```c
__u8 proto;      // 0 = any, 6 = TCP, 17 = UDP
__u8 proto_mask; // 0xFF = exact, 0x00 = any
```

---

## 实现roadmap

### Phase 1.1: 核心扩展（必须）

- [ ] Level 2 map: `acl_proto_dstip_port_map`
- [ ] Level 3 map: `acl_proto_srcip_port_map`
- [ ] Level 4 map: `acl_proto_port_map`
- [ ] rsaclctl新命令: `add-proto-dst`, `add-proto-src`, `add-proto-port`
- [ ] 更新匹配流程
- [ ] 统计计数器扩展

### Phase 1.2: 特殊场景（可选）

- [ ] 端口范围支持
- [ ] VLAN隔离map
- [ ] 协议组合支持

### Phase 1.3: 优化（可选）

- [ ] 规则优先级可配置
- [ ] 规则热重载
- [ ] 统一命令接口

---

## Map资源评估

```
Level 1: acl_5tuple_map              65536 entries × 32 bytes = 2 MB
Level 2: acl_proto_dstip_port_map    65536 entries × 16 bytes = 1 MB
Level 3: acl_proto_srcip_port_map    65536 entries × 16 bytes = 1 MB
Level 4: acl_proto_port_map          1024 entries  × 8 bytes  = 8 KB
Level 5: acl_lpm_src_map             16384 entries × 16 bytes = 256 KB
Level 6: acl_lpm_dst_map             16384 entries × 16 bytes = 256 KB
Level 7: acl_config_map              1 entry       × 8 bytes  = 8 bytes

Total: ~4.5 MB (可接受)
```

---

## 性能预估

### 查找延迟

```
Best case (Level 1命中):     1次查找 = ~10ns
Typical case (Level 2-4命中): 2-4次查找 = ~20-40ns
Worst case (默认策略):       7次查找 = ~70ns
```

### 吞吐量影响

```
单核XDP理论极限: ~10 Mpps
ACL开销: ~70ns/pkt
实际吞吐: ~14 Mpps (受其他模块影响)

结论：性能损耗可接受 (~30%)
```

---

## 总结

### 设计原则

1. **实用性优先：** 覆盖95%真实场景，而非100%完美
2. **性能可控：** 固定查找次数，无循环
3. **扩展性：** 7级结构可根据需要增减
4. **简洁性：** 每个Level职责明确

### 核心优势

✅ 支持常见部分匹配场景（proto+port, proto+ip+port等）
✅ O(1)查找性能，无需遍历规则
✅ 优先级清晰，从精确到模糊
✅ Map资源消耗可控（~4.5MB）
✅ 易于理解和调试

### 待解决问题

⚠️ 端口范围需要额外处理
⚠️ 复杂逻辑组合（AND/OR）不支持
⚠️ VLAN隔离需要专门设计

### 下一步

实现**Level 2, 3, 4**三个新map，即可解决您提出的场景！
