> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch 剩余模块快速参考

## 📊 优先级矩阵

```
优先级  版本  模块           功能              难度  工作量    状态
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
P0      v1.1  route.bpf.c    IPv4 LPM 路由     中    2-3周     📋 计划中
P1      v1.2  qos.bpf.c      流量分类和标记    中    1-2周     📋 计划中
P1      v1.2  Stateful ACL   连接跟踪          高    2-3周     📋 计划中
P2      v1.2  QinQ           802.1ad 双标签    中    1-2周     📋 计划中
P3      v2.0  stp.bpf.c      生成树协议        高    3-4周     📋 计划中
P3      v2.0  lacp.bpf.c     链路聚合          高    3-4周     📋 计划中
P3      v2.0  lldp.bpf.c     拓扑发现          低    1周       📋 计划中
```

## 🎯 Route 模块（v1.1 - 优先级 P0）

### 核心功能
- ✅ IPv4 LPM 路由表 (BPF_MAP_TYPE_LPM_TRIE)
- ✅ 静态路由配置
- ✅ ARP 表管理
- ✅ TTL 递减和检查
- ✅ 下一跳查找

### 关键 Maps
```c
route_table      // LPM Trie: CIDR → nexthop/ifindex/metric
arp_table        // Hash: IP → MAC/ifindex
route_stats_map  // Stats: lookups/hits/misses/ttl_exceeded
```

### rswitchctl 命令
```bash
rswitchctl route-add 10.0.0.0/8 192.168.1.1 --ifindex 1 --metric 10
rswitchctl route-del 10.0.0.0/8
rswitchctl route-show
rswitchctl arp-add 192.168.1.1 00:11:22:33:44:55 1
rswitchctl arp-show
```

### 配置示例
```yaml
routes:
  - dest: 192.168.1.0/24
    nexthop: 0.0.0.0        # 直连
    ifindex: 1
  - dest: 0.0.0.0/0         # 默认路由
    nexthop: 192.168.1.254
    ifindex: 1
```

### 已知限制
- 仅 IPv4（IPv6 需要 v2.0）
- 简化 ARP（无 Gratuitous ARP）
- 无 ICMP Redirect
- 无动态路由协议

### 工作量: 2-3 周

---

## 🎨 QoS 模块（v1.2 - 优先级 P1）

### 核心功能
- ✅ L3/L4 流量分类
- ✅ DSCP 标记（IPv4）
- ✅ VLAN PCP 标记
- ✅ Token Bucket 速率限制
- ✅ VOQd 优先级映射

### 关键 Maps
```c
qos_rules        // Hash: 5-tuple → dscp/pcp/prio/rate
dscp_to_prio     // Array: DSCP → Priority
token_buckets    // Hash: Flow ID → tokens/rate/capacity
```

### rswitchctl 命令
```bash
rswitchctl qos-add-rule --dst-port 5060 --dscp 46 --pcp 7 --prio 7
rswitchctl qos-set-dscp-map 46 7  # EF → Priority 7
rswitchctl qos-show-rules
```

### 配置示例
```yaml
qos:
  dscp_map:
    - dscp: 46  # EF
      prio: 7
  rules:
    - name: "voip"
      match:
        dst_port: 5060-5100
        protocol: udp
      action:
        dscp: 46
        pcp: 7
        rate_limit: 100000000
```

### 工作量: 1-2 周

---

## 🔒 Stateful ACL（v1.2 - 优先级 P1）

### 核心功能
- ✅ TCP 连接跟踪
- ✅ TCP 状态机 (SYN/ACK/FIN/RST)
- ✅ UDP 伪连接
- ✅ 连接状态检测 (NEW/ESTABLISHED/RELATED/INVALID)
- ✅ LRU 自动老化

### 关键 Maps
```c
conntrack_table  // LRU Hash: 5-tuple → state/tcp_state/last_seen
```

### 连接状态
```
NEW          - 新建连接
ESTABLISHED  - 已建立连接
RELATED      - 相关连接
INVALID      - 非法连接
```

### TCP 状态机
```
CLOSED → SYN_SENT → SYN_RECV → ESTABLISHED → FIN_WAIT → CLOSING → TIME_WAIT → CLOSED
```

### rswitchctl 命令
```bash
rswitchctl ct-show
rswitchctl ct-show --state established
rswitchctl ct-flush
rswitchctl acl-add-rule --state established,related --action pass
```

### 配置示例
```yaml
acl_stateful:
  default_policy:
    new: drop
    established: pass
    related: pass
    invalid: drop
  rules:
    - match:
        dst_port: 22
        state: new
      action: pass
```

### 工作量: 2-3 周

---

## 🏷️ QinQ 支持（v1.2 - 优先级 P2）

### 核心功能
- ✅ 802.1ad 双标签解析
- ✅ S-TAG (Service VLAN)
- ✅ C-TAG (Customer VLAN)
- ✅ Push/Pop 操作
- ✅ VLAN Translation

### 端口模式
```
Customer  - 单标签（C-TAG）
Provider  - 双标签（S-TAG + C-TAG）
Hybrid    - 混合模式
```

### 配置示例
```yaml
qinq:
  ports:
    - id: 1
      mode: customer
      c_vlan: 100
    - id: 10
      mode: provider
      s_vlan: 1000
      c_vlan_range: 1-4094
```

### 工作量: 1-2 周

---

## 🌳 v2.0 高级协议（优先级 P3）

### STP/RSTP (生成树)
- IEEE 802.1D / 802.1w
- BPDU 处理
- 端口状态机: Blocking → Listening → Learning → Forwarding
- **工作量**: 3-4 周
- **挑战**: 定时器实现（可能需要用户空间辅助）

### LACP (链路聚合)
- IEEE 802.3ad
- LACPDU 处理
- 负载均衡: MAC/IP/五元组
- **工作量**: 3-4 周

### LLDP (拓扑发现)
- IEEE 802.1AB
- LLDP 帧发送/接收
- 邻居信息维护
- **工作量**: 1 周
- **难度**: 低（相对简单）

---

## 📅 开发时间线

### Q4 2024 (当前)
```
Week 1  ✅ ACL + Mirror + VLAN 增强
Week 2  🔄 Week 1 集成测试
Week 3-5   Route 模块实现和测试
```

### Q1 2025 (v1.1)
```
01月  Route 模块完成
      v1.1 集成测试
02月  QoS 模块
03月  Stateful ACL
```

### Q2 2025 (v1.2)
```
04月  QinQ 支持
      v1.2 集成测试
05月  性能优化
```

### Q3-Q4 2025 (v2.0)
```
06-07月  STP/RSTP
08月     LACP
09月     LLDP
10月     v2.0 集成测试
```

---

## 🔧 技术决策

### Route 模块
- **使用 LPM Trie**: O(log n) 查找，最长前缀匹配
- **简化 ARP**: 静态表 + 基础学习，无 Gratuitous ARP
- **TTL 处理**: 内核内递减，避免用户空间

### QoS 模块
- **Token Bucket**: 简单高效的速率限制
- **DSCP 映射**: 标准 DiffServ 分类
- **与 VOQd 集成**: 统一优先级体系

### Stateful ACL
- **LRU Hash**: 自动老化，避免手动清理
- **TCP 状态机**: 完整实现，支持所有状态转换
- **性能优先**: 单次 Hash 查找

### STP/LACP
- **用户空间辅助**: 定时器和复杂状态机在用户空间
- **BPF 快速路径**: 数据平面在 XDP

---

## ⚠️ 风险和挑战

### Route 模块
- **风险**: ARP 处理复杂度，性能影响
- **缓解**: 简化实现，充分测试

### Stateful ACL
- **风险**: 连接跟踪表大小，内存开销
- **缓解**: 使用 LRU，合理配置 max_entries

### STP/LACP
- **风险**: BPF 定时器限制
- **缓解**: 用户空间守护进程 + BPF 快速路径

---

## 📈 总工作量

| 版本 | 模块数 | 工作量 |
|------|--------|--------|
| v1.1 | 1 | 2-3 周 |
| v1.2 | 3 | 4-6 周 |
| v2.0 | 3 | 8-12 周 |
| **总计** | **7** | **14-21 周** |

**约 3.5-5 个月全职开发时间**

---

## 🎯 下一步行动

### 本周 (Week 2)
- [ ] 完成 Week 1 成果测试
- [ ] Route 模块设计文档
- [ ] 技术调研: LPM Trie, ARP 处理

### Week 3-5
- [ ] Route 模块实现
- [ ] Route 模块测试
- [ ] rswitchctl 命令

### Week 6-8
- [ ] v1.1 集成测试
- [ ] 性能优化
- [ ] v1.2 设计规划

---

**快速参考版本**: v1.0  
**更新日期**: 2024-11-04
