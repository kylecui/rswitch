> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Week 2 任务清单

> **日期**: 2024-11-04 开始  
> **目标**: 完成 Week 1 测试 + 启动 Route 模块开发

---

## 📊 任务总览

| 阶段 | 任务数 | 预计工作量 | 状态 |
|------|--------|-----------|------|
| Week 1 验收测试 | 3 | 1-2 天 | 🔄 进行中 |
| Route 模块调研 | 4 | 1-2 天 | ⏳ 待开始 |
| Route 模块设计 | 5 | 2-3 天 | ⏳ 待开始 |
| **总计** | **12** | **4-7 天** | - |

---

## ✅ Phase 1: Week 1 成果验收测试

### Task 1: 编译和结构测试 ✅ 已完成

- [x] 清理编译环境 (`make clean`)
- [x] 完整编译 (`make -j4`)
- [x] 运行 smoke test
- [x] 验证编译结果

**结果**: 
```
✓ 27/27 smoke tests PASSED
✓ 所有模块编译成功
✓ ACL: 20KB, Mirror: 14KB, VLAN: 13KB, Egress VLAN: 42KB
✓ rswitchctl: 81KB
```

### Task 2: 功能测试准备 🔄 进行中

- [ ] 检查网络接口配置
- [ ] 配置 loader 环境
- [ ] 准备测试网络拓扑
- [ ] 运行 functional test

**检查项**:
```bash
# 1. 检查可用网络接口
ip link show

# 2. 检查 BPF 文件系统
mount | grep bpf

# 3. 检查内核版本
uname -r

# 4. 检查 libbpf 版本
ls -l /usr/local/bpf/lib64/libbpf.a
```

**预期结果**: 
- functional_test.sh: 15/15 PASSED（当前 13 个跳过应通过）

### Task 3: ACL + Mirror 集成测试 ⏳ 待开始

**测试场景**:

1. **ACL 基础测试**:
   ```bash
   # 添加规则
   sudo rswitchctl acl-add-rule --id 10 --dst-port 22 --action pass --priority 10
   sudo rswitchctl acl-add-rule --id 20 --dst-port 23 --action drop --priority 20
   
   # 验证规则
   sudo rswitchctl acl-show-rules
   
   # 测试匹配
   # (需要实际流量)
   
   # 查看统计
   sudo rswitchctl acl-show-stats
   ```

2. **Mirror 基础测试**:
   ```bash
   # 启用镜像
   sudo rswitchctl mirror-enable 5
   
   # 配置端口镜像
   sudo rswitchctl mirror-set-port 1 --ingress --egress
   
   # 验证配置
   sudo rswitchctl mirror-show-config
   
   # 在 SPAN 端口抓包
   sudo tcpdump -i <interface5> -w mirror_test.pcap
   ```

3. **Mirror Redirect 行为验证** ⚠️ 重要:
   - 验证被镜像的包**不会**到达原始目的地
   - 确认是 redirect 而非 clone
   - 记录此行为作为已知限制

**成功标准**:
- [ ] ACL 规则正确匹配流量
- [ ] 统计数据准确
- [ ] Mirror 配置生效
- [ ] **确认 Mirror redirect 行为**（已知限制）
- [ ] 无内存泄漏
- [ ] 无性能严重退化

---

## 🔬 Phase 2: Route 模块技术调研

### Task 4: LPM Trie 调研 ⏳ 待开始

**调研内容**:

1. **BPF_MAP_TYPE_LPM_TRIE 特性**:
   - [ ] 阅读内核文档和示例
   - [ ] 理解 key 结构: `prefixlen + data`
   - [ ] 测试最长前缀匹配性能
   - [ ] 确认 max_entries 限制

2. **示例代码**:
   ```c
   struct lpm_key {
       __u32 prefixlen;  // 必须在前
       __be32 addr;      // IP 地址
   };
   
   struct {
       __uint(type, BPF_MAP_TYPE_LPM_TRIE);
       __uint(key_size, sizeof(struct lpm_key));
       __uint(value_size, sizeof(struct route_entry));
       __uint(max_entries, 10000);
       __uint(map_flags, BPF_F_NO_PREALLOC);
   } route_table SEC(".maps");
   ```

3. **性能测试**:
   - [ ] 测试不同路由表大小（100, 1K, 10K entries）
   - [ ] 测试查找延迟
   - [ ] 测试吞吐量影响

**交付物**: `docs/route/LPM_TRIE_RESEARCH.md`

### Task 5: ARP 处理调研 ⏳ 待开始

**调研内容**:

1. **ARP 协议基础**:
   - [ ] ARP 请求/响应格式
   - [ ] ARP 表结构设计
   - [ ] ARP 老化机制

2. **XDP ARP 处理**:
   - [ ] ARP 帧解析
   - [ ] ARP 响应生成
   - [ ] ARP 表更新

3. **简化策略**:
   - 静态 ARP 表（配置文件）
   - 基础动态学习（ARP 响应）
   - **不实现**: Gratuitous ARP, Proxy ARP

**交付物**: `docs/route/ARP_HANDLING.md`

### Task 6: TTL 和校验和调研 ⏳ 待开始

**调研内容**:

1. **TTL 处理**:
   ```c
   // TTL 递减
   if (iph->ttl <= 1)
       return XDP_DROP;
   iph->ttl--;
   
   // 重新计算校验和
   update_ip_checksum(iph);
   ```

2. **增量校验和更新**:
   - [ ] RFC 1624: 增量更新算法
   - [ ] BPF helper: `bpf_l3_csum_replace()`
   - [ ] 性能优化技巧

3. **测试用例**:
   - [ ] TTL=1 丢包测试
   - [ ] TTL 递减验证
   - [ ] 校验和正确性验证

**交付物**: `docs/route/TTL_CHECKSUM.md`

### Task 7: 路由表管理调研 ⏳ 待开始

**调研内容**:

1. **静态路由配置**:
   ```yaml
   routes:
     - dest: 192.168.1.0/24
       nexthop: 0.0.0.0  # 直连
       ifindex: 1
       metric: 0
     
     - dest: 0.0.0.0/0   # 默认路由
       nexthop: 192.168.1.254
       ifindex: 1
       metric: 100
   ```

2. **路由优先级**:
   - [ ] Metric 处理
   - [ ] 最长前缀优先
   - [ ] 多路径路由（ECMP）- 可选

3. **rswitchctl 命令设计**:
   ```bash
   rswitchctl route-add <CIDR> <NEXTHOP> [--ifindex N] [--metric M]
   rswitchctl route-del <CIDR>
   rswitchctl route-show [--json]
   rswitchctl arp-add <IP> <MAC> <IFINDEX>
   rswitchctl arp-show
   ```

**交付物**: `docs/route/ROUTE_MANAGEMENT.md`

---

## 📐 Phase 3: Route 模块设计

### Task 8: 数据结构设计 ⏳ 待开始

**设计内容**:

1. **BPF Maps 定义**:
   ```c
   // route_table: LPM Trie
   // arp_table: Hash
   // route_stats: PerCPU Array
   // iface_config: Array (接口 MAC 地址)
   ```

2. **结构体设计**:
   ```c
   struct route_entry {
       __be32 nexthop;
       __u32 ifindex;
       __u32 metric;
       __u8 type;  // DIRECT/STATIC/DYNAMIC
   };
   
   struct arp_entry {
       __u8 mac[6];
       __u32 ifindex;
       __u64 timestamp;
       __u8 state;  // REACHABLE/STALE
   };
   ```

**交付物**: `bpf/include/route_types.h`

### Task 9: 核心逻辑设计 ⏳ 待开始

**设计内容**:

1. **路由查找流程**:
   ```
   1. 检查是否需要路由（目的 MAC 是本机）
   2. 解析 IP 头
   3. TTL 检查和递减
   4. 路由表查找（LPM）
   5. ARP 查找
   6. 修改以太网头（MAC）
   7. 设置出接口
   ```

2. **ARP 处理流程**:
   ```
   ARP 请求 → 检查目标 IP → 生成 ARP 响应
   ARP 响应 → 学习 ARP 表项
   ```

3. **错误处理**:
   - 路由未找到 → DROP
   - ARP 未找到 → DROP（或触发 ARP 请求）
   - TTL=0 → DROP

**交付物**: `docs/route/ROUTE_LOGIC_DESIGN.md`

### Task 10: 性能优化设计 ⏳ 待开始

**优化策略**:

1. **Fast Path 优化**:
   - 避免不必要的包解析
   - 使用 PerCPU maps 避免锁
   - 内联小函数

2. **内存优化**:
   - LPM Trie: `BPF_F_NO_PREALLOC`
   - ARP 表: 合理的 max_entries
   - 统计使用 PerCPU

3. **性能目标**:
   - 路由查找延迟: < 5 μs
   - 吞吐量影响: < 10%
   - CPU 使用: < 20%

**交付物**: `docs/route/PERFORMANCE_OPTIMIZATION.md`

### Task 11: 测试计划设计 ⏳ 待开始

**测试用例**:

1. **功能测试**:
   - [ ] 直连网络路由
   - [ ] 静态路由
   - [ ] 默认路由
   - [ ] ARP 请求/响应
   - [ ] TTL 递减
   - [ ] 路由优先级

2. **边界测试**:
   - [ ] 路由表满（max_entries）
   - [ ] ARP 表满
   - [ ] TTL=0/1
   - [ ] 校验和错误

3. **性能测试**:
   - [ ] 不同路由表大小
   - [ ] 高并发查找
   - [ ] 内存使用

**交付物**: `test/route_test_plan.md`

### Task 12: 用户工具设计 ⏳ 待开始

**设计内容**:

1. **rswitchctl 命令**:
   ```c
   // user/ctl/rswitchctl_route.c
   int cmd_route_add(int argc, char **argv);
   int cmd_route_del(int argc, char **argv);
   int cmd_route_show(int argc, char **argv);
   int cmd_arp_add(int argc, char **argv);
   int cmd_arp_show(int argc, char **argv);
   ```

2. **配置文件解析**:
   ```c
   // 解析 /etc/rswitch/routes.yaml
   int load_routes_from_config(const char *path);
   ```

3. **JSON 输出**:
   ```bash
   rswitchctl route-show --json | jq '.routes[]'
   ```

**交付物**: `user/ctl/rswitchctl_route.c` (框架)

---

## 📅 时间安排

### Day 1 (今天):
- [x] ✅ 编译和 smoke test
- [ ] 🔄 功能测试准备
- [ ] 🔄 LPM Trie 调研（开始）

### Day 2:
- [ ] LPM Trie 调研（完成）
- [ ] ARP 处理调研
- [ ] TTL 和校验和调研

### Day 3:
- [ ] 路由表管理调研
- [ ] 数据结构设计
- [ ] 核心逻辑设计

### Day 4-5:
- [ ] 性能优化设计
- [ ] 测试计划设计
- [ ] 用户工具设计
- [ ] Week 2 总结

---

## 🎯 Week 2 成功标准

### 验收测试通过:
- [ ] functional_test.sh: 15/15 PASSED
- [ ] ACL 规则匹配正确
- [ ] Mirror 配置生效
- [ ] ✅ Mirror redirect 行为已确认并记录

### Route 模块设计完成:
- [ ] 4 个调研文档
- [ ] 5 个设计文档
- [ ] 测试计划
- [ ] rswitchctl 框架代码

### 文档更新:
- [ ] 更新 DEVELOPMENT_ROADMAP.md
- [ ] 创建 Route 模块设计文档
- [ ] 更新 Migration_Guide.md (v1.1 部分)

---

## 📝 备注

### Mirror Redirect 行为验证 ⚠️

**重要**: 需要明确验证和记录以下行为：
- 被镜像的包使用 `bpf_redirect_map()` 重定向到 SPAN 端口
- 原始流量**不会**到达预期目的地
- 这是 XDP 的限制（不支持 `bpf_clone_redirect()`）
- 适用场景: 单向监控、采样分析
- v1.2 计划: 使用 TC-BPF 实现真正的包克隆

### 下周预告 (Week 3-5)

**Route 模块实现**:
- Week 3: 核心实现（LPM, ARP, TTL）
- Week 4: rswitchctl 命令和测试
- Week 5: 性能优化和文档

---

**创建日期**: 2024-11-04  
**更新日期**: 2024-11-04  
**状态**: 🔄 进行中
