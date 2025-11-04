# Week 2 进展总结 - 2024-11-04

## ✅ 已完成

### 1. 测试环境搭建
- ✅ 创建 network namespace 测试拓扑 (`test/setup_test_env.sh`)
- ✅ 配置 bridge + veth pairs (br0, ns1, ns2, ns3)
- ✅ SPAN port (ns3) 用于 Mirror 测试

### 2. BPF 验证器问题诊断和修复

**问题 A**: `BPF_MAP_TYPE_PROG_ARRAY` 不能使用 `bpf_map_lookup_elem()`
- **原因**: 内核 6.x+ 限制
- ✅ **已修复**: 移除 `dispatcher.bpf.c` 中的 map_lookup 调用

**问题 B**: BPF 程序指令数超限 (>1,000,000)
- **原因**: Dispatcher 进行全面包解析（包括IPv6扩展头）
- **根本问题**: 新架构设计错误 - dispatcher 不应做全面解析
- ✅ **已修复**: 采用 **lazy parsing** 策略（像 PoC 一样）
  - Dispatcher 只验证以太网头
  - 各模块按需解析（VLAN解析在vlan模块，ACL解析在acl模块）
  - 恢复使用 `parsing_helpers.h`（已在PoC中验证可行）

**问题 C**: Map sharing 参数不匹配
- **状态**: 🔧 正在解决
- **原因**: dispatcher 和 egress 对 `rs_devmap` 定义不一致
- **解决方案**: 统一 map 定义到共享头文件

## 📊 架构优化对比

| 指标 | 旧设计（全面解析） | **新设计（Lazy Parsing）** |
|------|------------------|---------------------------|
| Dispatcher 指令数 | >1,000,000 ❌ | ~10,000 ✅ |
| IPv6 支持 | 失败（超限） | 由各模块按需实现 ✅ |
| 验证器通过 | 失败 | ✅ 成功 |
| 与 PoC 一致性 | 偏离 | ✅ 对齐 |

## 🎯 当前状态

**Dispatcher**: ✅ 成功加载  
**Egress**: ⏳ Map 共享问题待修复  
**测试**: ⏳ 等待 loader 完全启动

## 📝 核心设计原则（已验证）

> **"Dispatcher 应该轻量化，只做分发；解析由各模块按需进行"**

这是 PoC 成功的关键 - 我们现在对齐到这个设计。

## 下一步

1. ⏳ 修复 map 共享问题（统一定义）
2. ⏳ 完成 loader 启动
3. ⏳ 运行 functional_test.sh
4. ⏳ 验证 ACL + Mirror 功能

---

**更新时间**: 2024-11-04 22:00  
**当前阻塞**: Map sharing 参数不匹配
