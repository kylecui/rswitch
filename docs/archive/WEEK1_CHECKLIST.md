> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Week 1 任务清单

## ✅ 已完成 (10/15)

- [x] **Task 1-6**: ACL + Mirror BPF 模块实现和编译
  - `acl.bpf.c`: 460 lines, 20 KB
  - `mirror.bpf.c`: 294 lines, 14 KB
  - 状态: ✅ 编译通过，CO-RE 可移植

- [x] **Task 7**: VLAN PCP/DEI 增强
  - 文件: `vlan.bpf.c`（修改 ~60 行）
  - 功能: PCP → prio, DEI → ecn 映射
  - 状态: ✅ 实现完成

- [x] **Task 8**: Egress VLAN 模块
  - 文件: `egress_vlan.bpf.c` (252 lines, 43 KB)
  - 功能: Devmap egress VLAN 标签处理
  - 状态: ✅ 编译通过

- [x] **Task 9**: rswitchctl ACL 命令
  - 文件: `rswitchctl_acl.c` (344 lines)
  - 命令: add-rule, del-rule, show-rules, show-stats, enable, disable
  - 状态: ✅ 命令解析正确

- [x] **Task 10**: rswitchctl Mirror 命令
  - 文件: `rswitchctl_mirror.c` (240 lines)
  - 命令: enable, disable, set-span, set-port, show-config, show-stats
  - 状态: ✅ 命令结构正确

- [x] **Task 15**: 文档更新
  - 文件: `Migration_Guide.md`（新增 171 行）
  - 内容: v1.1-dev 更新说明章节
  - 状态: ✅ 更新完成

## 🔄 进行中 (0/15)

（无）

## ⏳ 待开始 (4/15)

- [ ] **Task 11**: ACL 功能测试
  - 需要: rSwitch loader 运行
  - 测试: 规则匹配、优先级、统计
  - 优先级: P0

- [ ] **Task 12**: Mirror 功能测试
  - 需要: rSwitch loader 运行
  - 测试: redirect 行为、统计准确性
  - 优先级: P0

- [ ] **Task 13**: VLAN PCP → VOQd 集成测试
  - 需要: VOQd 运行
  - 测试: 优先级映射、队列分类
  - 优先级: P0

- [ ] **Task 14**: 性能测试
  - 工具: pktgen-dpdk / TRex
  - 测试: 吞吐量、延迟、CPU 负载
  - 优先级: P1

## 📊 进度统计

- **总任务**: 15 个
- **已完成**: 10 个 (67%)
- **待完成**: 4 个 (27%)
- **跳过**: 1 个 (Task 11-14 合并计数)

## 🧪 测试结果

### Smoke Test
- **结果**: ✅ 27/27 PASSED
- **置信度**: 95%

### Functional Test
- **结果**: ✅ 2/2 PASSED, 🔄 13 SKIPPED
- **置信度**: 70%（需运行时验证）

## ⚠️ 已知限制

1. **Mirror redirect vs clone**: XDP 不支持包克隆，当前为重定向模式
2. **Egress VLAN 简化**: 包操作简化实现
3. **ACL 规则限制**: 最多 64 条（verifier 限制）
4. **VLAN PCP→VOQd**: 未测试集成

## 📅 下一步

**Week 2 优先级**:
1. P0: 部署 loader，运行 functional_test.sh
2. P0: ACL + Mirror 功能验证
3. P0: VLAN PCP → VOQd 集成测试
4. P1: 性能测试和数据收集

## 📁 交付物

- **代码**: ~1,700 行（新增 + 修改）
- **测试**: 2 个测试脚本，42 个测试用例
- **文档**: 171 行更新，1 个总结文档
- **二进制**: rswitchctl (81 KB)
