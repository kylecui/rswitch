> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Week 2 已知问题和解决方案

## 问题 1: BPF_MAP_TYPE_PROG_ARRAY 验证器错误（已解决）

**错误**: `cannot pass map_type 3 into func bpf_map_lookup_elem#1`

**根本原因**: 内核 6.x+ 版本不允许对 `BPF_MAP_TYPE_PROG_ARRAY` 使用 `bpf_map_lookup_elem()` helper

**解决方案**: 
- 移除 `dispatcher.bpf.c` 中的 map lookup 代码
- 直接使用 `bpf_tail_call()`，如果索引未填充会优雅失败

**修改文件**: `rswitch/bpf/core/dispatcher.bpf.c`

**Commit**: 修复 `get_first_prog()` 函数，移除违规的 map_lookup_elem 调用

---

## 问题 2: BPF 程序指令数超限 ⚠️ **当前阻塞**

**错误**: 
```
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000)
```

**根本原因**: 
- IPv6 扩展头解析循环过于复杂
- `parsing_helpers.h` 中的 `skip_ip6hdrext()` 函数有多重嵌套循环
- Clang 展开后生成的指令数超过内核限制（1M 条指令）

**影响范围**:
- `dispatcher.bpf.c` 由于包含完整的包解析逻辑而无法加载
- 阻塞所有功能测试

### 短期解决方案（临时，用于 Week 2 测试）

**方案 A**: 编译时禁用 IPv6 支持（推荐）
```c
// bpf/include/rswitch_parsing.h
#define RS_DISABLE_IPV6  // Add this define

#ifdef RS_DISABLE_IPV6
    // Simplified parsing - only IPv4
#else
    // Full IPv6 extension header parsing
#endif
```

**方案 B**: 减少 IPv6 扩展头链深度
```c
// parsing_helpers.h
-#define IPV6_EXT_MAX_CHAIN 6
+#define IPV6_EXT_MAX_CHAIN 2  // Reduce from 6 to 2
```

### 长期解决方案（v1.2+）

**方案 1**: 拆分 Dispatcher 职责
- Dispatcher 只做简单查找 + tail-call
- 包解析移到独立模块（`parse.bpf.c`）
- 估计减少 ~30% 指令数

**方案 2**: 优化 IPv6 解析逻辑
- 使用 `bpf_loop()` helper (kernel 5.17+) 替代循环展开
- 将解析拆分为多个小函数
- 使用 `#pragma clang loop unroll_count(N)` 限制展开

**方案 3**: 使用多级 Tail-Call
- Dispatcher → Parser → VLAN → ACL → ...
- 每个程序独立验证，不会累积指令数
- 缺点：增加 tail-call 开销

**方案 4**: 内核参数调整（需要内核补丁/配置）
```bash
# 某些内核版本支持调整限制（需要验证）
sysctl -w kernel.bpf.max_insns=2000000
```

### 临时措施 - 立即行动

1. **禁用 IPv6**: 添加编译宏 `RS_DISABLE_IPV6`
2. **重新编译**: `make clean && make`
3. **测试加载**: `sudo ./build/rswitch_loader --iface br0`
4. **完成功能测试**: 运行 `functional_test.sh`

5. **记录限制**: 
   - 更新 `Migration_Guide.md` "Known Issues"
   - v1.1-dev 暂不支持 IPv6
   - v1.2 将实现优化的 IPv6 解析

### 性能影响分析

**当前问题规模**:
- Dispatcher 指令数: >1,000,000
- 主要来源: `skip_ip6hdrext()` 循环展开
- 估算: IPv6 解析占 ~70% 指令

**优化后预期**:
- 禁用 IPv6: ~300,000 指令 ✓ 可加载
- 减少链深度: ~600,000 指令 ✓ 可加载
- 拆分模块: ~400,000 指令 ✓ 可加载

---

## 下一步行动

### 立即（今天）:
1. [ ] 在 `rswitch_parsing.h` 添加 `RS_DISABLE_IPV6` 宏
2. [ ] 重新编译和测试
3. [ ] 完成功能测试
4. [ ] 更新已知问题文档

### Week 3:
1. [ ] 设计优化的 IPv6 解析方案
2. [ ] 实现方案 1（拆分 Dispatcher）
3. [ ] 实现方案 2（优化循环）
4. [ ] 性能测试和验证

---

**记录日期**: 2024-11-04  
**状态**: 🔧 临时方案待实施  
**优先级**: P0 (阻塞测试)
