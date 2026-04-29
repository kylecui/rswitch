# 平滑降级协议 (Graceful Degradation Protocol)

> 当流水线部分可用或在完整的rSwitch环境之外运行时，rSwitch模块应如何表现。

## 概述

一个编写良好的rSwitch模块必须能够处理**降级情况**，而不会崩溃或静默丢弃流量。本文档定义了检测和响应部分流水线可用性的标准模式。

## 降级发生的情况

| 条件 | 原因 | 模块行为 |
|-----------|-------|-----------------|
| `rs_ctx_map` 查找返回 `NULL` | 流水线未初始化，模块独立加载 | 透传数据包 (`XDP_PASS`) |
| `rs_prog_chain` 查找返回 `NULL` | 未配置下一阶段 | 返回 `XDP_PASS` (流水线结束) |
| 尾调用失败 (回退) | 目标程序未加载 | 根据模块策略返回 `XDP_PASS` 或 `XDP_DROP` |
| 所需的配置Map为空 | 模块尚未配置 | 透传数据包 |

## 检测：`RS_IS_PIPELINE_ACTIVE`

SDK提供了一个辅助宏来检查rSwitch流水线是否处于活动状态：

```c
#include "rswitch_helpers.h"

SEC("xdp")
int my_module(struct xdp_md *xdp_ctx)
{
    /* 在依赖 rs_ctx 之前检查流水线是否处于活动状态 */
    if (!RS_IS_PIPELINE_ACTIVE())
        return XDP_PASS;  /* 平滑回退：透传流量 */

    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx)
        return XDP_PASS;

    /* 此处为正常的模块逻辑... */
}
```

`RS_IS_PIPELINE_ACTIVE()` 对 `rs_ctx_map` 执行零键 (zero-key) 查找。如果Map未固定或流水线尚未初始化，查找将返回 `NULL`，宏的评估结果为 `false`。

## 推荐模式

### 模式1：降级时透传 (默认)

大多数模块在降级时应透传流量。这可以防止部分加载的流水线导致数据包“黑洞”。

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx)
    return XDP_PASS;  /* 流水线未就绪 —— 让内核处理 */
```

### 模式2：降级时丢弃 (仅限安全模块)

安全关键模块（ACL、源防护）在流水线未完全运行时可以选择丢弃流量。**这必须在文档中明确说明。**

```c
struct rs_ctx *ctx = RS_GET_CTX();
if (!ctx)
    return XDP_DROP;  /* 安全：如果流水线降级，则拒绝流量 */
```

### 模式3：尾调用回退 (Fallthrough)

当到下一阶段的尾调用失败（目标未加载）时，BPF程序会在 `bpf_tail_call()` 之后继续执行。务必处理这种情况：

```c
/* 继续到下一阶段 */
RS_TAIL_CALL_NEXT(xdp_ctx, ctx);

/* 尾调用失败 —— 这是最后一个阶段或目标缺失 */
return XDP_PASS;  /* 或对于安全模块返回 XDP_DROP */
```

### 模式4：配置Map回退

如果您的模块依赖于配置Map，请处理其为空的情况：

```c
struct my_config *cfg = bpf_map_lookup_elem(&my_config_map, &key);
if (!cfg) {
    /* 配置尚未加载 —— 透传 */
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_PASS;
}
```

## 测试降级

使用 `BPF_PROG_TEST_RUN` 测试降级行为。`test/unit/rs_test_runner.c` 中的测试框架会初始化 `rs_ctx_map`，但您可以使用空Map进行测试以验证回退行为。

有关在部分配置条件下测试模块的示例，请参阅 `test/ci/` 中的CI测试套件（例如，`test_vlan_bpf.c` 在没有端口配置的情况下测试VLAN模块）。

## 指南

1. **默认使用XDP_PASS** —— 如有疑问，请透传数据包。静默丢弃的数据包比到达内核栈的数据包更难调试。

2. **记录您的回退方案** —— 如果您的模块在降级时丢弃数据包，请在代码中添加注释，并在模块的头文件/README中注明。

3. **永不崩溃** —— BPF中的NULL指针解引用会导致 `XDP_ABORTED` 并记录内核警告。务必检查返回值。

4. **记录降级** —— 使用 `bpf_printk()`（在 `#ifdef DEBUG` 下）记录模块何时进入降级模式。这有助于操作人员诊断部分加载场景。

## 另请参阅

- [模块开发规范](../../sdk/docs/Module_Development_Spec.md)
- [ABI策略](ABI_POLICY.md) —— 版本控制和兼容性保证
- [SDK快速入门](../../sdk/docs/SDK_Quick_Start.md) —— 入门指南
