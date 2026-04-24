> 📖 [English Version](../../development/ABI_POLICY.md)
# ABI稳定性策略

**适用于**: rSwitch ABI v2.0+
**最后更新**: 2026-03-24

本文档定义了rSwitch模块ABI的稳定性契约。它规定了变更如何分类、沟通和执行。

---

## 1. 版本语义

rSwitch使用两部分组成的ABI版本：**`MAJOR.MINOR`**（编码为 `(MAJOR << 16) | MINOR`）。

| 版本组件 | 何时增加 | 对现有模块的影响 |
|-------------------|-------------|---------------------------|
| **MAJOR** | 破坏性变更：struct布局、删除字段、语义变更 | Loader **拒绝** 针对旧主版本构建的模块 |
| **MINOR** | 增量变更：新标志、新错误代码、新预留字段用途 | Loader **接受** 针对相同主版本 + 较旧次版本构建的模块 |

### Loader执行

Loader (`rswitch_loader`)、注册表和热重载守护进程都会强制执行ABI兼容性：

```
Module ABI    Platform ABI    Result
─────────────────────────────────────
1.x           2.x             REJECTED  (major mismatch)
2.0           2.1             ACCEPTED  (older minor OK)
2.1           2.0             REJECTED  (newer minor than platform)
2.1           2.1             ACCEPTED  (exact match)
3.0           2.x             REJECTED  (major mismatch)
```

**规则**：仅当 `mod_major == plat_major && mod_minor <= plat_minor` 时，模块才会加载。

---

## 2. 稳定性层级

每个公共API元素都标注有三个稳定性层级之一：

### RS_API_STABLE

**保证**：在同一个主版本内没有破坏性变更。如果必须更改稳定API，则会增加主版本号。

**包含**：
- `struct rs_ctx` 布局和字段语义
- `struct rs_layers` 布局和字段语义
- `struct rs_module_desc` 布局
- `RS_DECLARE_MODULE()` 宏签名
- `RS_DEPENDS_ON()` 宏签名
- `RS_GET_CTX()`、`RS_TAIL_CALL_NEXT()`、`RS_TAIL_CALL_EGRESS()`、`RS_EMIT_EVENT()`
- 所有 `RS_FLAG_*` 常量（现有位的含义永远不会改变）
- 所有 `RS_HOOK_*` 常量
- `RS_STAGE_USER_INGRESS_MIN/MAX`、`RS_STAGE_USER_EGRESS_MIN/MAX`
- `RS_EVENT_USER_BASE`、`RS_EVENT_USER_MAX`
- 所有 `RS_ERROR_*` 和 `RS_DROP_*` 常量

### RS_API_EXPERIMENTAL

**保证**：可能会在次版本之间发生变化。将在2个次版本发布内晋升为STABLE或被移除。

**当前实验性API**：
- `struct rs_module_deps`（依赖声明格式）
- 模块配置map接口 (`rs_get_module_config`)

**迁移**：当实验性API发生变化时，变更日志将包含迁移说明。

### RS_API_INTERNAL

**保证**：无。可能在任何commit时发生变化。请勿在外部模块中使用。

**包含**：
- 内部map布局（ring buffer元数据、prog chain内部机制）
- Dispatcher阶段分配逻辑
- Loader ELF解析内部机制

---

## 3. Struct布局规则

### rs_ctx (Per-Packet Context)

The `rs_ctx` struct是模块之间主要的ABI界面。适用以下规则：

1. **禁止字段重排**：字段在主版本内保持其偏移量
2. **禁止字段删除**：字段可以被弃用，但在主版本内不能删除
3. **禁止类型更改**：字段的类型和大小在主版本内永远不会改变
4. **预留区域**：`rs_ctx` 末尾的 `reserved[16]`（64字节）可用于未来的次版本添加。新字段从 `reserved[]` 中分配 —— 在主版本内，struct的总大小不会改变
5. **填充**：存在显式的 `pad[]` 字段用于对齐；在没有主版本升级的情况下，不得重新利用它们

### rs_module_desc (Module Metadata)

1. **格式在主版本内冻结**（字段偏移量、大小、section名称 `.rodata.mod`）
2. 末尾的 `reserved[4]` 可用于未来的次版本扩展
3. `name` 最大长度 (32) 和 `description` 最大长度 (64) 是稳定的

### 添加新字段（次版本升级）

当需要新字段时：
1. 从 `reserved[]` 区域分配（不改变struct大小）
2. 增加 `RS_ABI_VERSION_MINOR`
3. 旧模块（相同主版本，较旧次版本）继续工作 —— 它们只是不读取/写入新字段
4. 需要该字段的新模块将 `RS_ABI_VERSION_MINOR` 设置为引入该字段的版本

---

## 4. 标志和常量稳定性

### RS_FLAG_* Capability Flags

| 规则 | 详情 |
|------|--------|
| 现有位的含义永远不会改变 | `RS_FLAG_MAY_DROP` 始终是第4位 |
| 新标志使用下一个可用位 | 目前已分配0-6位 |
| 添加新标志是 **次版本 (minor)** 升级 | 不设置该标志的现有模块不受影响 |
| Loader永远不会因为缺少可选标志而拒绝模块 | 标志是信息性的 / 声明性的 |

### RS_EVENT_* Event Types

| 范围 | 所有者 | 稳定性 |
|-------|-------|-----------|
| `0x0000-0x0FFF` | Core rSwitch | 在主版本内STABLE |
| `0x1000-0x7FFF` | 用户模块 | STABLE范围边界；内部分配由用户负责 |
| `0x8000-0xFEFF` | 预留 | 请勿使用 |
| `0xFF00-0xFFFF` | Core错误 | 在主版本内STABLE |

### RS_STAGE_* Stage Ranges

| 范围 | 所有者 | 稳定性 |
|-------|-------|-----------|
| 10-99 | Core ingress | STABLE |
| 100-199 | Core egress | STABLE |
| 200-299 | 用户ingress | STABLE |
| 400-499 | 用户egress | STABLE |
| 300-399 | 预留 | 请勿使用 |

---

## 5. 弃用流程

当STABLE API需要更改时：

1. **宣布**：添加 `RS_DEPRECATED("Use X instead, removed in ABI vN+1")` 注解
2. **宽限期**：弃用的API在至少1个主版本内保持功能
3. **记录**：变更日志和迁移指南与弃用公告一同发布
4. **移除**：弃用的API在下一个主版本中移除

示例时间线：
```
ABI 2.0  — 引入 RS_FLAG_FOO (STABLE)
ABI 2.3  — 弃用 RS_FLAG_FOO，由 RS_FLAG_BAR 替代
ABI 3.0  — 移除 RS_FLAG_FOO，RS_FLAG_BAR 现在是唯一选项
```

---

## 6. ABI版本历史

| 版本 | 日期 | 变更 |
|---------|------|---------|
| **2.0** | 2026-03 | `rs_ctx.reserved` 从16字节扩展到64字节；添加 `RS_FLAG_MAY_REDIRECT`；用户阶段范围 (200-299, 400-499)；用户事件范围 (0x1000-0x7FFF)；从1.0升级主版本 |
| **1.0** | 2025-12 | 初始ABI：具有16字节预留区域的 `rs_ctx`，6个能力标志，仅包含核心阶段范围 |

---

## 7. 致模块开发者

### 检查ABI兼容性

```c
#include "rswitch_module.h"

// RS_DECLARE_MODULE 自动在 .rodata.mod 中嵌入 RS_ABI_VERSION
// Loader 在加载时检查此版本 —— 无需手动检查版本。
```

### 针对特定ABI构建

ABI版本在编译时由SDK头文件设置。要针对特定ABI：

```bash
# 检查已安装的 SDK 版本
pkg-config --modversion rswitch
# 输出: 2.0.0

# 模块的 ABI 版本与其编译时使用的 SDK 头文件匹配
```

### 当您的模块停止加载时

如果Loader以 "ABI major mismatch" 拒绝您的模块：
1. 针对当前的SDK头文件重新编译（运行 `sudo make install-sdk` 进行更新）
2. 查看 [ABI版本历史](#6-abi-version-history) 了解破坏性变更
3. 如果任何API被移除或更改，请更新您的代码

---

## 8. 参考资料

- [SDK快速入门](../../../sdk/docs/SDK_Quick_Start.md) — 开始模块开发
- [模块开发者指南](Module_Developer_Guide.md) — 完整的模块编写模式
- [API参考](API_Reference.md) — 完整的API文档
- 头文件：[`rswitch_abi.h`](../../../sdk/include/rswitch_abi.h) — 规范的ABI定义
