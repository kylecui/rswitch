# ABI v1 → v2迁移指南

> **目标读者**：从rSwitch ABI v1.0升级到ABI v2.0的模块开发者。
>
> 本指南涵盖所有破坏性变更、所需的具体代码修改和常见陷阱。

---

## 1. 破坏性变更摘要

ABI v2.0是**主版本**升级。使用ABI v1.0头文件编译的模块将被v2.0加载器**拒绝**（主版本不匹配）。所有模块必须重新编译。

| 变更 | ABI v1.0 | ABI v2.0 | 影响 |
|------|----------|----------|------|
| **`rs_ctx.reserved` 大小** | `__u32 reserved[4]`（16字节）| `__u32 reserved[16]`（64字节）| 结构体布局变更 — 二进制不兼容 |
| **用户入站阶段范围** | 未定义（随意使用）| 200-299（`RS_STAGE_USER_INGRESS_MIN/MAX`）| 使用此范围外硬编码阶段号的模块将违反策略 |
| **用户出站阶段范围** | 未定义（随意使用）| 400-499（`RS_STAGE_USER_EGRESS_MIN/MAX`）| 同上 |
| **用户事件类型范围** | 扁平命名空间（有冲突风险）| `0x1000-0x7FFF`（`RS_EVENT_USER_BASE/MAX`）| 此范围外的事件类型可能与核心事件冲突 |
| **`RS_FLAG_MAY_REDIRECT`** | 不可用 | 位6 | 重定向数据包的模块应设置此标志 |
| **`RS_DEPENDS_ON()` 宏** | 不可用 | 声明模块依赖关系 | 可选 — 现有模块不使用也可正常工作 |
| **统一SDK头文件** | `#include "module_abi.h"`（旧版）| `#include <rswitch_module.h>` | 旧头文件仍可用但会发出弃用警告 |

---

## 2. 逐步迁移清单

### 步骤1：更新包含路径

**迁移前（v1）**：
```c
#include "module_abi.h"
#include "rswitch_bpf.h"
#include "map_defs.h"
```

**迁移后（v2）**：
```c
#include <rswitch_module.h>    /* 统一入口 — 包含 ABI、辅助函数、map 定义 */
```

`rswitch_module.h` 包含了 `rswitch_abi.h`、`rswitch_helpers.h` 和 `rswitch_maps.h`。不再需要单独包含。

> **注意**：旧头文件（`module_abi.h`、`rswitch_bpf.h`、`map_defs.h`、`uapi.h`）仍可编译但会发出 `#warning` 弃用提示。移除它们以消除警告。

### 步骤2：安装SDK v2.0头文件

```bash
# 在构建机器上更新 SDK
cd rswitch && sudo make install-sdk

# 验证版本
pkg-config --modversion rswitch
# 预期输出: 2.0.0
```

如果使用 `Makefile.module` 进行树外构建：
```bash
# Makefile.module 自动从已安装的 SDK 拉取头文件
make -f /usr/local/share/rswitch/Makefile.module
```

### 步骤3：验证 `RS_DECLARE_MODULE` ABI版本

`RS_DECLARE_MODULE` 宏自动嵌入 `RS_ABI_VERSION`（现在是 `2.0`）。无需修改代码 — 使用v2.0头文件重新编译即可。

```c
// 保持不变 — 宏会自动使用正确的版本
RS_DECLARE_MODULE("my_module",
    RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 10,  // 阶段 210
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MODIFIES_PACKET,
    "我的自定义数据包处理器"
);
```

重新编译后验证嵌入的版本：
```bash
# 检查 .rodata.mod section
llvm-readelf -x .rodata.mod build/my_module.bpf.o | head -4
# 前 4 字节应显示 0x00020000（版本 2.0，大端序）
```

### 步骤4：更新阶段号

如果模块使用了硬编码的阶段号，请更新到v2用户范围：

| 钩子 | v2范围 | 宏 |
|------|---------|-----|
| 入站 | 200-299 | `RS_STAGE_USER_INGRESS_MIN`（200）到 `RS_STAGE_USER_INGRESS_MAX`（299）|
| 出站 | 400-499 | `RS_STAGE_USER_EGRESS_MIN`（400）到 `RS_STAGE_USER_EGRESS_MAX`（499）|

**迁移前（v1）** — 硬编码任意阶段号：
```c
RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS, 50, ...);
// 阶段 50 在核心范围内 — 可以工作但违反 v2 策略
```

**迁移后（v2）** — 使用用户范围：
```c
RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 10,  // 阶段 210
    ...);
```

> **警告**：核心阶段10-99（入站）和100-199（出站）保留给rSwitch平台模块。用户模块占用核心阶段虽然可以加载，但可能与未来的平台模块冲突。

### 步骤5：将事件类型迁移到用户命名空间

如果模块通过 `RS_EMIT_EVENT` 发送自定义事件，需更新事件类型常量：

**迁移前（v1）** — 扁平命名空间，有冲突风险：
```c
#define MY_EVENT_FOO  42   // 可能与核心事件冲突
RS_EMIT_EVENT(MY_EVENT_FOO, &data, sizeof(data));
```

**迁移后（v2）** — 使用用户事件范围：
```c
#define MY_EVENT_FOO  (RS_EVENT_USER_BASE + 1)   // 0x1001
#define MY_EVENT_BAR  (RS_EVENT_USER_BASE + 2)   // 0x1002
RS_EMIT_EVENT(MY_EVENT_FOO, &data, sizeof(data));
```

用户事件范围为 `0x1000-0x7FFF`（28,672个值）。如果共享平台，请与其他模块作者协调。

### 步骤6：添加新能力标志（如适用）

如果模块重定向数据包（通过 `bpf_redirect`、`bpf_redirect_map` 等），添加新标志：

```c
RS_DECLARE_MODULE("my_redirector",
    RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 20,
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_REDIRECT,  // ← v2 新增
    "将数据包重定向到目标端口"
);
```

此标志是信息性的 — 加载器不强制检查。但正确设置可启用未来的工具和流水线优化。

### 步骤7：声明依赖关系（可选）

ABI v2.0引入了 `RS_DEPENDS_ON()` 用于声明模块依赖：

```c
RS_DECLARE_MODULE("my_module", ...);
RS_DEPENDS_ON("dispatcher", "vlan");  // 需要 dispatcher 和 vlan 模块
```

这是**实验性的**（`RS_API_EXPERIMENTAL`）且可选。在v2.0中没有运行时效果，但支持未来的依赖感知加载。

### 步骤8：重新编译并测试

```bash
# 清理并编译
make clean && make

# 运行 BPF 测试工具（如果可用）
sudo ./test/run_tests.sh

# 或使用 BPF_PROG_TEST_RUN 测试
sudo ./test/bpf_test_runner my_module.bpf.o
```

---

## 3. 常见陷阱

### 陷阱1：混用v1和v2头文件

**症状**：编译成功但加载器拒绝模块，提示"ABI major mismatch"。

**原因**：构建系统从不同路径引入了过时的v1头文件。模块虽然使用了v2源代码但嵌入了ABI v1.0。

**修复**：确保 `-I` 标志指向v2 SDK：
```bash
# 验证使用的是哪个 rswitch_abi.h
clang -E -dM my_module.bpf.c | grep RS_ABI_VERSION_MAJOR
# 必须显示: #define RS_ABI_VERSION_MAJOR 2
```

### 陷阱2：`rs_ctx` 大小假设

**症状**：模块从 `rs_ctx` 保留区域之后的字段读取到垃圾数据。

**原因**：代码假设 `sizeof(struct rs_ctx)` 与v1布局匹配（v1的 `reserved` 少48字节）。

**修复**：永远不要硬编码 `rs_ctx` 大小。始终使用 `sizeof(struct rs_ctx)` 并通过字段名访问。

### 陷阱3：与核心模块的阶段冲突

**症状**：流水线顺序错误 — 模块在预期位置之前或之后运行。

**原因**：用户模块使用了核心阶段号（例如30 = ACL阶段）。

**修复**：入站使用 `RS_STAGE_USER_INGRESS_MIN + offset`，出站使用 `RS_STAGE_USER_EGRESS_MIN + offset`。

### 陷阱4：事件类型冲突

**症状**：用户空间事件消费者收到意外的事件数据。

**原因**：模块使用了核心范围（0x0000-0x0FFF）或错误范围（0xFF00-0xFFFF）的事件类型。

**修复**：所有自定义事件使用 `RS_EVENT_USER_BASE + N`。保持在 `0x1000-0x7FFF` 范围内。

### 陷阱5：热重载ABI检查

**症状**：`hot_reload reload my_module` 拒绝新二进制文件，提示"ABI mismatch"。

**原因**：运行平台为v2.0，但模块使用v1头文件编译（或反之）。

**修复**：确保模块使用与运行平台相同主版本编译。热重载强制执行 `mod_major == plat_major && mod_minor <= plat_minor`。

---

## 4. 快速参考：v1 vs v2对比

```c
/* ═══════════════════════════════════════════════════════ */
/* ABI v1.0（旧版）                                       */
/* ═══════════════════════════════════════════════════════ */

#include "module_abi.h"
#include "rswitch_bpf.h"

RS_DECLARE_MODULE("my_module",
    RS_HOOK_XDP_INGRESS,
    50,                              // 随意阶段号
    RS_FLAG_NEED_L2L3_PARSE,
    "My module"
);

#define MY_EVENT 42                   // 扁平命名空间
RS_EMIT_EVENT(MY_EVENT, &data, sizeof(data));


/* ═══════════════════════════════════════════════════════ */
/* ABI v2.0（新版）                                       */
/* ═══════════════════════════════════════════════════════ */

#include <rswitch_module.h>          // 统一入口

RS_DECLARE_MODULE("my_module",
    RS_HOOK_XDP_INGRESS,
    RS_STAGE_USER_INGRESS_MIN + 10,  // 阶段 210（用户范围）
    RS_FLAG_NEED_L2L3_PARSE,
    "My module"
);

#define MY_EVENT (RS_EVENT_USER_BASE + 1)   // 用户命名空间
RS_EMIT_EVENT(MY_EVENT, &data, sizeof(data));

RS_DEPENDS_ON("dispatcher");         // 可选：声明依赖
```

---

## 5. 验证清单

迁移完成后，逐项验证：

- [ ] `pkg-config --modversion rswitch` 返回 `2.0.0`
- [ ] `clang -E -dM ... | grep RS_ABI_VERSION_MAJOR` 返回 `2`
- [ ] 编译时无 `#warning` 弃用消息（已移除所有旧头文件）
- [ ] 模块加载成功：`sudo ./scripts/rswitch-init.sh start`
- [ ] 热重载正常：`sudo ./user/reload/hot_reload reload my_module --dry-run`
- [ ] 阶段号在用户范围内（入站200-299，出站400-499）
- [ ] 事件类型在用户范围内（`0x1000-0x7FFF`）

---

*另见：[ABI稳定性策略](ABI_POLICY.md) · [SDK快速开始](../../sdk/docs/SDK_Quick_Start.md) · [SDK迁移指南](../../sdk/docs/SDK_Migration_Guide.md)*
