# SDK 头文件迁移指南

> **适用对象**：在 SDK v2.0 之前已引入（vendored）rSwitch 头文件的下游项目。
>
> **目标**：从旧版头文件（`uapi.h`、`map_defs.h`、`rswitch_bpf.h`、`module_abi.h`）迁移到统一的 SDK 头文件（`rswitch_module.h`、`rswitch_maps.h`）。

---

## 1. 头文件映射表

| 旧版头文件 | 替代头文件 | 迁移内容 |
|-----------|-----------|---------|
| `uapi.h` | `rswitch_abi.h`（类型/常量）+ `rswitch_helpers.h`（宏） | `struct rs_ctx`、`struct rs_layers`、`RS_GET_CTX`、`RS_TAIL_CALL_*`、`RS_EMIT_EVENT`、错误/丢弃码 |
| `map_defs.h` | `rswitch_maps.h` | `struct rs_port_config`、`struct rs_mac_key`、`struct rs_mac_entry`、`struct rs_stats`、所有 map 定义和辅助函数 |
| `rswitch_bpf.h` | `rswitch_module.h` | CO-RE 宏、协议常量、报文解析辅助函数、编译器提示 |
| `module_abi.h` | `rswitch_abi.h` | `RS_DECLARE_MODULE`、`struct rs_module_info`、ABI 版本常量 |

### 推荐的引用方式

迁移完成后，所有 BPF 源文件最多只需两行 include：

```c
#include <rswitch_module.h>   /* 必需：ABI 类型 + 辅助函数 + 管道宏 */
#include <rswitch_maps.h>     /* 可选：仅在访问共享 map 时引入 */
```

`rswitch_module.h` 会自动引入 `rswitch_abi.h` 和 `rswitch_helpers.h`——无需直接 include 它们。

---

## 2. 逐步迁移

### 第 1 步：替换头文件引用

查找所有旧版 `#include` 指令并替换：

```diff
- #include "uapi.h"
- #include "rswitch_bpf.h"
- #include "module_abi.h"
+ #include <rswitch_module.h>
```

如果你的文件还使用了共享 map（端口配置、统计、MAC 表、VLAN map）：

```diff
- #include "map_defs.h"
+ #include <rswitch_maps.h>
```

### 第 2 步：更新 Include 路径

旧版头文件使用引号（quoted）include 和相对路径。SDK 头文件使用尖括号（angle bracket），通过 `-I` 标志解析：

```diff
  # 在你的 Makefile / 构建系统中
- CFLAGS += -I./include/rswitch
+ CFLAGS += -I$(SDK_DIR)/include
```

或者使用提供的 `Makefile.module`，它会自动设置路径：

```bash
make -f /path/to/sdk/Makefile.module MODULE=my_module
```

### 第 3 步：删除 Vendored 副本

确认迁移成功后，删除旧版头文件的 vendored 副本：

```bash
rm include/rswitch/uapi.h
rm include/rswitch/map_defs.h
rm include/rswitch/rswitch_bpf.h
rm include/rswitch/module_abi.h
```

### 第 4 步：验证构建

```bash
# 使用 Makefile.module（推荐）
make -f /path/to/sdk/Makefile.module MODULE=my_module clean all

# 或手动 clang 调用
clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86 -D__BPF__ \
    -I/path/to/sdk/include \
    -Wall -Werror \
    -c my_module.bpf.c -o my_module.bpf.o
```

---

## 3. 迁移前后对比

### 示例 A：简单入口模块

**迁移前**（旧版头文件）：

```c
#include "rswitch_bpf.h"
#include "uapi.h"

SEC("xdp")
int my_filter(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    if (rs->layers.ip_proto == IPPROTO_UDP)
        return XDP_DROP;

    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

**迁移后**（SDK 头文件）：

```c
#include <rswitch_module.h>

SEC("xdp")
int my_filter(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    if (rs->layers.ip_proto == IPPROTO_UDP)
        return XDP_DROP;

    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

无需代码改动——只需更改 `#include` 行。

### 示例 B：使用 Map 的模块

**迁移前**（旧版头文件）：

```c
#include "rswitch_bpf.h"
#include "uapi.h"
#include "map_defs.h"

SEC("xdp")
int my_stats(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    rs_stats_update_rx(rs, ctx->data_end - ctx->data);
    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

**迁移后**（SDK 头文件）：

```c
#include <rswitch_module.h>
#include <rswitch_maps.h>

SEC("xdp")
int my_stats(struct xdp_md *ctx)
{
    struct rs_ctx *rs = RS_GET_CTX();
    if (!rs) return XDP_PASS;

    rs_stats_update_rx(rs, ctx->data_end - ctx->data);
    RS_TAIL_CALL_NEXT(ctx, rs);
    return XDP_PASS;
}
```

### 示例 C：模块元数据声明

**迁移前**（旧版 `module_abi.h`）：

```c
#include "module_abi.h"

RS_DECLARE_MODULE(my_module, 2, 0, RS_HOOK_INGRESS, RS_STAGE_L3);
```

**迁移后**（`rswitch_module.h` 包含 `rswitch_abi.h`，提供 `RS_DECLARE_MODULE`）：

```c
#include <rswitch_module.h>

RS_DECLARE_MODULE(my_module, 2, 0, RS_HOOK_INGRESS, RS_STAGE_L3);
```

---

## 4. 常见迁移错误

### 错误：`'vmlinux.h' file not found`

**原因**：`rswitch_helpers.h`（通过 `rswitch_module.h` 引入）需要 `vmlinux.h`。

**修复**：从运行中的内核生成：

```bash
# 使用提供的辅助脚本
sdk/scripts/generate_vmlinux.sh include/vmlinux.h

# 或手动执行
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

### 错误：`redefinition of 'struct rs_ctx'`

**原因**：同时引入了旧版头文件和新版 SDK 头文件，导致重复定义。

**修复**：移除所有旧版 `#include` 指令。不要混用新旧头文件。

### 错误：`use of undeclared identifier 'rs_port_config_map'`

**原因**：Map 定义现在是可选引入的。`rswitch_module.h` 不包含 map。

**修复**：在访问共享 map 的文件中添加 `#include <rswitch_maps.h>`。

### 错误：`unknown type name 'struct rs_port_config'`

**原因**：同上——map value 的结构体定义在 `rswitch_maps.h` 中。

**修复**：添加 `#include <rswitch_maps.h>`。

### 警告：`"uapi.h is deprecated..."` （或类似）

**原因**：旧版头文件现在会发出 `#warning` 提醒你迁移。

**修复**：按第 1 步所述替换 `#include`。切换到新头文件后警告消失。

---

## 5. 验证清单

迁移完成后，验证以下项目：

- [ ] `grep -rn 'uapi\.h\|map_defs\.h\|rswitch_bpf\.h\|module_abi\.h' src/` → 无匹配（所有旧版 include 已移除）
- [ ] 使用 `-Wall -Werror` 构建成功（无弃用警告）
- [ ] `bpftool prog show` 列出加载后的模块（BPF 程序完好）
- [ ] `bpftool map show` 确认 pinned map 可访问（map 引用已解析）
- [ ] 功能测试通过（报文正确通过模块处理）

---

## 6. SDK 头文件架构

```
rswitch_module.h          ← 唯一入口（推荐）
  └── rswitch_helpers.h   ← BPF 辅助函数、宏、报文解析
        ├── vmlinux.h     ← 内核类型（CO-RE）
        ├── bpf_helpers.h ← libbpf
        └── rswitch_abi.h ← ABI 类型、常量、结构体定义
              ├── bpf_helpers.h  （BPF 侧）
              └── linux/types.h  （用户空间侧）

rswitch_maps.h            ← 共享 map 定义（可选引入）
  ├── bpf_helpers.h
  └── rswitch_abi.h

rswitch_common.h          ← 旧版全量引入（包含所有内容）
  ├── rswitch_module.h
  └── rswitch_maps.h
```

旧版头文件（`uapi.h`、`map_defs.h`、`rswitch_bpf.h`、`module_abi.h`）保留用于向后兼容，但在编译时会发出弃用警告。

---

*另请参阅：[SDK 快速开始](../../sdk/docs/zh-CN/SDK_Quick_Start.md) · [ABI 稳定性策略](../development/ABI_POLICY.md) · [模块开发指南](../development/Module_Developer_Guide.md)*
