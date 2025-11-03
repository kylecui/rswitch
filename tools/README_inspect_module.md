# rSwitch 模块验证工具使用指南

## 快速验证所有模块

```bash
# 验证所有已编译的模块
cd rswitch
python3 tools/inspect_module.py --all build/bpf/

# 输出示例：
# ✅ All modules are CO-RE compatible and portable!
# Total modules: 7
# Pluggable modules: 5 (can be distributed)
# Core components: 2 (framework built-in)
# CO-RE portable: 7/7
```

## 验证单个模块

```bash
# 检查特定模块的详细信息
python3 tools/inspect_module.py build/bpf/vlan.bpf.o

# 显示内容：
# - 模块名称和描述
# - ABI 版本
# - Hook 点和 Stage 编号
# - BTF 和 CO-RE 重定位信息
# - 可移植性评估
# - 分发建议
```

## 验证客户模块

```bash
# 验证第三方或客户提供的模块
python3 tools/inspect_module.py /path/to/customer_module.bpf.o

# 检查点：
# ✅ 有 .rodata.mod 段（可插拔）
# ✅ 有 BTF 信息（CO-RE 兼容）
# ✅ 有 CO-RE 重定位（跨内核可移植）
# ✅ ABI 版本兼容（当前 v1）
```

## 模块分类

### 可插拔模块（Pluggable Modules）

这些模块有 `.rodata.mod` 段，可以独立分发：

- **vlan.bpf.o** - VLAN 处理（ACCESS/TRUNK/HYBRID 模式）
- **l2learn.bpf.o** - L2 MAC 学习和转发表
- **lastcall.bpf.o** - 最终转发决策
- **afxdp_redirect.bpf.o** - AF_XDP 高优先级重定向
- **core_example.bpf.o** - CO-RE 统计示例

**特点**：
- 客户可自选安装
- 通过 YAML profile 配置
- 支持热重载
- 可单独分发 .bpf.o 文件

### 核心组件（Core Components）

框架内置组件，无 `.rodata.mod` 段：

- **dispatcher.bpf.o** - XDP ingress 主调度器
- **egress.bpf.o** - Devmap egress hook

**特点**：
- 框架必需组件
- 按硬件环境编译
- 随 rSwitch 主程序分发

## CO-RE 兼容性检查清单

使用工具验证模块是否满足以下条件：

- [ ] ✅ BTF 调试信息存在
- [ ] ✅ CO-RE 重定位段存在 (.BTF.ext)
- [ ] ✅ 可插拔模块有 .rodata.mod
- [ ] ✅ ABI 版本为 v1
- [ ] ✅ Stage 编号合理（0-99）
- [ ] ✅ 模块名称和描述清晰

## 常见问题排查

### 问题：模块缺少 BTF 信息

```bash
python3 tools/inspect_module.py my_module.bpf.o
# 输出: ✗ BTF debug info: Missing

# 解决方案：
# 1. 检查编译时是否包含 -g 标志
# 2. 确保使用了 vmlinux.h
# 3. 验证 clang 版本 >= 10
make clean && make
```

### 问题：模块没有 .rodata.mod

```bash
# 输出: ⚙️ Core Component (no .rodata.mod)

# 这是正常的，如果：
# - 模块是 dispatcher 或 egress（核心组件）
# - 模块不需要可插拔（如测试代码）

# 如果应该是可插拔模块，添加：
RS_DECLARE_MODULE("module_name", RS_HOOK_XDP_INGRESS, 50, 0,
                  "Module description");
```

### 问题：ABI 版本不匹配

```bash
# 输出: ABI version: v2
# 当前 rSwitch: v1

# 解决方案：
# 1. 升级 rSwitch 框架
# 2. 或重新编译模块为 ABI v1
```

## 自动化集成

### CI/CD 检查

```bash
#!/bin/bash
# ci/verify-modules.sh

set -e

echo "Building modules..."
make clean && make

echo "Verifying CO-RE compatibility..."
python3 tools/inspect_module.py --all build/bpf/ > /tmp/verify.log

# 检查是否所有模块都可移植
if grep -q "All modules are CO-RE compatible" /tmp/verify.log; then
    echo "✅ All modules passed CO-RE verification"
    exit 0
else
    echo "❌ Some modules failed CO-RE verification"
    cat /tmp/verify.log
    exit 1
fi
```

### 模块发布前检查

```bash
#!/bin/bash
# release/check-module.sh <module.bpf.o>

MODULE=$1

# 验证 CO-RE
python3 tools/inspect_module.py "$MODULE" | tee /tmp/check.log

# 必须通过的检查
grep -q "Portable across kernel versions" /tmp/check.log || exit 1
grep -q "BTF debug info" /tmp/check.log || exit 1
grep -q "CO-RE relocations" /tmp/check.log || exit 1

# 对于可插拔模块，必须有元数据
if grep -q "Pluggable Module" /tmp/check.log; then
    grep -q "Module name:" /tmp/check.log || exit 1
    grep -q "Description:" /tmp/check.log || exit 1
fi

echo "✅ Module ready for distribution"
```

## 参考文档

- **CO-RE 迁移完成报告**: `docs/CO-RE_Migration_Complete.md`
- **模块可移植性报告**: `docs/Module_Portability_Report.md`
- **CO-RE 使用指南**: `docs/CO-RE_Guide.md`
- **模块 ABI 规范**: `bpf/core/module_abi.h`

## 更多示例

```bash
# 验证多个内核版本编译的模块
for kver in 5.15 6.1 6.6; do
    echo "=== Kernel $kver ==="
    python3 tools/inspect_module.py build-$kver/bpf/vlan.bpf.o
done

# 批量验证客户模块包
for mod in customer-modules/*.bpf.o; do
    echo "Checking $mod..."
    python3 tools/inspect_module.py "$mod" || echo "FAILED: $mod"
done

# 导出模块信息为 JSON（用于自动化）
python3 tools/inspect_module.py build/bpf/vlan.bpf.o --json > vlan.json
```

---

**工具版本**: v1.0  
**支持的 ABI**: v1  
**兼容的内核**: Linux 5.8+
