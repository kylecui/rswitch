> 📖 [English Version](../../../CONTRIBUTING.md)
# 为rSwitch贡献代码

感谢您有兴趣为rSwitch贡献代码！本文档涵盖了构建、测试和提交更改的工作流程。

## 先决条件

- **Clang 16+** (推荐17或18)
- **libbpf** (从 `external/libbpf/src` 构建)
- **libelf**, **zlib** 开发头文件
- **Linux kernel 5.15+** (用于BPF_PROG_TEST_RUN和XDP特性)
- **bpftool** (用于vmlinux.h生成)

## 快速入门

```bash
git clone --recursive <repo-url>
cd rswitch

# 构建 libbpf
cd external/libbpf/src
make -j$(nproc)
sudo make install PREFIX=/usr/local/bpf
cd ../../../rswitch

# 构建一切
make all
```

## 构建

```bash
make all           # 构建所有 BPF 对象 + 用户态程序
make test          # 构建单元测试二进制文件
make test-ci       # 构建 CI BPF 测试二进制文件
make test-bpf      # 构建 + 运行 BPF_PROG_TEST_RUN 测试 (需要 root)
make fuzz          # 运行模糊测试 (需要 root)
make clean         # 移除构建产物
```

## 测试

### 单元测试（用户态）

```bash
make test
sudo ./test/unit/run_tests.sh
```

### BPF测试（需要root）

BPF测试使用 `BPF_PROG_TEST_RUN` 在内核中练习BPF程序，而无需附加到真实接口。

```bash
make test-bpf   # 构建并运行所有 BPF 测试
```

单个测试二进制文件：
```bash
sudo ./build/test_acl_bpf ./build/bpf/acl.bpf.o output.junit.xml
sudo ./build/test_dispatcher_bpf ./build/bpf/dispatcher.bpf.o output.junit.xml
```

### 集成测试

```bash
sudo bash ./test/integration/run_all.sh
```

## 代码风格

项目使用 `clang-format`，配置位于 `.clang-format`。
关键约定：

- **4空格缩进** (不使用tab)
- **K&R大括号风格** (Linux kernel风格)
- **100列限制**
- **`//` 注释** 在BPF代码中优先使用
- **指针对齐**：`int *ptr` (而非 `int* ptr`)

在commit之前格式化您的更改：
```bash
clang-format -i path/to/file.c
```

## Commit消息

我们使用语义化commit消息：

```
<type>(<scope>): <description>

[optional body]
```

类型：`feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`

示例：
```
feat(acl): add IPv6 source matching
fix(afxdp): correct map pin path for multi-queue
docs: update module development spec for egress stages
test(ci): add BPF_PROG_TEST_RUN tests for VLAN module
```

## Pull Request工作流

1. Fork仓库并从 `dev` 分支创建特性分支
2. 进行更改，遵循上述代码风格
3. 为您的更改添加或更新测试
4. 运行完整的测试套件 (`make test && make test-bpf`)
5. 使用语义化消息进行commit
6. 向 `dev` 分支发起PR

### PR检查清单

- [ ] `make all` 编译无警告
- [ ] `make test` 构建所有单元测试
- [ ] 新的BPF模块包含具有正确阶段/标志的 `RS_DECLARE_MODULE()`
- [ ] ABI更改根据 [ABI策略](../../development/ABI_POLICY.md) 增加 `module_abi.h` 中的版本
- [ ] 如果行为发生变化，已更新文档

## 模块开发

请参阅 [SDK快速入门](../../../sdk/docs/SDK_Quick_Start.md) 了解编写第一个模块的教程，以及 [模块开发规范](../../../sdk/docs/Module_Development_Spec.md) 了解完整的API参考。

### 关键文件

| 文件 | 用途 |
|------|---------|
| `sdk/include/rswitch_module.h` | 模块的顶层包含文件 |
| `sdk/include/rswitch_abi.h` | ABI struct和版本常量 |
| `sdk/include/rswitch_helpers.h` | BPF辅助宏和数据包解析器 |
| `sdk/include/rswitch_maps.h` | 核心BPF map定义 |
| `sdk/templates/simple_module.bpf.c` | 入门模板 |
| `sdk/Makefile.module` | 独立模块构建系统 |

## 报告问题

使用 [问题模板](../../../.github/ISSUE_TEMPLATE/) 进行错误报告和功能请求。

## 许可证

rSwitch采用LGPL-2.1-or-later许可。BPF内核程序使用GPL-2.0 SPDX标头（BPF辅助函数访问所需）。通过贡献代码，您同意您的贡献将根据相同的条款获得许可。
