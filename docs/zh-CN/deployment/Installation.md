> 📖 [English Version](../../deployment/Installation.md)

# 安装

从源码构建rSwitch的完整指南。

## 系统要求

### 操作系统

- Linux内核5.8或更高版本
- 已启用BTF支持 (`CONFIG_DEBUG_INFO_BTF=y`)
- 已验证：Ubuntu 22.04+、Debian 12+

### 硬件

- x86_64架构
- 至少2个用于交换的网络接口
- 推荐：Intel X710 (i40e) 或Mellanox CX-5 (mlx5) 以支持原生XDP

### 内核验证

```bash
# 检查内核版本（需要 5.8+）
uname -r

# 检查 BTF 支持（CO-RE 所需）
ls /sys/kernel/btf/vmlinux

# 检查 XDP 支持
grep -i xdp /boot/config-$(uname -r) 2>/dev/null || zcat /proc/config.gz 2>/dev/null | grep -i xdp
```

## 安装依赖

### Ubuntu / Debian

```bash
# 构建基础工具
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    clang \
    llvm \
    pkg-config

# BPF 库
sudo apt install -y \
    libxdp-dev \
    libbpf-dev

# 内核头文件（用于生成 vmlinux.h）
sudo apt install -y \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r)

# 可选：用于 NIC 配置
sudo apt install -y ethtool
```

### Fedora / RHEL

```bash
sudo dnf install -y \
    gcc \
    make \
    cmake \
    clang \
    llvm \
    pkg-config \
    libxdp-devel \
    libbpf-devel \
    kernel-devel \
    bpftool \
    ethtool
```

### 验证工具版本

```bash
clang --version    # 需要 10+
llvm-strip --version
bpftool --version  # 需要 5.8+
pkg-config --modversion libbpf  # 需要 0.6+
```

## 克隆与构建

### 克隆仓库

```bash
git clone --recurse-submodules <repo-url>
cd rSwitch/rswitch
```

如果你在克隆时没有包含子模块：
```bash
git submodule update --init --recursive
```

如果你的系统版本太旧，`external/libbpf` 子模块提供了一个自备的libbpf。

### 构建

```bash
cd rswitch/

# 步骤 1：生成 vmlinux.h（仅限首次，或在内核升级后）
make vmlinux

# 步骤 2：构建所有内容
make
```

### 构建输出

二进制文件（Binaries）位于 `build/`：

| 二进制文件 | 描述 |
|--------|-------------|
| `rswitch_loader` | 主loader — 加载BPF modules，管理pipeline |
| `rswitch-voqd` | VOQd用户空间QoS调度器 |
| `rswitchctl` | Pipeline管理和监控 |
| `rsvlanctl` | VLAN配置 |
| `rsaclctl` | ACL管理 |
| `rsqosctl` | QoS监控 |

BPF object files位于 `build/bpf/`：

| 对象 | 描述 |
|--------|-------------|
| `dispatcher.bpf.o` | XDP ingress入口点 |
| `egress.bpf.o` | Devmap egress回调 |
| `vlan.bpf.o` | VLAN处理module |
| `acl.bpf.o` | ACL module |
| `l2learn.bpf.o` | MAC学习module |
| `lastcall.bpf.o` | 最终转发module |
| `*.bpf.o` | 其他modules |

### 清理构建

```bash
make clean && make
```

## 验证安装

```bash
# 快速测试：使用简单的 profile 加载
sudo ./build/rswitch_loader \
    --profile etc/profiles/dumb.yaml \
    --ifaces ens34,ens35

# 检查是否已加载
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rswitch

# 停止
# 在 loader 终端按 Ctrl+C
```

## 跨内核部署

得益于CO-RE，编译后的BPF objects可以在不同的内核版本上运行而无需重新编译：

```bash
# 在开发机上构建
make vmlinux && make

# 将二进制文件复制到目标机
scp -r build/ target:/opt/rswitch/
scp -r etc/profiles/ target:/opt/rswitch/etc/profiles/

# 在目标机上运行（不需要构建工具，只需要 libbpf）
ssh target "cd /opt/rswitch && sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml --ifaces eth0,eth1"
```

**目标机要求**：
- Linux内核5.8+ 并带有BTF (`/sys/kernel/btf/vmlinux`)
- libbpf运行时库
- Root权限

## 故障排除构建问题

### vmlinux.h生成失败

```
bpftool: command not found
```

```bash
sudo apt install linux-tools-$(uname -r)
# 或指定路径：
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### 缺失BTF

```
/sys/kernel/btf/vmlinux: No such file or directory
```

你的内核没有启用BTF。请升级到启用了 `CONFIG_DEBUG_INFO_BTF=y` 的内核（大多数现代发行版中的标准配置）。

### libbpf版本太旧

```
undefined reference to 'bpf_object__open_file'
```

使用自备的libbpf：
```bash
cd external/libbpf/src
make
make install PREFIX=/usr/local
ldconfig
```

### clang太旧

```
error: unknown argument: '-mcpu=v3'
```

将clang升级到10或更高版本：
```bash
sudo apt install clang-14
export CC=clang-14
make
```

## 目录结构

```
rswitch/
├── bpf/
│   ├── include/         # BPF 头文件 (rswitch_bpf.h, vmlinux.h)
│   ├── core/            # 核心 BPF 程序 (dispatcher, egress, module_abi)
│   └── modules/         # BPF modules (vlan, acl, l2learn, etc.)
├── user/
│   ├── loader/          # rswitch_loader 源码
│   ├── voqd/            # VOQd 调度器源码
│   └── tools/           # CLI 工具源码
├── etc/
│   └── profiles/        # YAML profile 文件
├── scripts/             # 辅助脚本
├── test/                # 测试
├── docs/                # 文档
├── external/
│   └── libbpf/          # 自备 libbpf (git submodule)
├── build/               # 构建输出 (binaries, BPF objects)
└── Makefile
```

## 下一步

- [快速入门](../../usage/Quick_Start.md) — 5分钟内运行
- [NIC配置](NIC_Configuration.md) — 特定硬件设置
- [配置](Configuration.md) — YAML profile参考
- [Systemd集成](Systemd_Integration.md) — 生产服务设置
