> 📖 [English Version](../../usage/Quick_Start.md)

# 快速入门

在 5 分钟内运行 rSwitch。

## 前置条件

- Linux kernel 5.8+，支持 BTF（必须存在 `/sys/kernel/btf/vmlinux`）
- Root / sudo 权限
- 构建工具：`build-essential`, `cmake`, `clang`, `llvm`, `pkg-config`
- 库：`libxdp-dev`, `libbpf-dev`, `linux-headers-$(uname -r)`
- 至少 2 个用于交换的网络接口

> 有关详细的安装步骤，请参阅 [安装](../deployment/Installation.md)。

## 构建

```bash
cd rswitch/
make vmlinux   # 为 CO-RE 生成 vmlinux.h（仅限首次）
make
```

二进制文件位于 `build/` 目录中：
- `rswitch_loader` — 主加载器
- `rswitch-voqd` — QoS 调度器
- `rswitchctl`, `rsvlanctl`, `rsaclctl`, `rsqosctl` — CLI 工具

## 选择 Profile

Profile 定义了运行哪些模块以及运行顺序。它们位于 `etc/profiles/` 目录中：

```bash
ls etc/profiles/
```

常用的起点：

| Profile | 描述 |
|---------|-------------|
| `dumb.yaml` | 简单的泛洪交换机（无学习功能） |
| `l2.yaml` | 支持 VLAN 的 L2 学习型交换机 |
| `l3.yaml` | 带有基础 ACL 的 L3 路由 |
| `firewall.yaml` | 以安全为中心，带有有序 ACL |

## 运行

```bash
# 设置你的 Profile 和接口
PROFILE=etc/profiles/l2.yaml
INTERFACES=ens34,ens35,ens36

# 启动 rSwitch
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces $INTERFACES
```

> **提示**：如果在读取 map 时看到 "No such file" 错误，请等待 3–5 秒进行初始化，或者使用自动处理计时的 `scripts/rswitch_start.sh`。

## 验证

```bash
# 检查已加载的 BPF 程序
sudo bpftool prog list | grep rswitch

# 检查已固定的 map
sudo bpftool map show | grep rswitch
ls /sys/fs/bpf/ | grep rs_

# 如果使用 QoS profile，请检查 VOQd
ps -ef | grep rswitch-voqd
```

## 清理

```bash
# 停止 rSwitch（在加载器终端中按 Ctrl+C，或者）：
sudo pkill rswitch_loader

# 移除已固定的 map
sudo rm -rf /sys/fs/bpf/rs_*
# 或者使用 unpin 脚本：
sudo ./scripts/unpin_maps.sh
```

## 加载器标志

| 标志 | 描述 |
|------|-------------|
| `--profile <path>` | YAML profile 文件 |
| `--ifaces <if1,if2>` | 逗号分隔的接口列表 |
| `--verbose` | 详细日志 |
| `--debug` | 调试级别日志 |
| `--xdp-mode <mode>` | `native` 或 `generic`（默认：native） |
| `--detach` | 分离 XDP 程序并退出 |

## 后续步骤

- [如何使用](How_To_Use.md) — 全面的使用指南
- [场景 Profile](Scenario_Profiles.md) — 所有可用 profile 的说明
- [CLI 参考](CLI_Reference.md) — CLI 工具命令
- [故障排除](Troubleshooting.md) — 常见问题及解决方案
