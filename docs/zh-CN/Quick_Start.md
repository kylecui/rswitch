# 快速开始

> 5 分钟内构建并运行 rSwitch。

## 前置条件

- Linux 内核 5.8+，支持 BTF（`/sys/kernel/btf/vmlinux` 必须存在）
- Root / sudo 访问权限
- 构建工具：`build-essential`、`cmake`、`clang`、`llvm`、`pkg-config`
- 库：`libxdp-dev`、`libbpf-dev`、`linux-headers-$(uname -r)`
- 至少 2 个网络接口用于交换

> 详细安装步骤请参阅 [安装指南](Installation.md)。

## 构建

```bash
cd rswitch/
make vmlinux   # 生成 vmlinux.h 用于 CO-RE（仅首次）
make
```

二进制文件输出到 `build/`：
- `rswitch_loader` — 主加载器
- `rswitch-voqd` — QoS 调度器
- `rswitchctl`、`rsvlanctl`、`rsaclctl`、`rsqosctl` — CLI 工具

## 选择配置文件

配置文件定义运行哪些模块及其顺序。它们位于 `etc/profiles/`：

```bash
ls etc/profiles/
```

常用起点：

| 配置文件 | 描述 |
|---------|------|
| `dumb.yaml` | 简单泛洪交换机（无学习） |
| `l2.yaml` | 带 VLAN 支持的二层学习交换机 |
| `l3.yaml` | 带基本 ACL 的三层路由 |
| `firewall.yaml` | 安全为主，带有序 ACL |

## 运行

```bash
# 设置配置文件和接口
PROFILE=etc/profiles/l2.yaml
INTERFACES=ens34,ens35,ens36

# 启动 rSwitch
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces $INTERFACES
```

> **提示**：如果在读取映射时看到"No such file"错误，请等待 3-5 秒让初始化完成，或使用 `scripts/rswitch_start.sh` 自动处理时序。

## 验证

```bash
# 检查已加载的 BPF 程序
sudo bpftool prog list | grep rswitch

# 检查固定的映射
sudo bpftool map show | grep rswitch
ls /sys/fs/bpf/ | grep rs_

# 如果使用 QoS 配置文件，检查 VOQd
ps -ef | grep rswitch-voqd
```

## 清理

```bash
# 停止 rSwitch（在加载器终端按 Ctrl+C，或：）
sudo pkill rswitch_loader

# 移除固定的映射
sudo rm -rf /sys/fs/bpf/rs_*
# 或使用取消固定脚本：
sudo ./scripts/unpin_maps.sh
```

## 加载器参数

| 参数 | 描述 |
|------|------|
| `--profile <path>` | YAML 配置文件 |
| `--ifaces <if1,if2>` | 逗号分隔的接口列表 |
| `--verbose` | 详细日志 |
| `--debug` | 调试级别日志 |
| `--xdp-mode <mode>` | `native` 或 `generic`（默认：native） |
| `--detach` | 分离 XDP 程序并退出 |

## 下一步

- [使用方法](How_To_Use.md) — 完整使用指南
- [场景配置](Scenario_Profiles.md) — 所有可用配置文件说明
- [CLI 参考](CLI_Reference.md) — CLI 工具命令
- [故障排除](Troubleshooting.md) — 常见问题和解决方案

---

*最后更新: 2026-03-17*
