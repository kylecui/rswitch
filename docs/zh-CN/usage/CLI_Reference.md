> 📖 [English Version](../../usage/CLI_Reference.md)

# CLI参考

rSwitch提供了多个用于运行时管理和监控的命令行工具。所有工具都构建到 `build/` 目录中，并且需要root权限。

## rswitchctl

用于流水线 (pipeline) 管理和监控的主要控制工具。

### 流水线 (Pipeline)

```bash
# 显示活动的流水线（已加载的模块、阶段顺序）
sudo ./build/rswitchctl show-pipeline

# 显示每个端口和每个模块的统计信息
sudo ./build/rswitchctl show-stats
sudo ./build/rswitchctl stats [interface]
```

### MAC表

```bash
# 显示已学习的 MAC 地址
sudo ./build/rswitchctl mac-table

# 添加静态 MAC 条目
sudo ./build/rswitchctl mac-add <mac_address> <vlan_id> <interface>

# 删除 MAC 条目
sudo ./build/rswitchctl mac-del <mac_address> <vlan_id>
```

### 事件

```bash
# 显示来自事件总线 (event bus) 的事件
sudo ./build/rswitchctl show-events
```

## rsvlanctl

VLAN配置工具。

```bash
# 显示所有 VLAN 配置
sudo ./build/rsvlanctl show

# 添加 VLAN
sudo ./build/rsvlanctl add <vlan_id> [name]

# 删除 VLAN
sudo ./build/rsvlanctl del <vlan_id>

# 将端口添加到 VLAN
sudo ./build/rsvlanctl add-port <vlan_id> <interface> [tagged|untagged]

# 从 VLAN 中移除端口
sudo ./build/rsvlanctl del-port <vlan_id> <interface>
```

## rsaclctl

访问控制列表 (ACL) 管理工具。

```bash
# 显示所有 ACL 规则
sudo ./build/rsaclctl show

# 添加 ACL 规则
sudo ./build/rsaclctl add <priority> <match_expression> <action>

# 按优先级删除 ACL 规则
sudo ./build/rsaclctl del <priority>
```

### 匹配表达式示例

```bash
# 阻止来自子网的流量
sudo ./build/rsaclctl add 10 "src=10.0.0.0/8" drop

# 允许特定的目标端口
sudo ./build/rsaclctl add 20 "dst_port=80" permit

# 阻止特定的源 IP
sudo ./build/rsaclctl add 5 "src=192.168.1.100" drop
```

## rsqosctl

QoS配置和监控工具。

```bash
# 显示 QoS 统计信息
sudo ./build/rsqosctl stats

# 显示队列状态
sudo ./build/rsqosctl queues

# 设置端口优先级
sudo ./build/rsqosctl set-prio <interface> <priority>
```

## rsvoqctl

VOQd调度器控制工具。

```bash
# 显示 VOQd 状态
sudo ./build/rsvoqctl status

# 显示 VOQd 统计信息
sudo ./build/rsvoqctl stats
```

## rswitch_loader

主加载器二进制文件。通常不作为“工具”使用，而是运行rSwitch的入口点。

```bash
sudo ./build/rswitch_loader [options]
```

| 选项 | 描述 |
|--------|-------------|
| `--profile <path>` | YAML profile文件的路径 |
| `--ifaces <if1,if2,...>` | 逗号分隔的接口列表 |
| `--verbose` | 启用详细日志 |
| `--debug` | 启用调试级别日志 |
| `--xdp-mode <native\|generic>` | XDP挂载模式（默认：native） |
| `--detach` | 从接口分离XDP程序并退出 |

## rswitch-voqd

VOQd用户空间调度器。当profile中的 `voqd_config.enabled: true` 时，通常由加载器自动启动。

```bash
sudo ./build/rswitch-voqd [options]
```

| 选项 | 描述 |
|--------|-------------|
| `-i <interfaces>` | 逗号分隔的接口列表 |
| `-m <mode>` | VOQd模式：`bypass`, `shadow` 或 `active` |
| `-p <num_ports>` | 端口数量 |
| `-P <prio_mask>` | 优先级掩码（十六进制） |
| `-q` | 启用软件队列 |
| `-Q <depth>` | 软件队列深度 |
| `-s` | 启用调度器 |
| `-S <interval>` | 统计报告间隔（秒） |

## bpftool命令

对rSwitch检查有用的标准 `bpftool` 命令：

```bash
# 列出已加载的 BPF 程序
sudo bpftool prog list | grep rswitch

# 列出 BPF map
sudo bpftool map list | grep rs_

# 转储特定的已固定 map
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table
sudo bpftool map dump pinned /sys/fs/bpf/rs_port_config_map
sudo bpftool map dump pinned /sys/fs/bpf/rs_stats_map
sudo bpftool map dump pinned /sys/fs/bpf/rs_ctx_map

# 检查程序指令
sudo bpftool prog dump xlated pinned /sys/fs/bpf/rswitch_dispatcher

# 检查 VOQd 状态 map
sudo bpftool map dump name voqd_state_map
```

## 辅助脚本

位于 `scripts/` 目录：

| 脚本 | 描述 |
|--------|-------------|
| `rswitch_start.sh` | 启动加载器，并进行map就绪检查和启动VOQd |
| `rswitch_diag.sh` | 快速诊断（程序、map、接口） |
| `voqd_check.sh` | 验证VOQd就绪情况和状态 |
| `unpin_maps.sh` | 移除所有已固定的rSwitch map |
| `hot-reload.sh` | 在不完全重启的情况下热重载BPF模块 |
| `setup_nic_queues.sh` | 配置NIC IRQ亲和性和队列隔离 |

位于 `tools/` 目录：

| 脚本 | 描述 |
|--------|-------------|
| `tools/qos_verify.sh` | 快速QoS验证 |
| `tools/qos_monitor.sh` | 实时QoS监控 |
| `tools/scripts/all/disable_vlan_offload.sh` | 在接口上禁用硬件VLAN卸载 (offload) |
| `tools/scripts/all/promisc_switch.sh` | 在接口上启用混杂模式 |

## 另请参阅

- [如何使用](How_To_Use.md) — 使用工作流
- [故障排除](Troubleshooting.md) — 常见问题
- [VOQd设置](../deployment/VOQd_Setup.md) — VOQd部署指南
