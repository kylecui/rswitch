> 📖 [English Version](../../usage/How_To_Use.md)

# 如何使用 rSwitch

本指南涵盖了日常操作：启动、配置、监控和管理 rSwitch 实例。

## 工作流程概览

```
1. 构建        →  make vmlinux && make
2. 选择        →  选择一个 YAML profile
3. 配置        →  （可选）设置 NIC 队列、VLAN 卸载 (offload)
4. 启动        →  rswitch_loader --profile ... --ifaces ...
5. 验证        →  bpftool / CLI 工具
6. 操作        →  在运行时监控、调整 ACL/VLAN/QoS
7. 关闭        →  Ctrl+C 或 pkill，然后清理 map
```

## 1. 构建

```bash
cd rswitch/

# 首次：为 CO-RE 可移植性生成 vmlinux.h
make vmlinux

# 构建所有内容
make

# 清理并重新构建
make clean && make
```

所有二进制文件都输出到 `build/`。

## 2. 选择 Profile

Profile 是 `etc/profiles/` 中的 YAML 文件，定义了要加载哪些 BPF 模块以及如何配置端口、VLAN 和 QoS。有关完整详细信息，请参阅 [场景 Profile](Scenario_Profiles.md)。

```bash
# 列出可用的 profile
ls etc/profiles/

# 预览 profile
cat etc/profiles/l2-vlan.yaml
```

## 3. 启动前配置（可选）

### 禁用硬件 VLAN 卸载 (Offload)

如果你的 profile 使用 VLAN 处理，则必须执行此操作 —— 硬件 VLAN 卸载会在 XDP 看到它们之前剥离标签。

```bash
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens35 rx-vlan-offload off
# 或者使用辅助脚本：
sudo ./tools/scripts/all/disable_vlan_offload.sh ens34 ens35
```

> **注意**：rSwitch 加载器 v1.1+ 在挂载时会自动禁用 VLAN 卸载并启用混杂模式。只有旧版本或进行故障排除时才需要手动设置。

### 设置 NIC 队列

用于性能调优（IRQ 亲和性、队列隔离）：

```bash
sudo scripts/setup_nic_queues.sh ens34 2
```

有关详细信息，请参阅 [NIC 配置](../deployment/NIC_Configuration.md)。

## 4. 启动 rSwitch

### 基础启动

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l2.yaml \
    --ifaces ens34,ens35,ens36
```

### 使用详细日志

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l3-qos-voqd-test.yaml \
    --ifaces ens34,ens35 \
    --verbose
```

### 使用 Generic XDP（用于不支持的 NIC）

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l2.yaml \
    --ifaces ens34,ens35 \
    --xdp-mode generic
```

### 使用启动脚本

启动脚本处理 map 就绪检查和 VOQd 启动计时：

```bash
sudo scripts/rswitch_start.sh etc/profiles/l3-qos-voqd-test.yaml ens34,ens35
```

## 5. 验证运行情况

### 检查已加载的程序

```bash
sudo bpftool prog list | grep rswitch
```

预期输出显示调度器 (dispatcher) + 你的 profile 模块。

### 检查已固定的 map

```bash
sudo bpftool map show | grep rswitch
# 或者：
ls /sys/fs/bpf/ | grep rs_
```

预期的 map：`rs_ctx_map`, `rs_progs`, `rs_prog_chain`, `rs_port_config_map`, `rs_stats_map`, `rs_event_bus`, `rs_mac_table`, `rs_vlan_map`, `rs_xdp_devmap`。

### 检查 VOQd（如果是 QoS profile）

```bash
ps -ef | grep rswitch-voqd
sudo ./build/rsqosctl stats
```

### 流水线 (Pipeline) 检查

```bash
sudo ./build/rswitchctl show-pipeline
sudo ./build/rswitchctl show-stats
```

### 诊断脚本

```bash
sudo scripts/rswitch_diag.sh
sudo scripts/voqd_check.sh
```

## 6. 运行时操作

### 查看 MAC 表

```bash
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table
# 或者：
sudo ./build/rswitchctl mac-table
```

### 管理 VLAN

```bash
sudo ./build/rsvlanctl show
sudo ./build/rsvlanctl add 100 "Management"
sudo ./build/rsvlanctl add-port 100 ens34 tagged
```

### 管理 ACL

```bash
sudo ./build/rsaclctl show
sudo ./build/rsaclctl add 10 "src=10.0.0.0/8" drop
sudo ./build/rsaclctl del 10
```

### QoS 统计数据

```bash
sudo ./build/rsqosctl stats
sudo ./build/rsqosctl queues
```

### 查看事件

```bash
sudo bpftool map dump pinned /sys/fs/bpf/rs_event_bus
```

## 7. 热重载模块（开发）

修改 BPF 模块源文件后：

```bash
# 构建
make

# 重载模块
sudo scripts/hot-reload.sh reload my_module
```

## 8. 关闭和清理

### 优雅关闭

在加载器终端中按 `Ctrl+C`。加载器将：
1. 向 VOQd 发送 SIGTERM（如果正在运行）
2. 等待最多 5 秒以实现优雅停止
3. 从所有接口分离 XDP 程序
4. 清理 BPF map

### 手动关闭

```bash
sudo pkill rswitch_loader
# 如果 VOQd 正在单独运行：
sudo pkill rswitch-voqd
```

### 清理已固定的 map

```bash
sudo ./scripts/unpin_maps.sh
# 或者手动：
sudo rm -rf /sys/fs/bpf/rs_*
```

### 仅分离 XDP 程序

```bash
sudo ./build/rswitch_loader --detach --profile etc/profiles/l2.yaml
```

## 提示

- **等待 map**：启动后，在查询前留出 3–5 秒进行 map 初始化。
- **检查 VLAN 卸载**：如果 VLAN 流量不起作用，请使用 `ethtool -k <iface>` 验证 `rx-vlan-offload: off`。
- **使用 native XDP**：为了生产性能，优先使用 `--xdp-mode native`。仅在不支持的 NIC 或测试时使用 `generic`。
- **Profile 顺序很重要**：模块执行遵循 ELF 元数据中定义的阶段编号，而不是 YAML 列表顺序。

## 另请参阅

- [快速入门](Quick_Start.md) — 最小 5 分钟设置
- [场景 Profile](Scenario_Profiles.md) — profile 参考
- [CLI 参考](CLI_Reference.md) — 所有 CLI 命令
- [故障排除](Troubleshooting.md) — 常见问题
