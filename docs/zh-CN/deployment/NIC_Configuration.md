# 网卡配置

rSwitch 运行在 XDP 层，该层在数据包到达 Linux 网络栈之前的网卡驱动中运行。这需要特定的网卡配置。

## 关键要求

### 1. 禁用硬件 VLAN 卸载 (VLAN Offload)

现代网卡会在 XDP 程序看到 VLAN 标签之前在硬件中将其剥离。这会**破坏** rSwitch 的 VLAN 处理。

**检查状态**：
```bash
ethtool -k <interface> | grep rx-vlan-offload
```

**禁用** (每个接口都需要)：
```bash
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens35 rx-vlan-offload off
sudo ethtool -K ens36 rx-vlan-offload off
```

**或使用辅助脚本**：
```bash
sudo ./tools/scripts/all/disable_vlan_offload.sh ens34 ens35 ens36
```

### 2. 启用混杂模式 (Promiscuous Mode)

交换机运行需要接收网络段上的**所有**数据包，而不仅仅是发送到网卡自身 MAC 地址的数据包。

```bash
sudo ip link set dev ens34 promisc on
sudo ip link set dev ens35 promisc on
sudo ip link set dev ens36 promisc on
```

> **注意**：rSwitch 加载器 v1.1+ 在挂载 XDP 程序时会自动应用这两个设置。只有在旧版本或进行故障排除时才需要手动配置。

## 网卡兼容性

### 支持的网卡

| 网卡 | 驱动 | 原生 XDP | AF_XDP 零拷贝 | 备注 |
|-----|--------|-----------|------------------|-------|
| Intel X710 | i40e | 是 | 是 | 推荐用于生产环境 |
| Intel X520/X540 | ixgbe | 是 | 是 | 较旧但支持良好 |
| Mellanox CX-5 | mlx5 | 是 | 是 | 推荐用于生产环境 |
| Intel E810 | ice | 是 | 是 | 最新的 Intel XDP 支持 |
| Broadcom | bnxt_en | 是 | 有限 | 检查驱动版本 |
| VMware | vmxnet3 | 是 | 否 | 实验室/测试使用 |
| Hyper-V | hv_netvsc | **仅通用模式** | 否 | 性能显著降低 |
| Realtek | r8169 | 有限 | 否 | 某些型号不支持禁用 VLAN 卸载 |

### 检查你的网卡

```bash
# 检查驱动
ethtool -i ens34 | grep driver

# 检查是否可以禁用 VLAN 卸载 (查找 [fixed])
ethtool -k ens34 | grep "rx-vlan-offload:"
# 如果显示 [fixed]，则无法更改该设置

# 检查 XDP 支持
ip link set dev ens34 xdp obj /dev/null 2>&1
# 预期结果为 "No such file"；如果显示 "not supported" 则表示不支持 XDP
```

## 验证

### VLAN 卸载

```bash
ethtool -k ens34 | grep -i vlan
```

预期结果：
```
rx-vlan-offload: off        ← 必须为 OFF
tx-vlan-offload: on [fixed]
rx-vlan-filter: on [fixed]
```

### 混杂模式

```bash
ip link show ens34
```

预期结果 (查找 `PROMISC`)：
```
3: ens34: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> ...
```

### VLAN 标签可见性

加载 rSwitch 后，检查 VLAN 标签是否可见：

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "vlan_depth"
```

带标签的流量应显示 `vlan_depth=1`：
```
[rSwitch] Packet received on ifindex 3, vlan_depth=1, vlan_id=10
```

如果你对本应带标签的流量 (已通过 Wireshark 验证) 看到 `vlan_depth=0`，则说明 VLAN 卸载仍处于启用状态。

## 队列配置

### IRQ 亲和性和队列隔离

为了获得最佳性能，请隔离网卡队列并设置 CPU 亲和性：

```bash
# 配置网卡队列 (接口, 队列数量)
sudo scripts/setup_nic_queues.sh ens34 2
```

该脚本会：
1. 设置合并队列的数量
2. 配置 IRQ 亲和性以分散到各个 CPU
3. 隔离用于 XDP 处理的队列

### 手动队列设置

```bash
# 设置队列数量
sudo ethtool -L ens34 combined 4

# 为每个队列设置 IRQ 亲和性
# 查找 IRQ 编号
grep ens34 /proc/interrupts

# 设置亲和性 (例如，队列 0 → CPU 0)
echo 1 | sudo tee /proc/irq/<irq_num>/smp_affinity
```

## 重启后持久化

加载器的自动配置**不是持久的**。对于生产环境，请在启动时进行配置。

### 使用 systemd (推荐)

创建 `/etc/systemd/system/rswitch-nic.service`：

```ini
[Unit]
Description=rSwitch NIC Configuration
Before=rswitch.service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -K ens34 rx-vlan-offload off
ExecStart=/usr/sbin/ethtool -K ens35 rx-vlan-offload off
ExecStart=/usr/sbin/ethtool -K ens36 rx-vlan-offload off
ExecStart=/usr/sbin/ip link set dev ens34 promisc on
ExecStart=/usr/sbin/ip link set dev ens35 promisc on
ExecStart=/usr/sbin/ip link set dev ens36 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

启用：
```bash
sudo systemctl enable rswitch-nic.service
```

### 使用 udev 规则

对于在重启和热插拔后仍能保持的特定接口配置：

```bash
# /etc/udev/rules.d/99-rswitch-nic.rules
ACTION=="add", SUBSYSTEM=="net", KERNEL=="ens34", RUN+="/usr/sbin/ethtool -K %k rx-vlan-offload off"
ACTION=="add", SUBSYSTEM=="net", KERNEL=="ens34", RUN+="/usr/sbin/ip link set dev %k promisc on"
```

## 故障排除

### VLAN 流量无法正常工作

**症状**：VLAN 10 流量无法在 trunk 端口和 access 端口之间转发。

**诊断**：
1. 物理链路上的 Wireshark 显示 VLAN 10 标签 → 硬件看到了标签
2. BPF 追踪显示 `vlan_depth=0` → XDP 未看到标签
3. 结论：硬件 VLAN 卸载正在剥离标签

**修复**：
```bash
sudo ethtool -K ens34 rx-vlan-offload off
# 重启 rSwitch
```

### 加载器警告消息

```
Warning: Failed to disable VLAN offload on ens34
Warning: Failed to enable promiscuous mode on ens35
```

**原因**：
- `ethtool` 或 `ip` 不在 PATH 中
- 未以 root 身份运行
- 网卡驱动不支持该操作 (`[fixed]` 标志)

**修复**：
- 使用 `sudo` 运行加载器
- 安装 `ethtool`：`sudo apt install ethtool`
- 对于网卡限制，请在启动 rSwitch 之前手动配置

## 另请参阅

- [安装](Installation.md) — 从源码构建
- [VOQd 设置](VOQd_Setup.md) — AF_XDP 要求
- [故障排除](../usage/Troubleshooting.md) — 通用故障排除
