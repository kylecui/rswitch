> 📖 [English Version](../../usage/Troubleshooting.md)

# 故障排除

运行rSwitch时常见的问题及解决方案。

## 模块加载

### "Failed to load module X" — BPF验证器 (Verifier) 拒绝

**现象**：加载器失败并显示验证器错误消息。

**诊断**：
```bash
sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml --verbose
dmesg | grep bpf
```

**常见原因**：
- 在访问数据包数据之前缺少边界检查
- BPF代码中存在无界循环
- 在没有进行空检查的情况下访问map值
- 当前内核上不提供CO-RE字段

**解决方案**：
- 查看验证器输出，找出导致拒绝的具体指令
- 添加边界检查：`if ((void *)(hdr + 1) > data_end) return XDP_DROP;`
- 使用偏移掩码：`offset & RS_L3_OFFSET_MASK`
- 检查空返回值：`if (!val) return XDP_DROP;`

### "Map not found" 或 "No such file" 错误

**现象**：访问 `/sys/fs/bpf/rs_*` map时出错。

**原因**：
- map尚未初始化（加载器仍在启动中）
- 之前的非正常关闭留下了陈旧的map

**解决方案**：
```bash
# 等待初始化（启动后 3–5 秒）
sleep 5 && ls /sys/fs/bpf/ | grep rs_

# 清理陈旧的 map 并重启
sudo rm -rf /sys/fs/bpf/rs_*
sudo ./build/rswitch_loader --profile etc/profiles/l2-simple-managed.yaml
```

### 模块ABI版本不匹配

**现象**：加载器报告 "incompatible module" 或ABI版本错误。

**解决方案**：
```bash
# 从干净状态重新构建所有内容
make clean && make
```

## VLAN问题

### VLAN流量未转发

**现象**：Trunk端口和Access端口之间的带标签流量不起作用。

**诊断**：
```bash
# 检查 VLAN 卸载 (offload)（必须为 OFF）
ethtool -k ens34 | grep rx-vlan-offload

# 检查 BPF 追踪以获取 VLAN 深度
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "vlan_depth"
```

如果本应带标签的流量显示 `vlan_depth=0`，则说明硬件VLAN卸载正在剥离标签。

**解决方案**：
```bash
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens35 rx-vlan-offload off
# 重启 rSwitch
```

### 未启用混杂模式

**现象**：仅接收目的地为NIC自身MAC的流量。

**诊断**：
```bash
ip link show ens34
# 在输出中查找 PROMISC 标志
```

**解决方案**：
```bash
sudo ip link set dev ens34 promisc on
```

> rSwitch加载器v1.1+会自动处理此问题。

## VOQd问题

### VOQd启动失败

**现象**：`VOQd process exited prematurely`

**诊断**：
```bash
# 检查 VOQd 日志
cat /tmp/rswitch-voqd.log

# 检查二进制文件是否存在
ls -la ./build/rswitch-voqd

# 手动测试 VOQd
sudo ./build/rswitch-voqd --help
```

**常见原因**：
1. VOQd二进制文件未编译 —— 运行 `make`
2. 接口不存在 —— 验证 `--ifaces` 参数
3. 权限不足 —— 使用 `sudo` 运行
4. 不支持AF_XDP —— 内核太旧（需要5.3+）

### VOQd正在运行但未拦截流量

**诊断**：
```bash
sudo bpftool map dump name voqd_state_map
```

预期输出：
```json
{
    "running": 1,
    "mode": 2,           // 2 = ACTIVE
    "prio_mask": 12       // 0x0C = HIGH + CRITICAL
}
```

**如果 `running=0`**：VOQd崩溃。检查 `/tmp/rswitch-voqd.log` 并重启。

**如果 `mode=0` (BYPASS)**：VOQd自动降级。检查 `failover_count` 和日志以了解原因。

### Profile YAML解析错误

**现象**：`Failed to load profile: voqd_config not found`

**解决方案**：
- 确保YAML缩进使用2个空格（而不是制表符）
- 检查字段名称拼写（区分大小写）
- 验证 `voqd_config:` 部分存在且缩进正确

最小有效VOQd配置：
```yaml
voqd_config:
  enabled: true
  mode: active
  prio_mask: 0x0C
```

## 性能问题

### 低吞吐量

**诊断**：
```bash
sudo ./build/rswitchctl show-stats
sudo ./build/rsqosctl stats
```

**常见原因**：
- XDP运行在generic模式（软件）而不是native模式（驱动程序）
- NIC不支持native XDP（例如Azure VM上的 `hv_netvsc`）
- 未配置CPU亲和性 —— 所有队列都在同一个核心上
- 流水线 (pipeline) 中有太多沉重的模块

**解决方案**：
- 验证XDP模式：使用 `--xdp-mode native`（需要支持的NIC）
- 配置CPU亲和性：`sudo scripts/setup_nic_queues.sh ens34 2`
- 减少流水线长度 —— 从profile中移除未使用的模块
- 对于VOQd：增加批处理大小和环 (ring) 大小

### 支持Native XDP的NIC

| NIC | 驱动程序 | Native XDP | AF_XDP零拷贝 (Zero-Copy) |
|-----|--------|-----------|------------------|
| Intel X710 | i40e | 是 | 是 |
| Mellanox CX-5 | mlx5 | 是 | 是 |
| VMware vmxnet3 | vmxnet3 | 是 | 否 |
| Hyper-V | hv_netvsc | 否 (仅限generic) | 否 |

## Map检查

### 转储任何rSwitch Map

```bash
# MAC 表
sudo bpftool map dump pinned /sys/fs/bpf/rs_mac_table

# 端口配置
sudo bpftool map dump pinned /sys/fs/bpf/rs_port_config_map

# 统计信息
sudo bpftool map dump pinned /sys/fs/bpf/rs_stats_map

# 上下文 (Context)（每个 CPU）
sudo bpftool map dump pinned /sys/fs/bpf/rs_ctx_map
```

### 列出所有rSwitch资源

```bash
# 程序
sudo bpftool prog list | grep rswitch

# Map
sudo bpftool map list | grep rs_

# 已固定的路径
ls /sys/fs/bpf/ | grep rs_
```

## 构建问题

### vmlinux.h生成失败

**错误**：`bpftool not found`

```bash
sudo apt install linux-tools-$(uname -r)
# 或者指定 bpftool 路径：
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### BTF不可用

**错误**：`/sys/kernel/btf/vmlinux not found`

你的内核未启用BTF。选项：
- 升级到启用了 `CONFIG_DEBUG_INFO_BTF=y` 的内核
- 使用发行版内核5.8+（大多数现代发行版都启用了BTF）

### 编译错误（vmlinux.h冲突）

**错误**：`typedef redefinition with different types`

这通常意味着系统头文件和vmlinux.h发生冲突。BPF程序应该只包含 `rswitch_bpf.h`（其中包含vmlinux.h），而不是系统头文件，如 `<linux/if_ether.h>`。

## 清理

### 完全重置

```bash
# 停止所有内容
sudo pkill rswitch_loader
sudo pkill rswitch-voqd

# 移除所有已固定的 map
sudo rm -rf /sys/fs/bpf/rs_*

# 验证清理情况
ls /sys/fs/bpf/ | grep rs_    # 应该返回空
sudo bpftool prog list | grep rswitch  # 应该返回空
```

## 获取帮助

- 检查加载器详细输出：`--verbose` 或 `--debug` 标志
- 检查内核日志：`dmesg | tail -50`
- 检查VOQd日志：`cat /tmp/rswitch-voqd.log`
- 运行诊断：`sudo scripts/rswitch_diag.sh`
- 查看 [架构](../development/Architecture.md) 以了解流水线 (pipeline)

## 另请参阅

- [快速入门](Quick_Start.md) — 基础设置
- [NIC配置](../deployment/NIC_Configuration.md) — NIC特定要求
- [VOQd故障排除](Troubleshooting.md) — VOQd故障排除
