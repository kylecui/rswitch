# 性能调优指南

本指南说明如何针对最大吞吐量、最低延迟或均衡生产负载分别调优rSwitch。

## NIC调优

### XDP模式选择XDP附加模式对性能影响最大：

| 模式 | 性能 | 兼容性 |
|------|------|--------|
| **Native** (`xdp`) | 最佳 — 驱动层处理 | i40e, mlx5, ice, ixgbe |
| **Generic** (`xdpgeneric`) | 慢3-5倍 — 经过网络栈 | 所有NIC |

> **重要**: 所有接口（包括 `mgmt-br`）必须使用相同的XDP模式，`BPF_F_BROADCAST` 重定向才能正常工作。

### NIC队列配置

```bash
# 查看当前队列数ethtool -l ens34

# 设置组合队列（匹配可用CPU数）
sudo ethtool -L ens34 combined 4
```

### IRQ亲和性

将NIC中断绑定到特定CPU，减少缓存抖动：

```bash
# 查找NIC的IRQ号grep ens34 /proc/interrupts

# 绑定到专用CPU
echo 1 | sudo tee /proc/irq/<irq_num>/smp_affinity

# 或使用辅助脚本sudo scripts/setup_nic_queues.sh ens34 4
```

### 环形缓冲区大小

```bash
# 增大以应对突发流量sudo ethtool -G ens34 rx 4096 tx 4096
```

### 卸载设置

```bash
# 必须禁用: 硬件VLAN剥离sudo ethtool -K ens34 rx-vlan-offload off

# 必须启用: 混杂模式sudo ip link set dev ens34 promisc on

# 可选: 禁用GRO/LRO（降低延迟）
sudo ethtool -K ens34 gro off lro off
```

## CPU和内存调优

### CPU隔离

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3"
```

将VOQd绑定到隔离的CPU：

```yaml
voqd_config:
 cpu_affinity: 2
```

### NUMA感知

多路系统上，NIC和CPU应在同一NUMA节点，否则跨节点内存访问会增加延迟：

```bash
# 检查NIC NUMA节点cat /sys/class/net/ens34/device/numa_node

# 绑定到匹配的NUMA节点sudo numactl --cpunodebind=0 --membind=0 ./build/rswitch_loader ...
```

### 大页内存

```bash
echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
echo "vm.nr_hugepages = 256" >> /etc/sysctl.d/99-rswitch.conf
```

## VOQd调优

### 模式选择

| 模式 | 吞吐量 | 延迟 | 使用场景 |
|------|--------|------|----------|
| BYPASS | 最大 | 最低 | 纯L2/L3转发，无需QoS |
| SHADOW | 最大 | 最低 | QoS监控，不影响流量 |
| ACTIVE | 高 | 较高 | 生产QoS优先级调度 |

### 环形缓冲区大小

| 工作负载 | rx/tx_ring | batch_size | poll_timeout_ms |
|----------|-----------|------------|-----------------|
| 低延迟 | 1024 | 64 | 10 |
| 均衡 | 2048 | 256 | 100 |
| 高吞吐 | 4096 | 512 | 500 |

### 优先级掩码

仅拦截需要QoS调度的流量优先级，其余走XDP快速路径：

```yaml
voqd_config:
 prio_mask: 0x0C # 仅HIGH (0x04) + CRITICAL (0x08)
```

`0x0C` 配置下大多数流量绕过AF_XDP，减少VOQd处理负载。

### 零拷贝AF_XDP支持的NIC（i40e, mlx5）可启用零拷贝以获得最大AF_XDP吞吐量：

```yaml
voqd_config:
 zero_copy: true
```

## 流水线优化

### 模块选择

每个模块增加处理开销，应仅加载所需模块：

| 配置 | 模块数 | 相对性能 |
|------|--------|---------|
| `dumb.yaml` | 最少 | 最快 |
| `l2.yaml` | L2转发 | 快 |
| `l3.yaml` | L3路由 + ACL | 中等 |
| `qos-voqd.yaml` | 完整QoS | 中等偏高 |
| `all-modules.yaml` | 全部加载 | 最慢（仅测试） |

## 基准测试

### 内置性能测试

```bash
make test-perf
```

参见 [性能测试](../development/Performance_Testing.md) 了解 `BPF_PROG_TEST_RUN` 基准测试详情。

### 外部工具

```bash
# iperf3吞吐量测试iperf3 -s # 接收端iperf3 -c <接收端IP> -t 30 -P 4 # 发送端（经过rSwitch）

# Prometheus指标（持续监控）
curl -s http://localhost:9417/metrics | grep rswitch_port
```

## 另请参阅

- [NIC配置](../deployment/NIC_Configuration.md) — NIC特定设置
- [VOQd设置](../deployment/VOQd_Setup.md) — QoS调度器配置
- [运维指南](Operations_Guide.md) — 容量规划和监控
- [性能测试](../development/Performance_Testing.md) — BPF_PROG_TEST_RUN基准测试
