# VOQd 设置

VOQd (Virtual Output Queue daemon) 是 rSwitch 的用户态 QoS 调度器，使用 AF_XDP 套接字进行高优先级流量处理，并支持 DRR/WFQ 调度。

## 概览

VOQd 提供三种运行模式：

| 模式 | 值 | 行为 | 使用场景 |
|------|-------|----------|----------|
| **BYPASS** | 0 | 所有流量使用 XDP 快速路径；VOQd 不拦截 | 故障安全模式，最大性能 |
| **SHADOW** | 1 | VOQd 通过 ringbuf 观察流量，不拦截 | 测试配置，零影响 |
| **ACTIVE** | 2 | 高优先级流量通过 AF_XDP 重定向到 VOQd | 生产环境 QoS，精细化调度 |

## 架构

```
Ingress → dispatcher → ... → afxdp_redirect (stage 85)
                                     │
                          ┌──────────┴──────────┐
                          │  Check prio_mask    │
                          │  & VOQd state       │
                          └──────────┬──────────┘
                               │            │
                     prio matched      prio not matched
                     mode=ACTIVE       (or mode=BYPASS)
                               │            │
                               ▼            ▼
                     ┌──────────────┐   XDP fast-path
                     │   AF_XDP     │   (normal pipeline)
                     │   socket     │
                     └──────┬───────┘
                            │
                     ┌──────▼───────┐
                     │    VOQd      │
                     │  scheduler   │
                     │  (DRR/WFQ)   │
                     └──────┬───────┘
                            │
                     ┌──────▼───────┐
                     │  TX via      │
                     │  AF_XDP      │
                     └──────────────┘
```

## 自动设置 (推荐)

当配置文件包含 `voqd_config` 且 `enabled: true` 时，加载器会自动启动 VOQd。

### 1. 创建 QoS 配置文件

使用现有的 QoS 配置文件或在你的配置文件中添加 `voqd_config`：

```yaml
name: "L3 with QoS"
version: "1.0"

ingress:
  - vlan
  - acl
  - route
  - afxdp_redirect    # Required for VOQd
  - l2learn
  - lastcall

egress:
  - egress_qos         # QoS enforcement
  - egress_vlan
  - egress_final

voqd_config:
  enabled: true
  mode: active
  num_ports: 4
  prio_mask: 0x0C       # Intercept HIGH (0x04) + CRITICAL (0x08)
  enable_afxdp: true
  zero_copy: false
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  enable_scheduler: true
  cpu_affinity: 2
```

### 2. 启动加载器

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/l3-qos-voqd-test.yaml \
    --ifaces ens33,ens34,ens35,ens36 \
    --verbose
```

预期输出：
```
[... XDP loading ...]

Starting VOQd (user-space scheduler)...
  Command: ./build/rswitch-voqd -i ens33,ens34,ens35,ens36 -p 4 -m active -P 0x0c -s -S 10
  Mode: ACTIVE
  Priority Mask: 0x0c
  Ports: 4
  ✓ VOQd started (PID: 12345)
  ✓ Log: /tmp/rswitch-voqd.log

rSwitch running. Press Ctrl+C to exit.
```

### 3. 验证

```bash
# 快速验证
sudo ./tools/qos_verify.sh

# 实时监控
sudo ./tools/qos_monitor.sh

# 检查 VOQd 状态 map
sudo bpftool map dump name voqd_state_map
```

预期状态：
```json
{
    "running": 1,
    "mode": 2,
    "prio_mask": 12
}
```

### 4. 关闭

按下 `Ctrl+C`。加载器会自动：
1. 向 VOQd 发送 SIGTERM (优雅停止)
2. 等待最多 5 秒
3. 如果仍在运行，发送 SIGKILL
4. 清理 XDP 程序和 BPF map

## 手动设置

如果你需要独立控制 VOQd (例如用于调试)：

### 1. 在配置文件中禁用自动启动

```yaml
voqd_config:
  enabled: false    # Loader won't start VOQd
```

### 2. 启动不带 VOQd 的加载器

```bash
sudo ./build/rswitch_loader \
    --profile etc/profiles/qos-voqd-test.yaml \
    --ifaces ens33,ens34
```

### 3. 单独启动 VOQd

```bash
sudo ./build/rswitch-voqd \
    -i ens33,ens34 \
    -p 2 \
    -m active \
    -P 0x0c \
    -s \
    -S 10
```

### VOQd CLI 标志

| 标志 | 描述 |
|------|-------------|
| `-i <interfaces>` | 以逗号分隔的接口列表 |
| `-m <mode>` | `bypass`, `shadow`, 或 `active` |
| `-p <num_ports>` | 端口数量 |
| `-P <prio_mask>` | 优先级位掩码 (十六进制) |
| `-q` | 启用软件队列 |
| `-Q <depth>` | 软件队列深度 |
| `-s` | 启用调度器 |
| `-S <interval>` | 统计报告间隔 (秒) |

## 配置调优

### CPU 亲和性

将 VOQd 绑定到专用 CPU 核心以减少上下文切换：

```yaml
voqd_config:
  cpu_affinity: 2    # Run on CPU 2
```

为了获得最佳效果，请选择未被网卡 IRQ 处理程序使用的 CPU 核心。

### Ring 大小

较大的 ring 会增加吞吐量，但会以延迟为代价：

```yaml
voqd_config:
  rx_ring_size: 4096    # Larger receive ring
  tx_ring_size: 4096    # Larger transmit ring
  batch_size: 512       # Larger batch processing
```

### 零拷贝模式 (实验性)

需要网卡驱动支持 (Intel i40e, Mellanox mlx5)：

```yaml
voqd_config:
  zero_copy: true
```

> 零拷贝模式需要独占网卡队列访问。请确保没有其他应用程序使用相同的队列。

### 软件队列

对于不支持硬件多队列的网卡：

```yaml
voqd_config:
  software_queues:
    enabled: true
    queue_depth: 1024
    num_priorities: 8
```

## 优先级掩码

`prio_mask` 位掩码控制哪些优先级级别被 VOQd 拦截：

| 位 | 优先级 | 典型用途 |
|-----|----------|-------------|
| 0x01 | 0 (尽力而为) | 后台流量 |
| 0x02 | 1 | 备用 |
| 0x04 | 2 (HIGH) | 重要流量 |
| 0x08 | 3 (CRITICAL) | 实时 / 控制 |
| 0x0C | 2+3 | 高 + 关键 (常用默认值) |
| 0xFF | 全部 | 所有优先级通过 VOQd |

## 监控

### VOQd 统计信息

```bash
# 如果启动时带有 -S 标志
tail -f /tmp/rswitch-voqd.log
```

### BPF Map 统计信息

```bash
# AF_XDP 重定向统计信息
sudo bpftool map dump name afxdp_stats_map

# VOQd 状态
sudo bpftool map dump name voqd_state_map

# QoS 统计信息
sudo ./build/rsqosctl stats
```

## 故障排除

### VOQd 启动失败

**检查日志**：
```bash
cat /tmp/rswitch-voqd.log
```

**常见原因**：
1. **二进制文件未构建**：运行 `make` 进行编译
2. **接口不存在**：验证接口名称
3. **权限不足**：必须以 root 身份运行
4. **不支持 AF_XDP**：内核太旧 (需要 5.3+) 或网卡不支持 XDP

### VOQd 正在运行但未拦截

**检查状态 map**：
```bash
sudo bpftool map dump name voqd_state_map
```

- `running=0` → VOQd 崩溃。检查日志并重启。
- `mode=0` (BYPASS) → 自动降级。检查 `failover_count` 以获取原因。
- `prio_mask=0` → 未选择优先级。检查配置文件配置。

### 状态转换

VOQd 可能会在模式之间自动转换：

| 转换 | 触发条件 | 恢复 |
|------------|---------|----------|
| ACTIVE → BYPASS | VOQd 心跳超时 | VOQd 重启时自动恢复 |
| ACTIVE → BYPASS | Ringbuf 溢出 | 负载降低时自动恢复 |
| 任意 → BYPASS | VOQd 进程崩溃 | 重启加载器以重启 VOQd |

## 另请参阅

- [配置](Configuration.md) — voqd_config 的 YAML 参考
- [网卡配置](NIC_Configuration.md) — 用于 AF_XDP 的网卡设置
- [故障排除](../usage/Troubleshooting.md) — 通用故障排除
- [架构](../development/Architecture.md) — 系统架构中的 VOQd
