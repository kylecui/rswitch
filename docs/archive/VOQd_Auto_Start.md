# VOQd 自动启动功能

## 概述

rSwitch loader 现在支持根据 YAML profile 配置自动启动 VOQd（用户空间调度器）。这简化了 QoS + VOQd 部署流程。

## YAML 配置

在 profile 文件中添加 `voqd_config` 节：

```yaml
# VOQd configuration (user-space data plane)
voqd_config:
  # Basic settings
  enabled: true         # Enable VOQd auto-start
  mode: active          # active/shadow/bypass
  num_ports: 4          # Number of ports
  prio_mask: 0x0C       # Which priorities to intercept (HIGH + CRITICAL)

  # AF_XDP data plane settings
  enable_afxdp: true
  zero_copy: false      # Use copy mode (more compatible)
  rx_ring_size: 2048
  tx_ring_size: 2048
  frame_size: 2048
  batch_size: 256
  poll_timeout_ms: 100
  busy_poll: false
  cpu_affinity: 2       # CPU core for VOQd threads

  # Scheduler settings
  enable_scheduler: true
```

## 使用方法

### 1. 启动 Loader（VOQd 自动启动）

```bash
# Loader 会根据 profile 配置自动启动 VOQd
sudo ./build/rswitch_loader \
     --profile etc/profiles/qos-voqd-test.yaml \
     --ifaces ens33,ens34,ens35,ens36 \
     --verbose
```

输出示例：
```
[... XDP 加载过程 ...]

Starting VOQd (user-space scheduler)...
  Command: ./build/rswitch-voqd -i ens33,ens34,ens35,ens36 -p 4 -m active -P 0x0c -s -S 10
  Mode: ACTIVE
  Priority Mask: 0x0c
  Ports: 4
  ✓ VOQd started (PID: 12345)
  ✓ Log: /tmp/rswitch-voqd.log

rSwitch running. Press Ctrl+C to exit.
```

### 2. 验证 VOQd 运行状态

```bash
# 快速验证
sudo ./tools/qos_verify.sh

# 实时监控
sudo ./tools/qos_monitor.sh
```

期望看到：
```
VOQd Mode: ACTIVE
VOQd Running: 1 (0=stopped, 1=running)
Priority Mask: 0x0c (intercept priorities)
Status: ✓ ACTIVE mode - VOQd handling high-priority flows
```

### 3. 停止（自动清理）

按 `Ctrl+C` 停止 loader，它会自动：
1. 发送 SIGTERM 给 VOQd（优雅停止）
2. 等待最多 5 秒
3. 如果仍在运行，发送 SIGKILL（强制停止）
4. 清理 XDP 程序和 BPF maps

输出示例：
```
^C
========== Cleanup Started ==========

Stopping VOQd (PID: 12345)...
  ✓ VOQd stopped gracefully

Detaching XDP programs:
  Detached from ens33 (ifindex=3)
  [...]
```

## VOQd 模式说明

### BYPASS 模式
- **行为**: 所有流量走 XDP fast-path，VOQd 不拦截
- **用途**: 故障安全模式，VOQd 崩溃时自动切换
- **性能**: 最高（纯 XDP）

### SHADOW 模式
- **行为**: VOQd 观察流量（ringbuf），但不拦截
- **用途**: 测试 VOQd 配置，零影响
- **性能**: 接近 BYPASS（仅 ringbuf 开销）

### ACTIVE 模式
- **行为**: 高优先级流量重定向到 VOQd（AF_XDP）
- **用途**: 生产环境，需要精细 QoS 控制
- **性能**: 高优先级走用户空间（DRR调度），低优先级走fast-path

## 手动启动 VOQd（不推荐）

如果需要手动控制 VOQd：

```bash
# 1. 在 YAML 中禁用自动启动
voqd_config:
  enabled: false

# 2. 启动 loader（不启动 VOQd）
sudo ./build/rswitch_loader --profile etc/profiles/qos-voqd-test.yaml --ifaces ens33,ens34

# 3. 在另一个终端手动启动 VOQd
sudo ./build/rswitch-voqd -i ens33,ens34 -p 2 -m active -P 0x0c -s -S 10
```

## 故障排查

### VOQd 启动失败

**问题**: `VOQd process exited prematurely`

**检查**:
```bash
# 查看 VOQd 日志
cat /tmp/rswitch-voqd.log

# 检查 VOQd 二进制是否存在
ls -la ./build/rswitch-voqd

# 手动测试 VOQd
sudo ./build/rswitch-voqd --help
```

**常见原因**:
1. VOQd 未编译：运行 `make` 重新编译
2. 接口不存在：检查 `--ifaces` 参数
3. 权限不足：需要 root
4. AF_XDP 不支持：内核太旧（需要 5.3+）

### VOQd 运行但不拦截流量

**检查状态**:
```bash
sudo bpftool map dump name voqd_state_map
```

**期望输出**:
```json
{
    "running": 1,        # VOQd alive
    "mode": 2,           # ACTIVE
    "prio_mask": 12      # 0x0C = HIGH + CRITICAL
}
```

**如果 running=0**:
- VOQd 进程已崩溃，检查 `/tmp/rswitch-voqd.log`
- 重启 loader 会自动重启 VOQd

**如果 mode=0 (BYPASS)**:
- VOQd 自动降级（可能检测到问题）
- 检查 `failover_count` 字段（自动切换次数）

### Profile 解析错误

**问题**: `Failed to load profile: voqd_config not found`

**解决**:
1. 确保 YAML 缩进正确（2 空格）
2. `voqd_config:` 后面的字段必须缩进
3. 字段名拼写正确（区分大小写）

**最小配置**:
```yaml
voqd_config:
  enabled: true
  mode: active
  prio_mask: 0x0C
```

## 高级配置

### CPU 亲和性

将 VOQd 绑定到特定 CPU：

```yaml
voqd_config:
  cpu_affinity: 2    # 运行在 CPU 2 上
```

这可以提高性能并减少上下文切换。

### 零拷贝模式（实验性）

```yaml
voqd_config:
  zero_copy: true
```

**注意**: 需要网卡驱动支持，且必须独占网卡队列。

### 自定义 Ring 大小

```yaml
voqd_config:
  rx_ring_size: 4096    # 增大接收队列
  tx_ring_size: 4096    # 增大发送队列
  batch_size: 512       # 增大批处理
```

**权衡**: 更大的 ring = 更高延迟但更好吞吐。

## 性能监控

### VOQd 统计

```bash
# 查看 VOQd 统计（如果启用了 -S 参数）
tail -f /tmp/rswitch-voqd.log
```

### BPF Map 统计

```bash
# 查看拦截统计
sudo bpftool map dump name afxdp_stats_map

# 查看 VOQ 深度
sudo bpftool map dump name voq_ringbuf
```

## 相关文档
 
 - [QoS 测试指南](QoS_Testing_Guide.md) - 完整 QoS 测试流程
 - [数据平面设计](../../../docs/data_plane_desgin_with_af_XDP.md) - VOQd 架构详解
 - [Profile 配置](../../etc/profiles/qos-voqd-test.yaml) - 完整配置示例
## 下一步

1. 运行 QoS 测试验证 VOQd 工作正常
2. 调整 `prio_mask` 确定哪些优先级需要精细控制
3. 监控性能，根据需要调整 ring 大小和批处理参数
4. 启用 telemetry 导出进行长期监控
