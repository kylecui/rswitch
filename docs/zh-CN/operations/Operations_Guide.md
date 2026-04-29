# 运维指南rSwitch生产环境日常运维操作参考。

## 日常健康检查

### 快速状态检查

```bash
# 服务状态sudo systemctl status rswitch rswitch-mgmtd rswitch-voqd

# BPF流水线加载确认ls /sys/fs/bpf/rs_* | head -5

# 端口统计（确认数据转发正常）
sudo ./build/rswitchctl show-stats

# VOQd状态（启用QoS时）
sudo bpftool map dump name voqd_state_map
```

### 自动化健康检查脚本

```bash
#!/bin/bash
# /opt/rswitch/scripts/health-check.sh
set -euo pipefail

ERRORS=0

# 检查核心服务if ! systemctl is-active --quiet rswitch; then
 echo "严重: rswitch.service未运行"
 ERRORS=$((ERRORS + 1))
fi

# 检查BPF maps是否已挂载if [ ! -e /sys/fs/bpf/rs_ctx_map ]; then
 echo "严重: BPF流水线未加载 (rs_ctx_map不存在)"
 ERRORS=$((ERRORS + 1))
fi

# 检查管理门户（如已启用）
if systemctl is-enabled --quiet rswitch-mgmtd 2>/dev/null; then
 if ! systemctl is-active --quiet rswitch-mgmtd; then
 echo "警告: rswitch-mgmtd未运行"
 ERRORS=$((ERRORS + 1))
 fi
fi

if [ $ERRORS -eq 0 ]; then
 echo "正常: 所有检查通过"
fi
exit $ERRORS
```

## 日志管理

### Journal日志rSwitch服务日志写入systemd journal：

```bash
# 实时跟踪所有rSwitch日志sudo journalctl -u 'rswitch*' -f

# 最近一小时，指定服务sudo journalctl -u rswitch --since "1 hour ago"

# 仅错误sudo journalctl -u rswitch -p err
```

### VOQd日志文件VOQd以 `-S <间隔>` 参数启动时，统计信息写入 `/tmp/rswitch-voqd.log`：

```bash
tail -f /tmp/rswitch-voqd.log
```

配置日志轮转：

```bash
# /etc/logrotate.d/rswitch-voqd
/tmp/rswitch-voqd.log {
 daily
 rotate 7
 compress
 missingok
 notifempty
}
```

### Journal保留策略

```bash
# /etc/systemd/journald.conf
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=30d
```

## 备份与恢复

### 需要备份的内容

| 项目 | 路径 | 频率 |
|------|------|------|
| 配置文件 | `/opt/rswitch/etc/profiles/` 或 `/etc/rswitch/` | 变更时 |
| 环境文件 | `/etc/rswitch/rswitch.env` | 变更时 |
| Systemd服务文件 | `/etc/systemd/system/rswitch*.service` | 变更时 |
| Prometheus告警规则 | Prometheus配置目录 | 变更时 |
| Grafana仪表盘 | `/etc/grafana/provisioning/dashboards/rswitch/` | 变更时 |

> **注意**: BPF maps (`/sys/fs/bpf/rs_*`) 为临时性数据，每次启动时重新创建，无需备份。

### 恢复步骤1. 重新安装rSwitch二进制文件（参见[安装指南](../deployment/Installation.md)）
2. 恢复配置文件到 `/opt/rswitch/etc/profiles/`
3. 恢复systemd服务文件并执行 `daemon-reload`
4. 启动服务: `sudo systemctl start rswitch`
5. 验证流水线: `sudo ./build/rswitchctl show-pipeline`

## 升级流程

### 原地升级

```bash
# 1. 构建新版本cd /path/to/rswitch-source
git pull
make clean && make vmlinux && make

# 2. 停止服务sudo systemctl stop rswitch

# 3. 部署新二进制文件sudo cp -a build/ /opt/rswitch/build/

# 4. 比较配置变更（新版本可能新增字段）
diff /opt/rswitch/etc/profiles/ etc/profiles/

# 5. 启动服务sudo systemctl start rswitch

# 6. 验证sudo systemctl status rswitch
sudo ./build/rswitchctl show-pipeline
```

### 热重载（仅模块更新）

模块可在不停止服务的情况下单独更新：

```bash
sudo ./scripts/hot-reload.sh reload <模块名>
```

热重载通过原子 `prog_array` 替换实现 — 无需卸载XDP程序，零丢包。参见 [热重载](../development/Hot_Reload.md)。

## 容量规划

### 资源需求

| 资源 | 建议 |
|------|------|
| **CPU** | 每10 Gbps吞吐量1个核心（XDP native模式）；VOQd需要1个专用核心 |
| **内存** | 基础约200 MB + BPF map内存 |
| **锁定内存** | `LimitMEMLOCK=infinity`（systemd）或 `ulimit -l unlimited` |
| **内核** | 5.8+（管理门户需要5.15+） |

### 扩展限制

| 参数 | 默认值 | 已测试最大值 |
|------|--------|-------------|
| 接口数 | — | 256 (RS_MAX_INTERFACES) |
| VLAN数 | — | 4094 |
| ACL规则数 | — | 10,000+ |
| MAC表条目 | 8,192 | 65,536 |

## 告警与监控

### Prometheus导出器

```bash
# 启动导出器sudo rswitch-prometheus --port 9417

# 验证指标curl -s http://localhost:9417/metrics | head -20
```

### 关键监控指标

| 指标 | 含义 |
|------|------|
| `rswitch_uptime_seconds` | 服务稳定性 — 重置表示重启 |
| `rswitch_port_drop_packets_total` | 丢包 — 非零需排查 |
| `rswitch_module_packets_dropped_total` | 哪个模块在丢包 |
| `rswitch_voqd_mode` | VOQd运行状态 |
| `rswitch_mac_table_entries` | MAC表增长 — 溢出前告警 |

### Grafana仪表盘

`monitoring/grafana/` 中有四个预构建仪表盘：概览、QoS、安全、VLAN。

## 灾难恢复

### 完全故障（服务无法启动）

```bash
# 1. 查看错误日志sudo journalctl -u rswitch -n 50 --no-pager

# 2. 清理残留BPF maps
sudo rm -rf /sys/fs/bpf/rs_*

# 3. 验证NIC状态for iface in ens34 ens35 ens36; do
 ethtool -k $iface | grep rx-vlan-offload
done

# 4. 使用最小配置尝试启动sudo /opt/rswitch/build/rswitch_loader \
 --profile /opt/rswitch/etc/profiles/dumb.yaml \
 --ifaces ens34,ens35 --verbose
```

### 网络连接丢失rSwitch配置错误导致网络中断时，按以下步骤恢复：

```bash
# 1. 停止rSwitch（移除XDP程序）
sudo systemctl stop rswitch

# 2. 清理挂载的maps
sudo rm -rf /sys/fs/bpf/rs_*

# 3. 验证NIC恢复正常Linux网络栈ip link show
ping <网关>
```

## 计划维护

### 维护窗口流程

```bash
# 1. 静默告警
# 2. 优雅停止sudo systemctl stop rswitch
# 3. 执行维护（内核更新、NIC固件等）
# 4. 启动rSwitch
sudo systemctl start rswitch
# 5. 验证sudo ./build/rswitchctl show-stats
# 6. 取消告警静默
```

## 另请参阅

- [Systemd集成](../deployment/Systemd_Integration.md) — 服务配置
- [故障排除](../usage/Troubleshooting.md) — 诊断流程
- [性能调优](Performance_Tuning.md) — 优化指南
- [监控设置](../../monitoring/README.md) — Prometheus和Grafana
