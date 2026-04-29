# Framework Guide / 框架使用指南

> A practical guide to using the rSwitch reconfigurable network platform.
>
> rSwitch可重构网络平台的实用指南。

---

## Table of Contents / 目录

1. [Getting Started / 快速开始](#1-getting-started--快速开始)
2. [Understanding Profiles / 理解配置文件](#2-understanding-profiles--理解配置文件)
3. [Working with Modules / 使用模块](#3-working-with-modules--使用模块)
4. [Configuration Management / 配置管理](#4-configuration-management--配置管理)
5. [Runtime Operations / 运行时操作](#5-runtime-operations--运行时操作)
6. [Monitoring & Observability / 监控和可观测性](#6-monitoring--observability--监控和可观测性)
7. [Extending the Platform / 扩展平台](#7-extending-the-platform--扩展平台)
8. [Best Practices / 最佳实践](#8-best-practices--最佳实践)
9. [Troubleshooting / 故障排除](#9-troubleshooting--故障排除)

---

## 1. Getting Started / 快速开始

### Prerequisites / 前置条件

**English:**
- Linux kernel 5.8+ with BTF support
- Root/sudo access
- XDP-capable network interfaces (Intel i40e, Mellanox mlx5, or generic mode for others)
- Build tools: `build-essential`, `cmake`, `clang`, `llvm`, `pkg-config`
- Libraries: `libxdp-dev`, `libbpf-dev`, `linux-headers-$(uname -r)`

**中文:**
- Linux内核5.8+ 并支持BTF
- Root/sudo访问权限
- 支持XDP的网络接口（Intel i40e、Mellanox mlx5，或其他使用通用模式）
- 构建工具：`build-essential`、`cmake`、`clang`、`llvm`、`pkg-config`
- 库：`libxdp-dev`、`libbpf-dev`、`linux-headers-$(uname -r)`

### Build / 构建

```bash
# Clone the repository / 克隆仓库
git clone https://github.com/your-org/rswitch.git
cd rswitch

# Initialize submodules / 初始化子模块
git submodule update --init --recursive

# Generate vmlinux.h for CO-RE (first time only)
# 生成 vmlinux.h 用于 CO-RE（仅首次）
make vmlinux

# Build everything / 构建所有组件
make

# Verify build / 验证构建
ls build/
# Should show: rswitch_loader, rswitch-voqd, rswitchctl, rsvlanctl, rsaclctl, rsqosctl, ...
```

### First Run / 首次运行

```bash
# Choose a profile / 选择配置文件
ls etc/profiles/

# Start with a basic L2 switch / 启动基本二层交换机
sudo ./build/rswitch_loader \
    --profile etc/profiles/l2-simple-managed.yaml \
    --ifaces ens34,ens35,ens36

# Verify it's running / 验证运行状态
sudo bpftool prog list | grep rswitch
sudo bpftool map show | grep rs_
```

---

## 2. Understanding Profiles / 理解配置文件

### Profile Structure / 配置文件结构

**English:**

Profiles are YAML files that define the complete behavior of an rSwitch instance. They specify which modules to load, port configurations, VLAN settings, and more.

**中文:**

配置文件是定义rSwitch实例完整行为的YAML文件。它们指定要加载哪些模块、端口配置、VLAN设置等。

```yaml
# Profile structure / 配置文件结构
name: "profile-name"              # Required / 必需
version: "1.0"                    # Required / 必需
description: "Human description"  # Optional / 可选

# Module selection / 模块选择
ingress:                          # Required / 必需
  - module1
  - module2
  - lastcall                      # Always required / 始终必需

egress:                           # Required / 必需
  - egress_module1
  - egress_final                  # Always required / 始终必需

# Global settings / 全局设置
settings:                         # Optional / 可选
  mac_learning: true
  default_vlan: 1

# Port configuration / 端口配置
ports:                            # Optional / 可选
  - interface: "ens34"
    vlan_mode: trunk
    allowed_vlans: [1, 100, 200]

# VLAN definitions / VLAN 定义
vlans:                            # Optional / 可选
  - vlan_id: 100
    name: "Users"

# VOQd QoS configuration / VOQd QoS 配置
voqd_config:                      # Optional / 可选
  enabled: true
  mode: active

# Management portal / 管理门户
management:                       # Optional / 可选
  enabled: true
  port: 8080
```

### Profile Selection Guide / 配置文件选择指南

| Use Case / 使用场景 | Profile / 配置文件 | Description / 描述 |
|-----------|---------|-------------|
| Basic testing / 基本测试 | `dumb.yaml` | Simple flooding, no learning / 简单泛洪，无学习 |
| L2 unmanaged / 二层非管理 | `l2-unmanaged.yaml` | MAC learning, no VLANs / MAC学习，无VLAN |
| L2 managed / 二层管理 | `l2-simple-managed.yaml` | VLAN + DHCP snooping + mgmt / VLAN + DHCP监听 + 管理 |
| L3 routing / 三层路由 | `l3-full.yaml` | Full L3 routing + ACL / 完整三层路由 + ACL |
| All modules / 全模块 | `all.yaml` | Everything including QoS / 包括QoS的所有模块 |

### Creating Custom Profiles / 创建自定义配置文件

**English:**

Start from a similar existing profile and modify:

**中文:**

从类似的现有配置文件开始修改：

```bash
# Copy a base profile / 复制基础配置文件
cp etc/profiles/l2-simple-managed.yaml etc/profiles/my-custom.yaml

# Edit to your needs / 根据需求编辑
vim etc/profiles/my-custom.yaml

# Validate before running / 运行前验证
./build/rswitchctl validate-profile etc/profiles/my-custom.yaml
```

---

## 3. Working with Modules / 使用模块

### Available Modules / 可用模块

**English:**

rSwitch includes 27 BPF modules covering L2 switching, L3 routing, security, QoS, and monitoring. Each module is a self-contained BPF program that can be loaded or unloaded independently.

**中文:**

rSwitch包含27个BPF模块，涵盖二层交换、三层路由、安全、QoS和监控。每个模块都是独立的BPF程序，可以独立加载或卸载。

```bash
# List all available modules / 列出所有可用模块
./build/rswitchctl list-modules

# Show module details / 显示模块详情
./build/rswitchctl show-abi <module-name>
```

### Module Dependencies / 模块依赖

Some modules depend on others:

| Module / 模块 | Depends On / 依赖于 |
|--------|------------|
| `source_guard` | `vlan` |
| `dhcp_snoop` | `vlan` |
| `rate_limiter` | `qos_classify` |
| `nat` | `conntrack` |

The loader automatically resolves dependencies and loads modules in the correct order.

加载器自动解析依赖关系并按正确顺序加载模块。

### Hot-Reloading Modules / 热重载模块

**English:**

Individual modules can be replaced at runtime without restarting the entire pipeline:

**中文:**

可以在运行时替换单个模块而无需重启整个管道：

```bash
# Reload a single module / 重载单个模块
sudo ./build/rswitchctl reload acl

# Dry-run (validate only) / 空运行（仅验证）
sudo ./build/rswitchctl reload acl --dry-run
```

---

## 4. Configuration Management / 配置管理

### Port Configuration / 端口配置

```yaml
ports:
  # Trunk port (carries multiple VLANs)
  # Trunk 端口（承载多个 VLAN）
  - interface: "ens34"
    enabled: true
    vlan_mode: trunk
    native_vlan: 1              # Untagged VLAN / 无标签 VLAN
    allowed_vlans: [1, 100, 200]
    mac_learning: true
    default_priority: 0

  # Access port (single VLAN)
  # Access 端口（单个 VLAN）
  - interface: "ens35"
    enabled: true
    vlan_mode: access
    pvid: 100                   # Port VLAN ID / 端口 VLAN ID
    mac_learning: true
```

### VLAN Configuration / VLAN配置

```yaml
vlans:
  - vlan_id: 100
    name: "Users"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens35"]

  - vlan_id: 200
    name: "Servers"
    tagged_ports: ["ens34"]
    untagged_ports: ["ens36"]
```

### Runtime VLAN Management / 运行时VLAN管理

```bash
# Show VLANs / 显示 VLAN
sudo ./build/rsvlanctl show

# Add a VLAN / 添加 VLAN
sudo ./build/rsvlanctl add 300 "NewVLAN"

# Add port to VLAN / 添加端口到 VLAN
sudo ./build/rsvlanctl add-port 300 ens35 tagged

# Remove port from VLAN / 从 VLAN 移除端口
sudo ./build/rsvlanctl del-port 300 ens35

# Delete VLAN / 删除 VLAN
sudo ./build/rsvlanctl del 300
```

### ACL Configuration / ACL配置

```bash
# Show ACL rules / 显示 ACL 规则
sudo ./build/rsaclctl show

# Add a rule (block traffic from 10.0.0.0/8)
# 添加规则（阻止来自 10.0.0.0/8 的流量）
sudo ./build/rsaclctl add 10 "src=10.0.0.0/8" drop

# Add a rule (allow specific traffic)
# 添加规则（允许特定流量）
sudo ./build/rsaclctl add 20 "src=192.168.1.0/24 dst=10.0.0.1/32 dport=80 proto=tcp" permit

# Delete a rule / 删除规则
sudo ./build/rsaclctl del 10
```

---

## 5. Runtime Operations / 运行时操作

### Viewing Pipeline Status / 查看管道状态

```bash
# Show loaded modules and order / 显示已加载模块和顺序
sudo ./build/rswitchctl show-pipeline

# Show per-module statistics / 显示每模块统计
sudo ./build/rswitchctl show-stats

# Show current profile / 显示当前配置文件
sudo ./build/rswitchctl show-profile
```

### Viewing Tables / 查看表

```bash
# MAC address table / MAC 地址表
sudo ./build/rswitchctl mac-table

# VLAN membership / VLAN 成员
sudo ./build/rsvlanctl show

# Routing table / 路由表
sudo ./build/rsroutectl show

# Flow table / 流表
sudo ./build/rsflowctl show
```

### Profile Switching / 配置文件切换

**English:**

Switch to a different profile at runtime. This reloads all modules and configurations.

**中文:**

在运行时切换到不同的配置文件。这将重新加载所有模块和配置。

```bash
# Via management portal / 通过管理门户
# Navigate to Profiles page, select new profile, click Apply

# Via systemd (if using systemd integration)
# 通过 systemd（如果使用 systemd 集成）
sudo systemctl restart rswitch-mgmtd
# Or edit the profile path and restart
```

### Graceful Shutdown / 优雅关闭

```bash
# If running in foreground / 如果在前台运行
# Press Ctrl+C

# If running as service / 如果作为服务运行
sudo systemctl stop rswitch-loader

# Manual cleanup / 手动清理
sudo pkill rswitch_loader
sudo ./scripts/unpin_maps.sh
```

---

## 6. Monitoring & Observability / 监控和可观测性

### Built-in Statistics / 内置统计

```bash
# Per-port statistics / 每端口统计
sudo ./build/rswitchctl show-stats

# Per-module statistics / 每模块统计
sudo ./build/rswitchctl show-stats --module acl

# QoS statistics / QoS 统计
sudo ./build/rsqosctl stats
```

### Event Bus / 事件总线

**English:**

All modules emit structured events to a shared ring buffer. Use the event consumer to view them:

**中文:**

所有模块向共享环形缓冲区发送结构化事件。使用事件消费者查看：

```bash
# Start event consumer / 启动事件消费者
sudo ./build/rswitch-events

# Example output / 示例输出:
# [MAC_LEARNED] port=ens34 mac=aa:bb:cc:dd:ee:ff vlan=100
# [ACL_DENY] rule=10 src=10.1.2.3 dst=192.168.1.1
```

### Prometheus Metrics / Prometheus指标

```bash
# Start Prometheus exporter / 启动 Prometheus 导出器
sudo ./build/rswitch-prometheus --port 9417

# Scrape metrics / 抓取指标
curl http://localhost:9417/metrics
```

### Management Portal / 管理门户

**English:**

The web-based management portal provides real-time visualization:

**中文:**

基于Web的管理门户提供实时可视化：

- **Dashboard**: System overview, port summary, uptime / 系统概览、端口摘要、运行时间
- **Ports**: Port status with faceplate grid / 端口状态和面板网格
- **Modules**: Pipeline visualization / 管道可视化
- **VLANs**: VLAN management / VLAN管理
- **ACLs**: ACL rule management / ACL规则管理
- **Logs**: Live event log / 实时事件日志

Access at `http://<management-ip>:8080` (requires profile with `management.enabled: true`)

访问 `http://<管理IP>:8080`（需要配置文件中 `management.enabled: true`）

---

## 7. Extending the Platform / 扩展平台

### Writing Custom Modules / 编写自定义模块

**English:**

The SDK provides templates and APIs for developing custom BPF modules:

**中文:**

SDK提供用于开发自定义BPF模块的模板和API：

```bash
# Generate module scaffold / 生成模块脚手架
./build/rswitchctl new-module my_filter \
    --stage 35 \
    --hook ingress \
    --flags NEED_L2L3_PARSE,MAY_DROP

# This creates: sdk/modules/my_filter/
#   - my_filter.bpf.c   (BPF source)
#   - Makefile          (build rules)
#   - README.md         (documentation)
```

### Module Template / 模块模板

```c
#include "rswitch_bpf.h"
#include "module_abi.h"

char _license[] SEC("license") = "GPL";

// Declare module metadata / 声明模块元数据
RS_DECLARE_MODULE(
    "my_filter",                    // Name / 名称
    RS_HOOK_XDP_INGRESS,            // Hook point / 挂钩点
    35,                             // Stage number / 阶段号
    RS_FLAG_NEED_L2L3_PARSE | RS_FLAG_MAY_DROP,  // Flags / 标志
    "My custom filter module"       // Description / 描述
);

SEC("xdp")
int my_filter_prog(struct xdp_md *xdp_ctx) {
    // Get shared context / 获取共享上下文
    struct rs_ctx *ctx = RS_GET_CTX();
    if (!ctx) return XDP_DROP;

    // Your logic here / 您的逻辑在这里
    // ...

    // Continue to next module / 继续到下一个模块
    RS_TAIL_CALL_NEXT(xdp_ctx, ctx);
    return XDP_DROP;  // Fallthrough = drop
}
```

### Building External Modules / 构建外部模块

```bash
cd sdk/modules/my_filter/

# Build / 构建
make

# Install / 安装
sudo ./build/rswitchctl install-module ./my_filter.rsmod

# Add to profile / 添加到配置文件
# ingress:
#   - my_filter
```

See [Module Developer Guide](../development/Module_Developer_Guide.md) for complete documentation.

完整文档请参阅[模块开发指南](../development/Module_Developer_Guide.md)。

---

## 8. Best Practices / 最佳实践

### Profile Management / 配置文件管理

| Practice / 实践 | Description / 描述 |
|----------|-------------|
| Version control profiles / 版本控制配置文件 | Keep profiles in git / 将配置文件保存在git中 |
| Validate before deploy / 部署前验证 | `rswitchctl validate-profile` / `rswitchctl validate-profile` |
| Use inheritance / 使用继承 | `inherits: base.yaml` for common settings / `inherits: base.yaml` 用于公共设置 |
| Name meaningfully / 有意义的命名 | `campus-building-a.yaml` not `profile1.yaml` |

### Module Selection / 模块选择

| Practice / 实践 | Description / 描述 |
|----------|-------------|
| Minimal modules / 最少模块 | Only load what you need / 只加载需要的 |
| Required modules / 必需模块 | Always include `dispatcher`, `lastcall`, `egress_final` |
| Security baseline / 安全基线 | Always include `acl` for production / 生产环境始终包含 `acl` |
| QoS when needed / 需要时的QoS | Add `qos_classify` only if traffic prioritization required |

### Performance / 性能

| Practice / 实践 | Description / 描述 |
|----------|-------------|
| Native XDP / 原生XDP | Use `--xdp-mode native` when NIC supports it / 当NIC支持时使用 |
| Disable VLAN offload / 禁用VLAN卸载 | Required for VLAN processing / VLAN处理所需 |
| CPU affinity / CPU亲和性 | Pin VOQd to dedicated core / 将VOQd固定到专用核心 |
| Batch size / 批处理大小 | Tune AF_XDP batch_size for throughput / 调整AF_XDP batch_size以获得吞吐量 |

### Security / 安全

| Practice / 实践 | Description / 描述 |
|----------|-------------|
| Management isolation / 管理隔离 | Use namespace for mgmtd / 使用命名空间隔离mgmtd |
| Authentication / 认证 | Enable `auth_enabled: true` in management config / 在管理配置中启用 |
| ACL default deny / ACL默认拒绝 | Configure explicit allow rules / 配置显式允许规则 |
| Source guard / 源防护 | Enable for campus/edge deployments / 为校园/边缘部署启用 |

---

## 9. Troubleshooting / 故障排除

### Common Issues / 常见问题

#### XDP attachment fails / XDP附加失败

```bash
# Check if another XDP program is attached / 检查是否有其他 XDP 程序附加
ip link show ens34 | grep xdp

# Remove existing program / 移除现有程序
sudo ip link set ens34 xdp off

# Check kernel version / 检查内核版本
uname -r  # Should be 5.8+
```

#### VLAN traffic not working / VLAN流量不工作

```bash
# Disable hardware VLAN offload / 禁用硬件 VLAN 卸载
sudo ethtool -K ens34 rx-vlan-offload off
sudo ethtool -K ens34 tx-vlan-offload off

# Verify / 验证
ethtool -k ens34 | grep vlan
```

#### Management portal not accessible / 管理门户无法访问

```bash
# Check namespace exists / 检查命名空间是否存在
ip netns list | grep rswitch-mgmt

# Check mgmt0 has IP / 检查 mgmt0 是否有 IP
sudo ip netns exec rswitch-mgmt ip addr show mgmt0

# Check mgmtd is running / 检查 mgmtd 是否运行
ps aux | grep rswitch-mgmtd
```

#### No traffic forwarding / 没有流量转发

```bash
# Check programs are loaded / 检查程序是否已加载
sudo bpftool prog list | grep rswitch

# Check maps are populated / 检查映射是否已填充
sudo bpftool map dump pinned /sys/fs/bpf/rs_port_config_map

# Check statistics for drops / 检查丢弃统计
sudo ./build/rswitchctl show-stats
```

### Diagnostic Commands / 诊断命令

```bash
# Full system diagnosis / 完整系统诊断
sudo ./scripts/rswitch_diag.sh

# VOQd health check / VOQd 健康检查
sudo ./scripts/voqd_check.sh

# Health status / 健康状态
sudo ./build/rswitchctl health

# Debug logging / 调试日志
sudo ./build/rswitch_loader --debug --profile ...
```

### Getting Help / 获取帮助

- Check [Troubleshooting](../usage/Troubleshooting.md) for detailed solutions / 查看[故障排除](../usage/Troubleshooting.md)获取详细解决方案
- Review [Platform Architecture](../development/Platform_Architecture.md) for deeper understanding / 查看[平台架构](../development/Platform_Architecture.md)以获得更深入的理解
- Examine event bus for runtime errors / 检查事件总线以获取运行时错误

---

## See Also / 另请参阅

- [Reconfigurable Architecture](Reconfigurable_Architecture.md) — Platform philosophy / 平台哲学
- [Network Device Gallery](Network_Device_Gallery.md) — Device types you can build / 可构建的设备类型
- [Quick Start](../usage/Quick_Start.md) — 5-minute setup / 5分钟设置
- [Configuration Reference](../deployment/Configuration.md) — Full YAML reference / 完整YAML参考
- [CLI Reference](../usage/CLI_Reference.md) — All CLI commands / 所有CLI命令

---

*Last updated / 最后更新: 2026-03-17*
