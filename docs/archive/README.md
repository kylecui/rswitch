> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch Documentation

> **Reconfigurable Switch with eBPF/XDP** - Production-ready modular network switching framework

欢迎来到 rSwitch 文档！本目录包含从概念到部署的完整文档。

---

## 🚀 立即开始

### 1. **第一次使用？** 从这里开始

**[📖 Migration Guide](Migration_Guide.md)** ⭐ 推荐

- ✅ 5 分钟快速体验
- ✅ 框架核心能力介绍
- ✅ 完整部署指南
- ✅ 模块开发教程
- ✅ 性能调优和故障排查

**快速命令**:
```bash
# 克隆项目
git clone <repo>
cd rSwitch/rswitch

# 构建
make

# 运行（简单 L2 交换机）
sudo rswitch_loader --profile etc/profiles/dumb.yaml
```

---

## 📚 文档导航

### 按角色查找

| 角色 | 推荐阅读 | 时间估计 |
|------|---------|---------|
| **快速部署用户** | [Migration Guide](Migration_Guide.md) (第 2, 6, 7 节) | 30 分钟 |
| **模块开发者** | [CO-RE Guide](archive/CO-RE_Guide.md) + [Migration Guide](Migration_Guide.md) (第 5 节) | 2 小时 |
| **性能工程师** | [Migration Guide](Migration_Guide.md) (第 8 节) + [Data Plane Design](../../docs/data_plane_desgin_with_af_XDP.md) | 1 小时 |
| **架构师/决策者** | [rSwitch Definition](../../docs/rSwitch_Definition.md) + [Overview](../../docs/Reconfigurable_Switch_Overview.md) | 45 分钟 |
| **从 PoC 迁移** | [Migration Guide](Migration_Guide.md) (第 4 节) + [Milestone1 Plan](../../docs/Milestone1_plan.md) | 1 小时 |

### 核心文档（按优先级）

1. **⭐⭐⭐ [Migration Guide](Migration_Guide.md)** (118KB)
   - **适合所有人** - 完整的使用和开发指南
   
2. **⭐⭐ [CO-RE Guide](archive/CO-RE_Guide.md)** (71KB)
   - **模块开发者必读** - CO-RE 技术详解
   
3. **⭐⭐ [Data Plane Design](../../docs/data_plane_desgin_with_af_XDP.md)**
   - **深入理解** - XDP + AF_XDP 混合数据平面设计

4. **⭐ [rSwitch Definition](../../docs/rSwitch_Definition.md)**
   - **了解价值** - rSwitch 核心定义和工程价值

5. **📊 [Documentation Index](Documentation_Index.md)**
   - **完整索引** - 所有文档的详细索引和查找指南

---

## 🎯 常见任务快速跳转

| 任务 | 文档 | 章节 |
|------|------|------|
| 🏗️ **部署 L2 交换机** | Migration Guide | 第 2, 6 节 |
| 🔧 **开发自定义模块** | Migration Guide | 第 5 节 |
| ⚡ **性能调优** | Migration Guide | 第 8 节 |
| 🐛 **排查错误** | Migration Guide | 第 9 节 |
| 🔄 **从 PoC 迁移** | Migration Guide | 第 4 节 |
| 🛡️ **配置防火墙** | Migration Guide | 第 6.4 节 |
| 📊 **启用 QoS** | Migration Guide | 第 6.5 节 |
| 🔍 **查看统计数据** | Migration Guide | 第 3.6, 10 节 |
| 🌐 **配置 VLAN** | Migration Guide | 第 6.2, 7.2 节 |
| 🔌 **API 集成** | Migration Guide | 第 10 节 |

---

## 📖 文档列表

### 指南和教程
- **[Migration_Guide.md](Migration_Guide.md)** - 完整迁移和使用指南 ⭐⭐⭐
- **[CO-RE_Guide.md](archive/CO-RE_Guide.md)** - CO-RE 技术和模块可移植性指南 ⭐⭐

### 设计文档
- **[rSwitch_Definition.md](../../docs/rSwitch_Definition.md)** - rSwitch 核心定义
- **[Reconfigurable_Switch_Overview.md](../../docs/Reconfigurable_Switch_Overview.md)** - 可重配置交换机概述
- **[data_plane_desgin_with_af_XDP.md](../../docs/data_plane_desgin_with_af_XDP.md)** - 数据平面详细设计
- **[discussions.md](../../docs/discussions.md)** - 设计决策 Q&A

### 开发和迁移
- **[Milestone1_plan.md](../../docs/Milestone1_plan.md)** - PoC → Production 迁移计划
- **[Module_Portability_Report.md](archive/Module_Portability_Report.md)** - 模块分发策略
- **[CO-RE_Migration_Complete.md](archive/CO-RE_Migration_Complete.md)** - CO-RE 迁移记录

### 项目状态
- **[Phase5_Readiness_Assessment.md](archive/Phase5_Readiness_Assessment.md)** - Phase 5 就绪性评估

### 索引
- **[Documentation_Index.md](Documentation_Index.md)** - 完整文档索引和查找指南

---

## 🔍 按问题查找

| 问题 | 解决方案 |
|------|---------|
| **如何安装和运行？** | [Migration Guide 第 2 节](Migration_Guide.md#快速开始) |
| **如何配置 VLAN？** | [Migration Guide 第 7.2 节](Migration_Guide.md#端口配置详解) |
| **性能不达预期** | [Migration Guide 第 8 节](Migration_Guide.md#性能调优) |
| **模块加载失败** | [Migration Guide 第 9 节](Migration_Guide.md#故障排查) |
| **CO-RE 兼容性问题** | [CO-RE Guide 第 3-5 节](archive/CO-RE_Guide.md) |
| **如何使用 rswitchctl？** | [Migration Guide 第 10 节](Migration_Guide.md#api-参考) |
| **什么是 VOQd？** | [Data Plane Design 第 2-3 节](../../docs/data_plane_desgin_with_af_XDP.md) |
| **如何热重载模块？** | [Migration Guide 第 3.2 节](Migration_Guide.md#模块化插件系统) |

---

## 💡 示例场景

### 场景 1: 小型办公室网络（3 端口）
```yaml
# etc/profiles/small-office.yaml
name: "small-office"
ingress: [vlan, l2learn, lastcall]
ports:
  - {id: 1, mode: trunk, allowed_vlans: [1,10,20]}
  - {id: 2, mode: access, access_vlan: 10}  # Office
  - {id: 3, mode: access, access_vlan: 20}  # Guest
```
**详见**: [Migration Guide - 示例 1](Migration_Guide.md#示例 1: 小型办公室网络)

### 场景 2: 数据中心 ToR 交换机（QoS）
```yaml
# etc/profiles/datacenter-tor.yaml
ingress: [vlan, acl, l2learn, afxdp_redirect, lastcall]
voqd:
  enabled: true
  scheduler: drr
  priorities: [{prio: 3, weight: 50, rate_limit_mbps: 10000}]
```
**详见**: [Migration Guide - 示例 2](Migration_Guide.md#示例 2: 数据中心 ToR（Top-of-Rack）)

### 场景 3: DMZ 防火墙
```yaml
# etc/profiles/dmz-firewall.yaml
ingress: [vlan, acl, mirror, l2learn, lastcall]
acl_rules:
  - {name: "deny-inbound", action: drop, ...}
  - {name: "allow-web", protocol: tcp, dst_port: [80,443], ...}
```
**详见**: [Migration Guide - 示例 3](Migration_Guide.md#示例 3: DMZ 防火墙)

---

## 🏗️ 项目状态

### ✅ 已完成（Phase 1-4）

- **Phase 1**: 核心基础设施（Dispatcher, Egress, Module ABI）
- **Phase 2**: 模块化组件（VLAN, L2Learn, LastCall, ACL, Route 等）
- **Phase 3**: VOQd 集成（AF_XDP, 调度器, 3-state 机制）
- **Phase 4**: 控制和可观测性（rswitchctl, telemetry, events）

**完成率**: 17/17 tasks (100%)

### 🔧 进行中（Phase 5）

- ✅ **文档编写** - Migration Guide 完成
- ⏳ **性能基准测试** - 需要真实硬件（Intel X710/Mellanox CX-5）
- ⏳ **多环境测试** - 需要 jzzn/kc_lab 环境访问

**当前环境**: Azure VM（hv_netvsc, XDP generic 模式）- 仅支持功能测试

---

## 🚦 系统要求

### 最低要求
- **内核**: Linux 5.8+ (BTF 支持)
- **CPU**: 4 cores
- **内存**: 4 GB
- **NIC**: 任何 Linux 网卡（Generic XDP 模式）

### 推荐配置（生产环境）
- **内核**: Linux 6.1+
- **CPU**: 8+ cores
- **内存**: 16+ GB
- **NIC**: Intel X710/ice, Mellanox CX-5/mlx5（Native XDP 支持）

**详见**: [Migration Guide - 系统要求](Migration_Guide.md#系统要求)

---

## 🤝 贡献

文档改进建议：
1. **报告错误**: 发现不准确或过时的内容
2. **补充示例**: 添加实际使用场景
3. **翻译**: 帮助翻译文档（如需要）

---

## 📮 获取帮助

1. **查看 FAQ**: [Migration Guide - FAQ](Migration_Guide.md#FAQ)
2. **故障排查指南**: [Migration Guide - 故障排查](Migration_Guide.md#故障排查)
3. **提交 Issue**: GitHub Issues（如果可用）
4. **查看示例**: `bpf/modules/` 和 `demos/rswitch_scaffold/`

---

## 📊 快速参考

### 常用命令
```bash
# 查看状态
sudo rswitchctl status

# 查看 pipeline
sudo rswitchctl show-pipeline

# 查看端口
sudo rswitchctl show-ports

# 查看统计
sudo rswitchctl show-stats

# 查看 MAC 表
sudo rswitchctl show-macs

# 热重载模块
sudo rswitchctl hot-reload --module vlan --object build/bpf/vlan.bpf.o
```

### 关键文件位置
```
rswitch/
├── bpf/
│   ├── core/           # 核心组件（dispatcher, egress）
│   ├── modules/        # 可插拔模块（vlan, acl, etc.）
│   └── include/        # 头文件（vmlinux.h, rswitch_bpf.h）
├── user/
│   ├── loader/         # rswitch_loader
│   ├── voqd/           # rswitch-voqd
│   └── tools/          # rswitchctl, telemetry, events
├── etc/
│   └── profiles/       # 配置 Profile（dumb, l2, l3, firewall）
└── docs/               # 文档（你在这里）
```

---

**开始探索**: [Migration Guide](Migration_Guide.md) | [Documentation Index](Documentation_Index.md)

**版本**: 1.0.0  
**最后更新**: 2024-11-04  
**维护者**: rSwitch Team
