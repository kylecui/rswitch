# rSwitch 中文文档

> 📖 [English Documentation Index](../Documentation_Index.md)

---

**rSwitch** — 基于 XDP/eBPF 的高性能、模块化可重构网络交换平台，支持 CO-RE 跨内核兼容部署。

本目录包含 rSwitch 核心文档的中文翻译，覆盖用户使用、部署运维和二次开发所需的全部关键文档。

---

## 💡 概念指南（双语文档）

核心概念文档采用中英双语格式，可直接参阅：

| 文档 | 描述 |
|------|------|
| [可重构架构](../concepts/Reconfigurable_Architecture.md) | 平台哲学和设计原则 |
| [网络设备类型库](../concepts/Network_Device_Gallery.md) | 可构建的各种网络设备 |
| [框架使用指南](../concepts/Framework_Guide.md) | 如何使用 rSwitch 框架 |

---

## 📘 使用指南

| 文档 | 英文原文 | 描述 |
|------|----------|------|
| [快速开始](usage/Quick_Start.md) | [Quick Start](../usage/Quick_Start.md) | 5 分钟内构建、运行和验证 rSwitch |
| [使用方法](usage/How_To_Use.md) | [How To Use](../usage/How_To_Use.md) | 实用操作示例 — L2/L3 交换、QoS、防火墙和常见工作流 |
| [CLI 参考](usage/CLI_Reference.md) | [CLI Reference](../usage/CLI_Reference.md) | `rswitchctl`、`rsvlanctl`、`rsaclctl`、`rsqosctl`、`rsvoqctl` 完整参考 |
| [故障排除](usage/Troubleshooting.md) | [Troubleshooting](../usage/Troubleshooting.md) | 常见问题、诊断命令、清理流程和 NIC 特定说明 |

---

## 📦 部署指南

| 文档 | 英文原文 | 描述 |
|------|----------|------|
| [安装指南](deployment/Installation.md) | [Installation](../deployment/Installation.md) | 从源码构建、依赖项、内核要求和验证 |
| [配置参考](deployment/Configuration.md) | [Configuration](../deployment/Configuration.md) | YAML profile 结构 — `ingress`、`egress`、`settings`、`ports`、`voqd_config` |
| [管理门户](deployment/Management_Portal.md) | [Management Portal](../deployment/Management_Portal.md) | Web 管理界面 — 命名空间隔离、DHCP、REST API、实时监控 |

> 其他部署文档暂未翻译，请参阅英文原文：[VOQd Setup](../deployment/VOQd_Setup.md)、[NIC Configuration](../deployment/NIC_Configuration.md)、[Systemd Integration](../deployment/Systemd_Integration.md)

---

## 🛠️ 开发指南

| 文档 | 英文原文 | 描述 |
|------|----------|------|
| [架构设计](development/Architecture.md) | [Architecture](../development/Architecture.md) | 双管道架构、模块系统、共享上下文、数据结构 |
| [模块开发指南](development/Module_Developer_Guide.md) | [Module Developer Guide](../development/Module_Developer_Guide.md) | 从模板到生产 — BPF 模块开发完整指南 |
| [ABI 稳定性策略](development/ABI_POLICY.md) | [ABI Policy](../development/ABI_POLICY.md) | ABI 版本契约 — 稳定性层级、破坏性变更策略、loader 强制检查 |
| [CO-RE 指南](development/CO-RE_Guide.md) | [CO-RE Guide](../development/CO-RE_Guide.md) | CO-RE 可移植性 — `BPF_CORE_READ()`、offset masking、跨内核测试 |
| [贡献指南](development/CONTRIBUTING.md) | [Contributing](../../CONTRIBUTING.md) | 贡献工作流、代码规范、PR 流程、许可协议 |

> 其他开发文档暂未翻译，请参阅英文原文：[Platform Architecture](../development/Platform_Architecture.md)、[API Reference](../development/API_Reference.md)、[Graceful Degradation](../development/DEGRADATION.md)、[Map Pinning](../development/MAP_PINNING.md)

---

## 📦 SDK 文档

| 文档 | 英文原文 | 描述 |
|------|----------|------|
| [SDK 快速开始](../../sdk/docs/zh-CN/SDK_Quick_Start.md) | [SDK Quick Start](../../sdk/docs/SDK_Quick_Start.md) | 外部模块开发套件 — 构建、测试、打包、部署 |

---

## 📋 开发计划

开发计划暂未翻译，请参阅英文原文：

| 文档 | 描述 |
|------|------|
| [Platform Backlog](../backlog/platform-backlog.md) | 核心基础设施 — Profile 系统、loader、性能、CI |
| [API Backlog](../backlog/api-backlog.md) | API 稳定性、模块 SDK、开发工具、测试框架 |
| [Product Backlog](../backlog/product-backlog.md) | 网络功能模块 — L2/L3 增强、QoS、安全、高级转发 |
| [Ecosystem Backlog](../backlog/ecosystem-backlog.md) | 模块市场、多交换机编排、监控、生产加固 |

---

## 🔗 快速链接

- **只想运行？** → [快速开始](usage/Quick_Start.md)
- **了解平台？** → [可重构架构](../concepts/Reconfigurable_Architecture.md)（双语）
- **构建什么设备？** → [网络设备类型库](../concepts/Network_Device_Gallery.md)（双语）
- **如何使用框架？** → [框架使用指南](../concepts/Framework_Guide.md)（双语）
- **配置参考？** → [配置参考](deployment/Configuration.md)
- **开发模块？** → [模块开发指南](development/Module_Developer_Guide.md) / [SDK 快速开始](../../sdk/docs/zh-CN/SDK_Quick_Start.md)
- **ABI 兼容性？** → [ABI 稳定性策略](development/ABI_POLICY.md)
- **管理界面？** → [管理门户](deployment/Management_Portal.md)
- **故障排除？** → [故障排除](usage/Troubleshooting.md)

---

## 翻译规范

- 技术术语保留英文（如 XDP、BPF、CO-RE、AF_XDP、VLAN、QoS 等）
- 代码块和命令行不翻译
- 保持与英文原文相同的文档结构
- 文件名使用英文，与原文保持一致
- 每个翻译文件顶部包含指向英文原文的链接

---

*最后更新: 2026-03-24*
