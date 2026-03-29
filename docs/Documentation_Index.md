# rSwitch Documentation Index

> **rSwitch** — A high-performance, modular XDP/eBPF network switch platform with CO-RE compatibility.
>
> 📖 [中文文档](zh-CN/README.md) (Chinese translations available)

---

## 💡 Concepts (Bilingual / 双语)

Core platform concepts and architectural philosophy. All documents in this section are bilingual (English + Chinese).

| Document | Description |
|----------|-------------|
| [Reconfigurable Architecture](concepts/Reconfigurable_Architecture.md) | Platform philosophy — what "reconfigurable" means and why it matters / 平台理念 |
| [Network Device Gallery](concepts/Network_Device_Gallery.md) | Types of network devices you can build with rSwitch / 可构建的网络设备类型 |
| [Framework Guide](concepts/Framework_Guide.md) | How to use the rSwitch framework effectively / 框架使用指南 |

---

## 📘 Usage

Getting started and day-to-day operation guides.

| Document | 中文 | Description |
|----------|------|-------------|
| [Quick Start](usage/Quick_Start.md) | [快速开始](zh-CN/usage/Quick_Start.md) | Build, run, and verify rSwitch in under 5 minutes |
| [How To Use](usage/How_To_Use.md) | [使用指南](zh-CN/usage/How_To_Use.md) | Practical usage examples — L2/L3 switching, QoS, firewall, and common workflows |
| [Scenario Profiles](usage/Scenario_Profiles.md) | | All 18 YAML profiles explained — purpose, module pipeline, and when to use each |
| [CLI Reference](usage/CLI_Reference.md) | [CLI 参考](zh-CN/usage/CLI_Reference.md) | Complete reference for `rswitchctl`, `rsvlanctl`, `rsaclctl`, `rsqosctl`, `rsvoqctl` |
| [Intent Engine](usage/Intent_Engine.md) | | Intent-based networking — translate high-level YAML intents into profiles |
| [Policy Verification](usage/Policy_Verification.md) | | Policy compliance checking for profiles |
| [Troubleshooting](usage/Troubleshooting.md) | [故障排除](zh-CN/usage/Troubleshooting.md) | Common issues, diagnostic commands, cleanup procedures, and NIC-specific notes |

---

## 📦 Deployment

Installation, system configuration, and production deployment.

| Document | 中文 | Description |
|----------|------|-------------|
| [Installation](deployment/Installation.md) | [安装指南](zh-CN/deployment/Installation.md) | Build from source, dependencies, kernel requirements, and verification |
| [Configuration](deployment/Configuration.md) | [配置参考](zh-CN/deployment/Configuration.md) | YAML profile structure — `ingress`, `egress`, `settings`, `ports`, `voqd_config` |
| [VOQd Setup](deployment/VOQd_Setup.md) | | VOQd QoS scheduler — modes (BYPASS/SHADOW/ACTIVE), AF_XDP, software queues |
| [NIC Configuration](deployment/NIC_Configuration.md) | | NIC-specific setup — Intel X710/i40e, Mellanox CX-5/mlx5, Hyper-V hv_netvsc |
| [Systemd Integration](deployment/Systemd_Integration.md) | | Service units, auto-start, watchdog, and production deployment patterns |
| [Management Portal](deployment/Management_Portal.md) | [管理门户](zh-CN/deployment/Management_Portal.md) | Web management UI — namespace isolation, DHCP, REST API, real-time monitoring |

---

## 🛠️ Development

Architecture deep-dives, module development, and API reference.

| Document | 中文 | Description |
|----------|------|-------------|
| [Platform Architecture](development/Platform_Architecture.md) | | **Comprehensive** platform design — philosophy, data/control plane, module classification, stage map |
| [Architecture](development/Architecture.md) | [架构设计](zh-CN/development/Architecture.md) | Dual-pipeline architecture, module system, shared context, data structures |
| [Module Developer Guide](development/Module_Developer_Guide.md) | [模块开发指南](zh-CN/development/Module_Developer_Guide.md) | Step-by-step guide to writing BPF modules — from template to production |
| [ABI Policy](development/ABI_POLICY.md) | [ABI 稳定性策略](zh-CN/development/ABI_POLICY.md) | ABI versioning contract — stability tiers, breaking change policy, loader enforcement |
| [Graceful Degradation](development/DEGRADATION.md) | | How modules should behave when the pipeline is partially available |
| [Map Pinning](development/MAP_PINNING.md) | | BPF map pinning conventions — canonical paths, naming, user-space access |
| [API Reference](development/API_Reference.md) | | Complete API — macros, structs, maps, helpers, flags, error codes |
| [API Reference (Generated)](development/API_Reference_Generated.md) | | Auto-generated API documentation from source headers |
| [CO-RE Guide](development/CO-RE_Guide.md) | [CO-RE 指南](zh-CN/development/CO-RE_Guide.md) | CO-RE portability — `BPF_CORE_READ()`, offset masking, cross-kernel testing |
| [Distributed State Sync](development/Distributed_State_Sync.md) | | Multi-switch state synchronization design document |
| [Contributing](development/Contributing.md) | [贡献指南](zh-CN/development/CONTRIBUTING.md) | Contribution workflow, coding standards, PR process, licensing |
| [SDK Quick Start](../sdk/docs/SDK_Quick_Start.md) | [SDK 快速开始](../sdk/docs/zh-CN/SDK_Quick_Start.md) | External module development kit — build, test, package, deploy |
| [SDK Migration Guide](../sdk/docs/SDK_Migration_Guide.md) | [SDK 迁移指南](zh-CN/sdk/SDK_Migration_Guide.md) | Migrate from legacy headers (uapi.h, map_defs.h, etc.) to SDK v2.0 headers |

---

## 📋 Development Backlog

Forward-looking development plans organized by area.

| Document | Description |
|----------|-------------|
| [Platform Backlog](backlog/platform-backlog.md) | Core infrastructure — profile system, loader, performance, CI |
| [API Backlog](backlog/api-backlog.md) | API stability, module SDK, developer tooling, testing framework |
| [Product Backlog](backlog/product-backlog.md) | Network function modules — L2/L3 enhancements, QoS, security, advanced forwarding |
| [Ecosystem Backlog](backlog/ecosystem-backlog.md) | Module marketplace, multi-switch orchestration, monitoring, production hardening |

---

## 📁 Directory Structure

```
docs/
├── concepts/                  # Core concepts (bilingual / 双语)
│   ├── Reconfigurable_Architecture.md
│   ├── Network_Device_Gallery.md
│   └── Framework_Guide.md
├── usage/                     # User-facing operation guides
│   ├── Quick_Start.md
│   ├── How_To_Use.md
│   ├── Scenario_Profiles.md
│   ├── CLI_Reference.md
│   ├── Intent_Engine.md
│   ├── Policy_Verification.md
│   └── Troubleshooting.md
├── deployment/                # Installation and deployment
│   ├── Installation.md
│   ├── Configuration.md
│   ├── VOQd_Setup.md
│   ├── NIC_Configuration.md
│   ├── Systemd_Integration.md
│   └── Management_Portal.md
├── development/               # Developer documentation
│   ├── Platform_Architecture.md
│   ├── Architecture.md
│   ├── Module_Developer_Guide.md
│   ├── ABI_POLICY.md
│   ├── DEGRADATION.md
│   ├── MAP_PINNING.md
│   ├── API_Reference.md
│   ├── API_Reference_Generated.md
│   ├── CO-RE_Guide.md
│   ├── Distributed_State_Sync.md
│   └── Contributing.md
├── backlog/                   # Development roadmap
│   ├── platform-backlog.md
│   ├── api-backlog.md
│   ├── product-backlog.md
│   └── ecosystem-backlog.md
├── zh-CN/                     # Chinese translations (中文翻译)
│   ├── README.md              # 中文文档索引
│   ├── usage/
│   │   ├── Quick_Start.md
│   │   ├── How_To_Use.md
│   │   ├── CLI_Reference.md
│   │   └── Troubleshooting.md
│   ├── deployment/
│   │   ├── Installation.md
│   │   ├── Configuration.md
│   │   └── Management_Portal.md
│   └── development/
│       ├── Architecture.md
│       ├── Module_Developer_Guide.md
│       ├── CO-RE_Guide.md
│       ├── ABI_POLICY.md
│       └── CONTRIBUTING.md
├── marketplace/               # Module marketplace portal
├── archive/                   # Historical documents (preserved)
└── paperwork/                 # Technical white papers
```

SDK documentation:
```
sdk/docs/
├── SDK_Quick_Start.md
├── SDK_Migration_Guide.md
├── Module_Development_Spec.md
└── zh-CN/
    └── SDK_Quick_Start.md     # SDK 快速开始（中文）
```

---

## 🔗 Quick Links

- **Changelog?** → [CHANGELOG](../CHANGELOG.md) / [变更日志](zh-CN/CHANGELOG.md)
- **Just want to run it?** → [Quick Start](usage/Quick_Start.md) / [快速开始](zh-CN/usage/Quick_Start.md)
- **Platform overview?** → [Platform Architecture](development/Platform_Architecture.md)
- **What is "reconfigurable"?** → [Reconfigurable Architecture](concepts/Reconfigurable_Architecture.md)
- **What can I build?** → [Network Device Gallery](concepts/Network_Device_Gallery.md)
- **How to use the framework?** → [Framework Guide](concepts/Framework_Guide.md)
- **Building a module?** → [SDK Quick Start](../sdk/docs/SDK_Quick_Start.md) / [SDK 快速开始](../sdk/docs/zh-CN/SDK_Quick_Start.md)
- **Module dev guide?** → [Module Developer Guide](development/Module_Developer_Guide.md)
- **ABI compatibility?** → [ABI Policy](development/ABI_POLICY.md)
- **Migrating old headers?** → [SDK Migration Guide](../sdk/docs/SDK_Migration_Guide.md) / [SDK 迁移指南](zh-CN/sdk/SDK_Migration_Guide.md)
- **Deploying to production?** → [Systemd Integration](deployment/Systemd_Integration.md)
- **Management UI?** → [Management Portal](deployment/Management_Portal.md)
- **Need API details?** → [API Reference](development/API_Reference.md)
- **Intent-based config?** → [Intent Engine](usage/Intent_Engine.md)
- **What's coming next?** → [Product Backlog](backlog/product-backlog.md)

---

*Last updated: 2026-03-29*
