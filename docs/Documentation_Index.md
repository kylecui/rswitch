# rSwitch Documentation Index

> **rSwitch** — A high-performance, modular XDP/eBPF network switch platform with CO-RE compatibility.
>
> 📖 [中文文档](zh-CN/) (Chinese translations available)

---

## 📘 Usage

Getting started and day-to-day operation guides.

| Document | Description |
|----------|-------------|
| [Quick Start](usage/Quick_Start.md) | Build, run, and verify rSwitch in under 5 minutes |
| [How To Use](usage/How_To_Use.md) | Practical usage examples — L2/L3 switching, QoS, firewall, and common workflows |
| [Scenario Profiles](usage/Scenario_Profiles.md) | All 18 YAML profiles explained — purpose, module pipeline, and when to use each |
| [CLI Reference](usage/CLI_Reference.md) | Complete reference for `rswitchctl`, `rsvlanctl`, `rsaclctl`, `rsqosctl`, `rsvoqctl` |
| [Troubleshooting](usage/Troubleshooting.md) | Common issues, diagnostic commands, cleanup procedures, and NIC-specific notes |

---

## 📦 Deployment

Installation, system configuration, and production deployment.

| Document | Description |
|----------|-------------|
| [Installation](deployment/Installation.md) | Build from source, dependencies, kernel requirements, and verification |
| [Configuration](deployment/Configuration.md) | YAML profile structure — `ingress`, `egress`, `settings`, `ports`, `voqd_config` |
| [VOQd Setup](deployment/VOQd_Setup.md) | VOQd QoS scheduler — modes (BYPASS/SHADOW/ACTIVE), AF_XDP, software queues |
| [NIC Configuration](deployment/NIC_Configuration.md) | NIC-specific setup — Intel X710/i40e, Mellanox CX-5/mlx5, Hyper-V hv_netvsc |
| [Systemd Integration](deployment/Systemd_Integration.md) | Service units, auto-start, watchdog, and production deployment patterns |

---

## 🛠️ Development

Architecture deep-dives, module development, and API reference.

| Document | Description |
|----------|-------------|
| [Architecture](development/Architecture.md) | Dual-pipeline architecture, module system, shared context, data structures |
| [Module Developer Guide](development/Module_Developer_Guide.md) | Step-by-step guide to writing BPF modules — from template to production |
| [API Reference](development/API_Reference.md) | Complete API — macros, structs, maps, helpers, flags, error codes |
| [CO-RE Guide](development/CO-RE_Guide.md) | CO-RE portability — `BPF_CORE_READ()`, offset masking, cross-kernel testing |
| [Contributing](development/Contributing.md) | Contribution workflow, coding standards, PR process, licensing |

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
├── usage/                     # User-facing operation guides
│   ├── Quick_Start.md
│   ├── How_To_Use.md
│   ├── Scenario_Profiles.md
│   ├── CLI_Reference.md
│   └── Troubleshooting.md
├── deployment/                # Installation and deployment
│   ├── Installation.md
│   ├── Configuration.md
│   ├── VOQd_Setup.md
│   ├── NIC_Configuration.md
│   └── Systemd_Integration.md
├── development/               # Developer documentation
│   ├── Architecture.md
│   ├── Module_Developer_Guide.md
│   ├── API_Reference.md
│   ├── CO-RE_Guide.md
│   └── Contributing.md
├── backlog/                   # Development roadmap
│   ├── platform-backlog.md
│   ├── api-backlog.md
│   ├── product-backlog.md
│   └── ecosystem-backlog.md
├── zh-CN/                     # Chinese translations
├── archive/                   # Historical documents (preserved)
└── paperwork/                 # Administrative records (preserved)
```

---

## 🔗 Quick Links

- **Just want to run it?** → [Quick Start](usage/Quick_Start.md)
- **Building a module?** → [Module Developer Guide](development/Module_Developer_Guide.md)
- **Deploying to production?** → [Systemd Integration](deployment/Systemd_Integration.md)
- **Need API details?** → [API Reference](development/API_Reference.md)
- **What's coming next?** → [Product Backlog](backlog/product-backlog.md)

---

## 📄 Legacy Documents

The following original documents are preserved for reference. Their content has been reorganized into the categorized structure above.

| Original Document | Migrated To |
|-------------------|-------------|
| `AF_XDP_QoS_Design_Guide.md` | [VOQd Setup](deployment/VOQd_Setup.md), [Architecture](development/Architecture.md) |
| `API_Reference.md` (original) | [API Reference](development/API_Reference.md) |
| `Design_Philosophy.md` | [Architecture](development/Architecture.md) |
| `Design_Review.md` | [Architecture](development/Architecture.md) |
| `Development_Guide.md` | [Module Developer Guide](development/Module_Developer_Guide.md), backlogs |
| `Migration_Guide.md` | Split across all categories; original archived |
| `Module_Developer_Guide.md` (original) | [Module Developer Guide](development/Module_Developer_Guide.md) |
| `Network_Fabric_Design.md` | [Product Backlog §5.1](backlog/product-backlog.md) |
| `Reconfigurable_Architecture.md` | [Architecture](development/Architecture.md) |
| `Software_Queues_Test_Guide.md` | [VOQd Setup](deployment/VOQd_Setup.md) |
| `VOQd_Auto_Start.md` | [Systemd Integration](deployment/Systemd_Integration.md) |
| `veth-egress-guide.md` | [Architecture](development/Architecture.md), examples |

---

*Last updated: 2026-03-10*
