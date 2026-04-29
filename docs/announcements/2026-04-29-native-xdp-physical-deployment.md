# 📢 Native XDP 物理机部署已验证通过 — 新增两份必读文档

**日期**: 2026-04-29  
**影响范围**: 所有参与 rSwitch 部署、运维、二次开发的人员  
**分支**: `dev`

---

## 背景

我们在 `10.174.1.191` 上完成了**全端口 native XDP + 管理面 namespace** 的端到端验证。这是 rSwitch 第一次在物理机上以 native XDP 模式完整跑通管理面（SSH / Web Portal / mDNS / DHCP / killswitch）。

过程中踩了一系列只有在 native XDP 下才暴露的坑，且这些坑在虚拟机 `xdpgeneric` 环境下完全不会出现。

---

## 新增文档（强制阅读）

### 1. [物理机 Native XDP 部署与运维手册](../zh-CN/deployment/Physical_Machine_Native_XDP_Deployment.md)

**谁必须读**: 任何要在实体设备上部署 rSwitch 的人。

覆盖内容：
- 前期准备与依赖（`dhcpcd`、`libsystemd-dev`、`ethtool`）
- 管理面拓扑与启动流程
- systemd 服务编排要求
- killswitch key 格式
- 启动后如何验证
- 常见故障速查
- 人工兜底救援命令

### 2. [Native XDP 物理机场景排错复盘](../zh-CN/development/Native_XDP_Physical_Debugging_Postmortem.md)

**谁必须读**: 任何准备修改 management / loader / mgmtd / killswitch / systemd wiring 代码的开发者。

覆盖内容：
- 为什么 `xdpgeneric` 能跑但 native XDP 不能
- veth NAPI 静默丢包的根因与修复
- TCP checksum offload 在 XDP redirect 路径下失效的机制
- DHCP client 为什么不会"自动起来"
- systemd Wants/enable 遗漏的典型表现
- 给后续开发者的硬性验证 checklist

---

## 关键代码变更

| Commit | 内容 |
|--------|------|
| `7fee2da` | mgmt0 挂 XDP_PASS（激活 NAPI）+ 关闭 TX offload + 自动启动 dhcpcd |
| `88af515` | 新增两份中文文档 |
| `7626719` | README / 文档索引 / 管理门户文档更新，确保新文档被第一时间看到 |

---

## 行动项

- [ ] **部署人员**: 下次上线物理机前，先读部署手册第 7 节"启动前必须确认的事项"
- [ ] **开发人员**: 修改 management 相关代码前，先读排错复盘第 11 节"硬性建议"
- [ ] **所有人**: 确认你的目标机器上有 `dhcpcd`、killswitch key 文件是两行纯 hex 格式

---

## 一句话总结

> native XDP 物理机管理面能工作，但它**同时依赖** XDP_PASS / TX offload 关闭 / DHCP client 显式启动 / systemd wiring 正确这四个条件。少任何一个都会失败，而且失败现象容易误判。

如有疑问，找 @kylecui 或直接看文档。
