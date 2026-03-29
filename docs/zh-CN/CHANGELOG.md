# 变更日志

本项目的所有重要变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

## [未发布]

### 新增
- 遵循 Keep a Changelog 格式的 CHANGELOG.md
- ABI 策略文档中新增保留字节分配注册表
- Systemd 集成文档中新增下游服务排序指南
- MAP_PINNING.md 中新增共享 map 发现表
- SDK 迁移指南（`sdk/docs/SDK_Migration_Guide.md`），包含头文件映射表和分步迁移说明
- `sdk/scripts/generate_vmlinux.sh` 辅助脚本，用于生成 vmlinux.h
- 所有旧版头文件添加弃用警告（`#warning`）：`uapi.h`、`map_defs.h`、`rswitch_bpf.h`、`module_abi.h`

### 变更
- MAP_PINNING.md: 明确约定 — 核心 map 使用 `/sys/fs/bpf/` 扁平路径（带 `rs_` 前缀），用户模块使用 `/sys/fs/bpf/<project>/` 子目录
- `module_abi.h`（sdk + bpf/core）: 从 202 行的重复定义缩减为 18 行的薄层包装器，重导出 `rswitch_abi.h`
- SDK 快速开始: 新增 `generate_vmlinux.sh` 用法和迁移指南链接

### 修复
- MAP_PINNING.md 与 `rswitch_helpers.h` 关于子目录固定路径的矛盾

---

## [2.0.1] - 2026-03-28

### 修复
- **mgmtd**: mDNS 组播加入现在无限重试（指数退避），而不是静默失败

---

## [2.0.0] - 2026-03-24

### 新增
- **ABI v2.0**: `rs_ctx.reserved` 从 16 字节（`[4]`）扩展到 64 字节（`[16]`），用于未来次版本字段
- **ABI v2.0**: 用户入站阶段范围 200-299，用户出站阶段范围 400-499
- **ABI v2.0**: 用户事件类型范围 `0x1000-0x7FFF`
- **ABI v2.0**: `RS_FLAG_MAY_REDIRECT` 能力标志（位 6）
- **ABI v2.0**: 模块依赖声明宏（`RS_DEPENDS_ON`）
- **SDK**: 独立模块开发套件，统一入口 `rswitch_module.h`
- **SDK**: 可安装包（`make install-sdk`），集成 pkg-config
- **SDK**: `SDK_Quick_Start.md` 教程（820 行）和 `Module_Development_Spec.md`
- **SDK**: `Makefile.module` 用于树外模块构建
- **CI**: BPF 测试工具（`test_harness.h`）、GitHub Actions 流水线、clang-format
- **文档**: ABI 稳定性策略 — 版本合约、稳定性层级、弃用规则
- **文档**: 优雅降级协议
- **文档**: 贡献指南（PR 流程、编码标准）
- **文档**: 双语文档 — 13 份中文翻译
- **文档**: 平台架构综合设计文档
- **文档**: 概念文档（可重构架构、网络设备画廊、框架指南）
- **法律**: LGPL-2.1-or-later 许可证文件
- **法律**: 所有源文件添加 SPDX-License-Identifier 头

### 变更
- **ABI**: 主版本从 1.0 升级到 2.0（破坏性变更：结构体布局变化）
- **头文件**: 重构为统一 SDK 头文件（`rswitch_abi.h`、`rswitch_helpers.h`、`rswitch_maps.h`、`rswitch_module.h`）
- **README**: 更新了准确的功能状态表和已知限制
- **归档**: 历史文档添加了 ARCHIVED 通知头

### 修复
- **BPF 测试**: `BPF_PROG_TEST_RUN` 的 per-CPU 上下文扫描包含 `action`/`ifindex`
- **AF_XDP**: 使用 `rx_queue_index` 替代硬编码 `queue_id=0`
- **AF_XDP**: 标准化 XSKMAP 固定路径
- **AF_XDP**: 添加 `sendto()` TX 唤醒
- **AF_XDP**: 在 ACTIVE 模式下解耦 AF_XDP 重定向与 ringbuf
- **AF_XDP**: 栈式帧池替代线性分配器，防止 TX 帧耗尽

### 移除
- 清理 `.bak` 遗留文件

---

## [1.0.0] - 2026-01-15

### 新增
- **管理门户**: 完整 Web 管理界面 — 命名空间隔离、DHCP IP 获取、REST API、实时 WebSocket 监控
- **管理门户**: 会话 Cookie 认证、速率限制
- **管理门户**: 配置管理页面、VLAN 端口下拉框、真实端口名
- **管理门户**: SQLite 事件持久化、REST 查询 API、实时事件流
- **管理门户**: 管理网络配置页面
- **QoS**: IP 报文流量分类和优先级提取
- **QoS**: AF_XDP 套接字管理集成 VOQd 数据面
- **QoS**: 无硬件队列 NIC 的软件队列模拟
- **QoS**: CLI 工具（`rsqosctl`、`rsvoqctl`）
- **DHCP**: DHCP 嗅探与可信端口强制执行
- **ACL**: 用户自定义 ACL 规则优先级
- **Systemd**: rswitch、failsafe、mgmtd、watchdog 服务单元
- **Systemd**: 故障安全 L2 桥接脚本
- **安装器**: 一行安装/卸载脚本，自动端口检测，CLI 接口选择
- **配置**: 重组配置文件，移除硬编码接口引用
- **测试**: ARP 学习、L2 学习、路由、镜像、STP、限速器、源守卫、连接跟踪单元测试
- **文档**: 管理门户部署指南、双语概念文档、QoS 测试指南

### 变更
- **加载器**: 通过 `RSWITCH_HOME` 环境变量解析 BPF 对象路径
- **加载器**: 分离出站 `prog_array` 以修复 kernel 6.8.0 `owner_prog_type` 强制执行
- **BPF**: `RS_MAX_INTERFACES` 扩展到 256
- **BPF**: 入站和出站模块对齐模块开发规范
- **出站**: `prog_array` 的降序槽分配
- **服务**: 更新服务单元和 Makefile 用于生产安装路径

### 修复
- **AF_XDP**: 多项修复 — XSKMAP 查找、TX 唤醒、帧分配、重定向解耦
- **出站 VLAN**: BPF 验证器拒绝和标签推/弹时的偏移更新
- **安装器**: 在调用日志辅助函数之前创建日志目录
- **mgmtd**: 配置切换现在正确更新仪表盘和模块
- **mgmtd**: 验证 `web_root` 路径，无效时回退到默认值
- **mgmtd**: VLAN 配置同步到 BPF 数据面
- **门户**: WebSocket 认证预检，防止过期会话重连循环
- **初始化**: 启动接口前刷新交换端口 IP

---

## [0.9] - 2025-11-17

### 新增
- 初始 XDP 流水线 — 入站/出站双流水线架构
- BPF 模块: dispatcher、VLAN、ACL、route、L2 learn、last-call、mirror、出站模块
- VOQd 用户空间 QoS 调度器（BYPASS/SHADOW/ACTIVE 模式）
- AF_XDP 集成用于高吞吐转发
- YAML 配置文件系统
- 启动、诊断和健康检查脚本

### 修复
- IP 校验和验证和 DSCP/ECN 变更的增量更新
- 多个模块的 BPF 验证器兼容性改进
- `qos_stats_map` 的 map 固定
- VOQd 启动竞态条件检测

---

[未发布]: https://github.com/kylecui/rswitch/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/kylecui/rswitch/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/kylecui/rswitch/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/kylecui/rswitch/compare/v0.9...v1.0.0
[0.9]: https://github.com/kylecui/rswitch/releases/tag/v0.9
