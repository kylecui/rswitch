# 变更日志

本项目的所有重要变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

## [未发布]

### 新增
- SDK快速开始中新增独立libbpf加载指南 — 文档化 `__RSWITCH_MAPS_H` 逃逸机制，适用于使用自定义加载器（非 `rs_loader`）的项目

### 修复
- `sdk/include/rswitch_bpf.h`: 修复相对路径引用 `../core/map_defs.h` → `map_defs.h`（修复下游SDK贩售构建）
- Makefile: `INCLUDES` 新增 `-I./sdk/include`，使 `bpf/core/module_abi.h` 构建时能找到 `rswitch_abi.h`
- `.gitmodules`: libbpf子模块从私有SSH URL（`git@github.com:kylecui/libbpf.git`）改为公开HTTPS（`https://github.com/libbpf/libbpf.git`）
- `rswitch_abi.h` / `uapi.h`: 添加交叉头文件保护，防止同时包含时 `rs_layers` 和 `rs_ctx` 结构体重复定义
- `install.sh`: apt依赖列表新增 `libsystemd-dev`（`sd_notify` 构建所需）

---

## [2.1.0] - 2026-03-29

### 新增
- 遵循Keep a Changelog格式的CHANGELOG.md
- ABI策略文档中新增保留字节分配注册表
- Systemd集成文档中新增下游服务排序指南
- MAP_PINNING.md中新增共享map发现表
- SDK迁移指南（`sdk/docs/SDK_Migration_Guide.md`），包含头文件映射表和分步迁移说明
- `sdk/scripts/generate_vmlinux.sh` 辅助脚本，用于生成vmlinux.h
- 所有旧版头文件添加弃用警告（`#warning`）：`uapi.h`、`map_defs.h`、`rswitch_bpf.h`、`module_abi.h`
- 热重载架构文档（`docs/development/Hot_Reload.md`）
- SDK快速开始中新增逐模块配置替代方案指南（BPF map、EnvironmentFile、配置文件模式）
- ABI v1→v2迁移指南（`docs/development/ABI_Migration_v1_to_v2.md`），包含分步清单和常见陷阱
- CI中新增多内核编译矩阵（`kernel-compat` 任务）— 验证CO-RE BTF对6.2、6.5、6.8内核头文件的兼容性
- CI性能基线任务（`perf-baseline`）— 通过 `BPF_PROG_TEST_RUN` 测量每包延迟，支持回归检测
- `test/ci/test_perf_baseline.c` — 使用重复模式数据包注入的BPF性能测试
- 性能测试文档（`docs/development/Performance_Testing.md`）
- 中文翻译新增：VOQd设置、网卡配置、API参考、Map固定、平滑降级、性能测试
- `rswitch_loader` 新增 `sd_notify` 就绪协议 — 管道加载后向systemd发送 `READY=1`，关闭时发送 `STOPPING=1`
- FHS安装配置（`install.sh --fhs`）— 安装到 `/usr/lib/rswitch`，配置目录 `/etc/rswitch`，日志目录 `/var/log/rswitch`
- Systemd集成文档新增FHS安装布局章节

### 变更
- MAP_PINNING.md: 明确约定 — 核心map使用 `/sys/fs/bpf/` 扁平路径（带 `rs_` 前缀），用户模块使用 `/sys/fs/bpf/<project>/` 子目录
- `module_abi.h`（sdk + bpf/core）: 从202行的重复定义缩减为18行的薄层包装器，重导出 `rswitch_abi.h`
- SDK快速开始: 新增 `generate_vmlinux.sh` 用法和迁移指南链接
- README.md: 热重载状态从"计划中"更新为"✅ 已实现"
- README.md: 逐模块配置标记为"计划中 (v2.1)"，带版本目标
- `rswitch.service`: `Type=forking` → `Type=notify`，添加 `NotifyAccess=all`；移除PIDFile
- `rswitch-init.sh`: 加载器通过 `exec` 前台启动（sd_notify所需）
- Makefile: 加载器链接 `-lsystemd` 并定义 `-DHAVE_SYSTEMD`
- `install.sh` 服务heredoc: 更新为 `Type=notify` 及 `NotifyAccess=all`

### 修复
- MAP_PINNING.md与 `rswitch_helpers.h` 关于子目录固定路径的矛盾

---

## [2.0.1] - 2026-03-28

### 修复
- **mgmtd**: mDNS组播加入现在无限重试（指数退避），而不是静默失败

---

## [2.0.0] - 2026-03-24

### 新增
- **ABI v2.0**: `rs_ctx.reserved` 从16字节（`[4]`）扩展到64字节（`[16]`），用于未来次版本字段
- **ABI v2.0**: 用户入站阶段范围200-299，用户出站阶段范围400-499
- **ABI v2.0**: 用户事件类型范围 `0x1000-0x7FFF`
- **ABI v2.0**: `RS_FLAG_MAY_REDIRECT` 能力标志（位6）
- **ABI v2.0**: 模块依赖声明宏（`RS_DEPENDS_ON`）
- **SDK**: 独立模块开发套件，统一入口 `rswitch_module.h`
- **SDK**: 可安装包（`make install-sdk`），集成pkg-config
- **SDK**: `SDK_Quick_Start.md` 教程（820行）和 `Module_Development_Spec.md`
- **SDK**: `Makefile.module` 用于树外模块构建
- **CI**: BPF测试工具（`test_harness.h`）、GitHub Actions流水线、clang-format
- **文档**: ABI稳定性策略 — 版本合约、稳定性层级、弃用规则
- **文档**: 优雅降级协议
- **文档**: 贡献指南（PR流程、编码标准）
- **文档**: 双语文档 — 13份中文翻译
- **文档**: 平台架构综合设计文档
- **文档**: 概念文档（可重构架构、网络设备画廊、框架指南）
- **法律**: LGPL-2.1-or-later许可证文件
- **法律**: 所有源文件添加SPDX-License-Identifier头

### 变更
- **ABI**: 主版本从1.0升级到2.0（破坏性变更：结构体布局变化）
- **头文件**: 重构为统一SDK头文件（`rswitch_abi.h`、`rswitch_helpers.h`、`rswitch_maps.h`、`rswitch_module.h`）
- **README**: 更新了准确的功能状态表和已知限制
- **归档**: 历史文档添加了ARCHIVED通知头

### 修复
- **BPF测试**: `BPF_PROG_TEST_RUN` 的per-CPU上下文扫描包含 `action`/`ifindex`
- **AF_XDP**: 使用 `rx_queue_index` 替代硬编码 `queue_id=0`
- **AF_XDP**: 标准化XSKMAP固定路径
- **AF_XDP**: 添加 `sendto()` TX唤醒
- **AF_XDP**: 在ACTIVE模式下解耦AF_XDP重定向与ringbuf
- **AF_XDP**: 栈式帧池替代线性分配器，防止TX帧耗尽

### 移除
- 清理 `.bak` 遗留文件

---

## [1.0.0] - 2026-01-15

### 新增
- **管理门户**: 完整Web管理界面 — 命名空间隔离、DHCP IP获取、REST API、实时WebSocket监控
- **管理门户**: 会话Cookie认证、速率限制
- **管理门户**: 配置管理页面、VLAN端口下拉框、真实端口名
- **管理门户**: SQLite事件持久化、REST查询API、实时事件流
- **管理门户**: 管理网络配置页面
- **QoS**: IP报文流量分类和优先级提取
- **QoS**: AF_XDP套接字管理集成VOQd数据面
- **QoS**: 无硬件队列NIC的软件队列模拟
- **QoS**: CLI工具（`rsqosctl`、`rsvoqctl`）
- **DHCP**: DHCP嗅探与可信端口强制执行
- **ACL**: 用户自定义ACL规则优先级
- **Systemd**: rswitch、failsafe、mgmtd、watchdog服务单元
- **Systemd**: 故障安全L2桥接脚本
- **安装器**: 一行安装/卸载脚本，自动端口检测，CLI接口选择
- **配置**: 重组配置文件，移除硬编码接口引用
- **测试**: ARP学习、L2学习、路由、镜像、STP、限速器、源守卫、连接跟踪单元测试
- **文档**: 管理门户部署指南、双语概念文档、QoS测试指南

### 变更
- **加载器**: 通过 `RSWITCH_HOME` 环境变量解析BPF对象路径
- **加载器**: 分离出站 `prog_array` 以修复kernel 6.8.0 `owner_prog_type` 强制执行
- **BPF**: `RS_MAX_INTERFACES` 扩展到256
- **BPF**: 入站和出站模块对齐模块开发规范
- **出站**: `prog_array` 的降序槽分配
- **服务**: 更新服务单元和Makefile用于生产安装路径

### 修复
- **AF_XDP**: 多项修复 — XSKMAP查找、TX唤醒、帧分配、重定向解耦
- **出站VLAN**: BPF验证器拒绝和标签推/弹时的偏移更新
- **安装器**: 在调用日志辅助函数之前创建日志目录
- **mgmtd**: 配置切换现在正确更新仪表盘和模块
- **mgmtd**: 验证 `web_root` 路径，无效时回退到默认值
- **mgmtd**: VLAN配置同步到BPF数据面
- **门户**: WebSocket认证预检，防止过期会话重连循环
- **初始化**: 启动接口前刷新交换端口IP

---

## [0.9] - 2025-11-17

### 新增
- 初始XDP流水线 — 入站/出站双流水线架构
- BPF模块: dispatcher、VLAN、ACL、route、L2 learn、last-call、mirror、出站模块
- VOQd用户空间QoS调度器（BYPASS/SHADOW/ACTIVE模式）
- AF_XDP集成用于高吞吐转发
- YAML配置文件系统
- 启动、诊断和健康检查脚本

### 修复
- IP校验和验证和DSCP/ECN变更的增量更新
- 多个模块的BPF验证器兼容性改进
- `qos_stats_map` 的map固定
- VOQd启动竞态条件检测

---

[未发布]: https://github.com/kylecui/rswitch/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/kylecui/rswitch/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/kylecui/rswitch/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/kylecui/rswitch/compare/v0.9...v1.0.0
[0.9]: https://github.com/kylecui/rswitch/releases/tag/v0.9
