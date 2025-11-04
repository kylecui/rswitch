# rSwitch Documentation Index

## 📚 文档概览

本目录包含 rSwitch 项目的完整文档，涵盖从概念设计到实际部署的所有方面。

### 当前阶段：Phase 5 - 生产就绪文档化

✅ **Phase 1-4 完成率**: 17/17 tasks (100%)  
🔧 **Phase 5 进度**: Documentation (完成), Performance Benchmarking (待硬件), Testing (待硬件)

---

## 📖 核心文档（按阅读顺序）

### 1. 快速入门

- **[Migration Guide](Migration_Guide.md)** (118KB, 5367 行) ⭐⭐⭐
  - **目标读者**: 所有用户 - 从 PoC 迁移、新部署、模块开发
  - **内容**:
    - 框架核心能力介绍（7 大能力）
    - 5 分钟快速开始
    - PoC vs Production 架构对比
    - 完整的模块开发指南
    - 5 种部署模式（L2/VLAN/L3/防火墙/边缘节点）
    - 配置详解（Profile, 端口, ACL, VOQd）
    - 性能调优（NIC, CPU, 内存, XDP, VOQd）
    - 故障排查和调试
    - 完整 API 参考（CLI, C, Python）
    - FAQ 和最佳实践
  - **何时阅读**: 🔥 最优先阅读 - 部署前必读

### 2. 概念与设计

- **[rSwitch_Definition.md](rSwitch_Definition.md)**
  - **目标读者**: 架构师、技术决策者
  - **内容**:
    - rSwitch 的核心定义
    - 工程价值主张
    - 与传统交换机的对比
    - 应用场景
  - **何时阅读**: 了解"rSwitch 是什么"时

- **[Reconfigurable_Switch_Overview.md](Reconfigurable_Switch_Overview.md)**
  - **目标读者**: 网络工程师、系统架构师
  - **内容**:
    - 可重配置交换机概述
    - 技术能力
    - 业务价值
  - **何时阅读**: 评估技术可行性时

### 3. 详细设计

- **[data_plane_desgin_with_af_XDP.md](data_plane_desgin_with_af_XDP.md)**
  - **目标读者**: 数据平面开发者、性能工程师
  - **内容**:
    - 完整的 XDP + AF_XDP 混合数据平面设计
    - 3-state 状态机（BYPASS/SHADOW/ACTIVE）
    - VOQ 调度器设计
    - 拥塞控制机制
    - 遥测架构
    - 性能基准测试方法
  - **何时阅读**: 深入理解数据平面实现时

- **[discussions.md](discussions.md)**
  - **目标读者**: 开发者、架构师
  - **内容**:
    - 设计决策的 Q&A
    - 优先级隔离策略
    - NIC 队列管理
    - 控制平面设计考量
  - **何时阅读**: 遇到设计问题或需要理解设计理由时

### 4. 开发与迁移

- **[Milestone1_plan.md](Milestone1_plan.md)**
  - **目标读者**: 项目团队、贡献者
  - **内容**:
    - PoC → Production 迁移的分步计划
    - 5 个 Phase 的详细任务
    - 模块化重构路线图
  - **何时阅读**: 规划开发任务时

- **[CO-RE_Guide.md](CO-RE_Guide.md)** (71KB)
  - **目标读者**: BPF 模块开发者
  - **内容**:
    - CO-RE 技术详解
    - vmlinux.h 使用指南
    - 模块可移植性最佳实践
    - 常见陷阱和解决方案
  - **何时阅读**: 开发新模块或解决兼容性问题时

- **[Module_Portability_Report.md](Module_Portability_Report.md)** (12KB)
  - **目标读者**: 模块分发者、客户
  - **内容**:
    - 模块分类和分发策略
    - CO-RE 兼容性矩阵
    - 部署场景示例
  - **何时阅读**: 计划模块分发或自定义部署时

- **[CO-RE_Migration_Complete.md](CO-RE_Migration_Complete.md)** (20KB)
  - **目标读者**: 维护者、迁移执行者
  - **内容**:
    - 完整的 CO-RE 迁移过程记录
    - 7 个主要问题的解决方案
    - 验证结果
  - **何时阅读**: 参考历史迁移经验时

### 5. 评估与就绪性

- **[Phase5_Readiness_Assessment.md](Phase5_Readiness_Assessment.md)**
  - **目标读者**: 项目经理、测试团队
  - **内容**:
    - Phase 1-4 完成情况验证
    - Phase 5 任务分析
    - 当前环境限制（Azure VM vs 真实硬件）
    - 行动建议
  - **何时阅读**: 评估项目状态和下一步计划时

---

## 🛠️ 工具文档

- **[tools/README_inspect_module.md](../tools/README_inspect_module.md)**
  - inspect_module.py 工具使用指南
  - 模块 CO-RE 兼容性检查
  - 何时使用：验证新模块或检查现有模块

---

## 🧪 示例和演示

### Scaffold 原型

- **[demos/rswitch_scaffold/](demos/rswitch_scaffold/)**
  - **rswitch-xdp/**: XDP 层原型（ringbuf, devmap, state_map）
  - **rswitch-voqd/**: VOQd 用户空间调度器原型

---

## 📊 文档统计

| 文档 | 大小 | 主题 | 优先级 |
|------|------|------|--------|
| Migration_Guide.md | 118 KB | 完整指南 | ⭐⭐⭐ 必读 |
| CO-RE_Guide.md | 71 KB | CO-RE 技术 | ⭐⭐ 开发必读 |
| data_plane_desgin_with_af_XDP.md | ~30 KB | 数据平面设计 | ⭐⭐ 深入理解 |
| CO-RE_Migration_Complete.md | 20 KB | 迁移记录 | ⭐ 参考 |
| Module_Portability_Report.md | 12 KB | 模块分发 | ⭐⭐ 分发必读 |
| Phase5_Readiness_Assessment.md | ~10 KB | 项目状态 | ⭐⭐ 管理必读 |

---

## 🎯 推荐阅读路径

### 路径 1: 快速部署用户

```
1. Migration_Guide.md (前 2 节：概述、快速开始)
   └─ 理解 rSwitch 是什么，5 分钟体验

2. Migration_Guide.md (第 6 节：部署模式)
   └─ 选择适合的部署模式

3. Migration_Guide.md (第 7 节：配置详解)
   └─ 根据需求调整配置

4. 开始部署！
```

### 路径 2: 模块开发者

```
1. Migration_Guide.md (第 1 节：概述)
   └─ 了解框架整体架构

2. CO-RE_Guide.md
   └─ 掌握 CO-RE 编程模式

3. Migration_Guide.md (第 5 节：模块开发)
   └─ 学习模块开发流程

4. bpf/modules/core_example.bpf.c
   └─ 参考示例模块

5. tools/inspect_module.py
   └─ 验证自己的模块
```

### 路径 3: 性能工程师

```
1. Migration_Guide.md (第 8 节：性能调优)
   └─ NIC/CPU/内存优化

2. data_plane_desgin_with_af_XDP.md
   └─ 理解数据平面设计

3. Migration_Guide.md (Appendix D: 性能基准参考)
   └─ 了解预期性能

4. tools/perf-tests/
   └─ 运行基准测试
```

### 路径 4: 架构师/决策者

```
1. rSwitch_Definition.md
   └─ 核心价值主张

2. Reconfigurable_Switch_Overview.md
   └─ 技术能力概述

3. Migration_Guide.md (第 4 节：架构对比)
   └─ PoC vs Production

4. discussions.md
   └─ 设计决策理由

5. Phase5_Readiness_Assessment.md
   └─ 当前状态和风险
```

### 路径 5: 从 PoC 迁移

```
1. Migration_Guide.md (第 4 节：从 PoC 迁移)
   └─ 迁移步骤和注意事项

2. Milestone1_plan.md
   └─ 完整迁移路线图

3. CO-RE_Migration_Complete.md
   └─ 历史迁移经验

4. Migration_Guide.md (第 5-10 节)
   └─ 新框架使用指南
```

---

## 🔍 快速查找

### 按问题类型查找

| 问题类型 | 推荐文档 | 章节 |
|---------|---------|------|
| **如何部署？** | Migration_Guide.md | 第 2, 6 节 |
| **如何开发模块？** | Migration_Guide.md | 第 5 节 |
| **性能不达标** | Migration_Guide.md | 第 8 节 |
| **遇到错误** | Migration_Guide.md | 第 9 节 |
| **CO-RE 兼容性问题** | CO-RE_Guide.md | 第 3-5 节 |
| **配置语法** | Migration_Guide.md | 第 7 节 |
| **API 使用** | Migration_Guide.md | 第 10 节 |
| **设计理由** | discussions.md | 全文 |
| **数据平面细节** | data_plane_desgin_with_af_XDP.md | 第 2-4 节 |

### 按组件查找

| 组件 | 推荐文档 | 章节 |
|------|---------|------|
| **Dispatcher** | Migration_Guide.md | 第 3 节 |
| **VLAN 模块** | Migration_Guide.md | 第 5, 7 节 |
| **VOQd** | data_plane_desgin_with_af_XDP.md | 第 2-3 节 |
| **L2Learn** | Migration_Guide.md | 第 5, 8 节 |
| **ACL** | Migration_Guide.md | 第 5, 7 节 |
| **Profile 系统** | Migration_Guide.md | 第 6, 7 节 |
| **Telemetry** | Migration_Guide.md | 第 3, 8 节 |

---

## 🆕 最近更新

### 2024-11-04
- ✅ **创建 Migration_Guide.md** (118KB)
  - 完整的框架能力介绍（7 大能力）
  - 模块开发完整指南（Stage 编号、CO-RE 最佳实践、示例）
  - 5 种部署模式详解（L2/VLAN/L3/防火墙/边缘节点）
  - 性能调优检查清单（NIC/CPU/内存/XDP/VOQd）
  - 故障排查指南（5 个常见问题）
  - 完整 API 参考（rswitchctl, C API, Python API）
  - 10+ FAQ
  - 配置示例库（3 个完整场景）
  - 性能基准参考（2 套硬件配置）

### 2024-11-03
- ✅ CO-RE 迁移完成 (7/7 模块 CO-RE 兼容)
- ✅ Phase5_Readiness_Assessment.md (项目状态评估)
- ✅ Module_Portability_Report.md (模块分发策略)

### 2024-11-02
- ✅ CO-RE_Guide.md (71KB, CO-RE 技术指南)
- ✅ CO-RE_Migration_Complete.md (迁移记录)

---

## 📝 贡献指南

### 文档更新原则

1. **保持文档同步**: 代码变更后及时更新相关文档
2. **实例驱动**: 优先提供可运行的示例
3. **版本标记**: 重大变更时更新"最近更新"部分
4. **交叉引用**: 使用相对链接连接相关文档

### 文档模板

新文档应包含：
- 目标读者
- 前置知识要求
- 主要内容
- 相关文档链接
- 示例代码（如适用）

---

## 🔗 外部参考

### 官方资源
- [Linux Kernel XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)

### 教程和示例
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [BCC Tools](https://github.com/iovisor/bcc)

---

## 📮 反馈

如果您发现文档中的错误、不清晰的部分或缺失的内容，请：

1. **提交 Issue**（如有 GitHub）
2. **直接修改文档**并提交 PR
3. **联系维护者**

**文档维护者**: rSwitch Team  
**最后更新**: 2024-11-04  
**版本**: 1.0.0
