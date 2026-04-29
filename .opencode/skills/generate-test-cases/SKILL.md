---
name: generate-test-cases
description: Use this skill when the user wants test cases, a test matrix, regression cases, acceptance cases, API tests, CLI tests, UI tests, or automated test ideas derived from the current project's design, interfaces, configuration, or code. It is for grounded synthesis from the current repository, not for generic testing advice.
license: Proprietary. See project package context.
compatibility: Designed for OpenCode and Agent Skills compatible clients. Prefer Python 3.11+ and uv for running bundled scripts.
metadata:
  audience: project-maintainers
  package: opencode-skill-pack
  skill-family: engineering-quality
---

# Generate Test Cases

用这项技能时，你的目标不是泛泛而谈“应该测试什么”，而是**基于当前项目的真实设计与代码**，生成可追溯、可执行、可迭代的测试产物。

## 何时使用

当用户提出以下意图时加载本技能：

- 根据当前项目/模块/设计文档生成 test cases
- 为 API、CLI、Web UI、SDK、库或服务生成测试矩阵
- 生成冒烟测试、回归测试、负面测试、边界测试、验收测试
- 根据设计和代码补齐测试覆盖思路
- 为现有仓库提供自动化测试建议或测试文件骨架

若用户只是问“什么是单元测试”“测试有哪些类型”之类的通用问题，不必强制加载本技能。

## 默认方法

先做**项目盘点**，再做**追踪映射**，最后做**分层测试产物**。  
不要直接跳到“写若干条例子”。

### Step 1：盘点项目事实

优先读取以下材料：

1. README、docs、设计说明、架构说明
2. API 规范、proto、route、controller、schema
3. 配置样例、环境变量、构建文件
4. 入口程序、CLI 帮助、public API
5. 现有 tests 目录与测试框架
6. 关键状态机、权限、持久化、外部依赖

需要快速盘点时，先运行：

```bash
uv run scripts/project_inventory.py .
```

先根据盘点结果判断项目更接近哪一类：

- library / SDK
- CLI
- Web API
- Web UI
- daemon / service
- pipeline / job
- research prototype / demo

### Step 2：建立 traceability map

把“设计目标 / 模块 / 接口 / 风险”映射到“应测点”。

至少覆盖这些维度：

- 功能点
- 正常路径
- 异常路径
- 边界条件
- 状态迁移
- 认证 / 授权
- 幂等 / 重试 / 回滚
- 并发 / 时序
- 配置错误
- 外部依赖失败
- 兼容性 / 回归风险

输出 traceability matrix 时，优先使用 `assets/traceability-matrix-template.md` 的格式。

### Step 3：生成分层测试策略

从适用层中选择，而不是机械地全部输出：

- Unit tests
- Integration tests
- Contract / API tests
- CLI tests
- E2E / UI tests
- Smoke tests
- Regression tests
- Negative / abuse-adjacent tests
- Acceptance tests

给出“优先自动化的部分”和“暂时保留人工验证的部分”。

### Step 4：生成测试用例

每条测试用例至少要包含：

- Case ID
- 标题
- 目标 / Objective
- Target module / endpoint / command
- Preconditions
- 输入 / 测试数据
- 步骤
- 预期结果
- 优先级
- 覆盖风险
- 自动化建议

优先使用 `assets/test-case-template.md` 或 `assets/test-cases.schema.json` 的字段风格。

### Step 5：在信息足够时给出脚手架

只有在项目结构足够清晰时，才生成：

- pytest 测试文件骨架
- Playwright spec 骨架
- API contract 测试骨架
- 样例 fixtures / mocks / fake services 建议

**不得编造**不存在的模块名、路径、路由、参数、配置键或行为。

## 输出顺序

按以下顺序输出：

1. 项目理解摘要
2. 测试策略
3. traceability matrix
4. 测试用例列表
5. 建议的目录布局
6. 自动化优先级
7. 不确定项 / 待确认项

## 风格要求

- 以项目事实为基础，不给空泛建议
- 先整体策略，再详细 case
- 正常 / 异常 / 边界 三类必须区分
- 说明“这个 case 是从设计推导，还是从实现观察得出”
- 发现信息不足时，明确写出假设
- 优先给默认方案，不要一上来列很多菜单式选项

## Gotchas

- 现有实现不等于设计意图；不要把偶然实现细节当作产品需求
- 若项目已经有测试约定，优先沿用现有框架和目录命名
- 若无现有测试框架，先给推荐，再给骨架
- 对高风险路径，宁可少写空泛 case，也要写清楚关键前置条件和断言
- 当你生成 JSON 版测试用例时，用 `scripts/validate_test_case_json.py` 做结构校验

```bash
uv run scripts/validate_test_case_json.py path/to/test-cases.json
```

## 按需读取的参考文件

- 需要详细输出规范时，读：`references/OUTPUT_FORMAT.md`
- 需要 traceability 思路时，读：`references/TRACEABILITY_GUIDE.md`
- 需要判断哪些风险最常漏测时，读：`references/GOTCHAS.md`

## 最终目标

产出必须让维护者能够直接拿去做下一步工作：

- 讨论测试范围
- 编写自动化测试
- 制定回归计划
- 作为验收或 QA 清单
