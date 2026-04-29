---
name: generate-usage-docs
description: Use this skill when the user wants grounded usage documentation, README, quick start, configuration docs, API docs, CLI docs, troubleshooting notes, or operator/developer guides derived from the current project's design, interfaces, configuration, or code. It is for synthesizing docs from the current repository, not generic writing help.
license: Proprietary. See project package context.
compatibility: Designed for OpenCode and Agent Skills compatible clients. Prefer Python 3.11+ and uv for running bundled scripts.
metadata:
  audience: project-maintainers
  package: opencode-skill-pack
  skill-family: engineering-docs
---

# Generate Usage Docs

用这项技能时，你的目标是根据**当前项目的真实设计与代码**生成“给人用”的文档，而不是只把源码结构改写一遍。

## 何时使用

当用户提出以下意图时加载本技能：

- 根据当前项目生成使用文档
- 补 README、Quick Start、配置说明、FAQ、排障文档
- 根据 API / CLI / SDK / 配置文件生成文档
- 根据代码和设计文档生成交付级使用说明
- 把零散的设计说明整理成用户导向文档

若用户只是要润色一段文字、翻译文档或写纯创作型内容，不必强制加载本技能。

## 默认方法

先识别**读者与场景**，再识别**项目对外能力**，最后输出**文档集**。  
不要直接堆 API 细节或源码清单。

### Step 1：盘点项目事实

优先读取以下内容：

1. README、docs、设计说明、部署说明
2. OpenAPI / proto / route / controller
3. CLI 帮助、命令入口、子命令
4. package manifest、构建文件、安装方式
5. 配置文件、环境变量、示例配置
6. 示例代码、测试、样例数据
7. 常见报错、日志、故障处理线索

需要快速盘点时，先运行：

```bash
uv run scripts/project_inventory.py .
```

### Step 2：识别文档受众

先判断主要读者是谁：

- end user
- operator
- developer
- integrator
- internal team
- evaluator / reviewer

没有明确受众时，默认按“**首次接触该项目的技术使用者**”写。

### Step 3：识别项目的对外能力

至少梳理这些问题：

- 它是什么
- 适合什么场景
- 如何安装 / 启动 / 调用
- 需要哪些配置
- 核心工作流是什么
- 用户最可能从哪里开始
- 失败时如何排障
- 有哪些限制、注意事项或风险

### Step 4：构建 doc set

按需从以下文档集中选择：

- README.md
- docs/quickstart.md
- docs/configuration.md
- docs/usage.md
- docs/api.md
- docs/cli.md
- docs/troubleshooting.md
- docs/faq.md
- docs/deployment.md

优先生成**最少但完整**的文档集，不要把所有文档都一股脑写满。

### Step 5：区分 narrative 与 reference

必须区分：

- **Narrative docs**：任务导向、上手导向、工作流导向
- **Reference docs**：命令、参数、端点、配置项、返回字段

README 和 quick start 应偏 narrative；API/CLI/config 文档应偏 reference。

### Step 6：生成 grounded 示例

示例必须尽量来自真实项目事实：

- 真实命令
- 真实配置键
- 真实目录
- 真实端点
- 真实参数名
- 真实输入输出

如果无法确认，明确写成“待确认占位”，不要编造。

## 输出顺序

按以下顺序输出：

1. Audience and scope
2. Recommended doc set
3. README 草案
4. Quick Start
5. Configuration / Usage / API / CLI 相关章节
6. Troubleshooting / FAQ
7. 假设与待确认项

## 风格要求

- 先说明“它是什么、适合谁、如何最快跑起来”
- 叙事型文档优先于纯参考型堆砌
- 示例尽量最小可运行
- 优先默认路径，不给冗长菜单
- 避免把内部实现细节直接暴露成用户文档主线
- 区分“对终端用户重要”和“对开发者维护者重要”的信息

## Gotchas

- 不要把安装、启动、配置、最小示例混在一个超长段落中
- 不要把源码目录介绍误写成使用文档
- API / CLI / SDK 项目都应有不同的侧重点
- 不要在信息不足时捏造参数、环境变量、端口、接口返回值
- 用户最先需要的是 quick start，不是完整架构细节
- 故障排查应该基于真实报错线索或高概率失败点

## 按需读取的参考文件

- 需要文档集结构时，读：`references/DOCSET_BLUEPRINT.md`
- 需要 README 与 Quick Start 模板时，读：`references/README_GUIDE.md`
- 需要配置、CLI、API 的写法参考时，读：`references/REFERENCE_GUIDE.md`
- 需要常见错误与边界提醒时，读：`references/GOTCHAS.md`

## 可用校验脚本

当你已经产出一套文档文件后，可运行：

```bash
uv run scripts/validate_docset.py path/to/docset-root
```

这会检查 README 是否存在，以及常见推荐文档是否齐备。

## 最终目标

产出必须能支持以下实际用途：

- 项目首次交付
- 仓库 README 补全
- 对外演示 / 内部交接
- 开发者上手
- 运维或评审快速理解项目
