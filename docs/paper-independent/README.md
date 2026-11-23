# 独立论文工作区：跨 hook XDP 更新中的缓存出口选择

> 分支 `paper/independent-cross-hook-xdp`，基线 `dev 8850f7f`，2026-11-23。
> 用途：承载现稿 `Computer_Networks_Manuscript.pdf` 复位为独立论文的全部工作文档。
> 边界：只新增 `docs/paper-independent/`，不修改 `bpf/`、`user/`、`src/`、`Makefile` 或任何核心实现；未 push。

## 与主线分支的关系

| 分支 | 目录 | 主题 |
|---|---|---|
| `paper/rswitch-weaving` | `docs/paper/` | 主线复位：框架 → 流量编织 → 应用，对齐 R0 的 P1 与 P2 |
| `paper/independent-cross-hook-xdp` | `docs/paper-independent/` | 独立机制论文：跨 hook 更新中被选中的入口对象与实际执行的出口对象的区分 |

两个分支同从 `dev` 切出、互不依赖，目录不相交。独立论文不占 R0 的 P1–P4 编号：按 `PUBLICATION_STRATEGY.md` §3 的 Anti-Salami 规则与 `RESEARCH_BRIEF_v0.2.md` §7 的 Optional Paper 成立逻辑，登记为研究组合之外的 standalone mechanism study，并需在 `PAPER_PORTFOLIO.md` 中补一条贡献合同。

## 实现版本口径

现稿参考文献 [8] 与 `jz_sniff_rn` 的 submodule pin 同为 `c10fbd8e15dc68fad936fead1f207b950d1ee296`（`v2.2.0` tag，也是 `origin/main`）。本分支基线 `dev 8850f7f` 与之分叉：`merge-base --is-ancestor c10fbd8 HEAD` 退出 1，`c10fbd8..HEAD` 为 3 个提交、`HEAD..c10fbd8` 为 8 个提交。本分支是文档分支，**不得**用其代码状态代替现稿所引的冻结实现；复现实验须显式 checkout `c10fbd8`，并按 `EXPERIMENT_QUALITY_GATE.md` Q1 记录 commit、kernel、NIC、driver、CPU、XDP mode、topology、profile、config 与 random seed。

## 文档清单

| 文件 | 内容 |
|---|---|
| `00-A-C-B策略判断与R0纲领对齐.md` | 对用户提出的 `A→C→B` 给出判断、编号口径对齐与推荐序列 |
| `01-独立论文契约与主线边界.md` | 独立 RQ、机制、实验、失败条件、主要 claim、共享内容声明与禁句 |
| `02-手稿骨架与逐节复位说明.md` | 现稿复位为独立论文的逐节规格，全部数字引自现稿，不新增实验 |
| `03-证据缺口与投稿闸门.md` | Q0–Q5、Claim Gate、Submission Gate 对账，必须补实验清单与 venue 模板 |

## 使用约定

- 中文叙述一律使用弯引号；英文原文引述中的标点逐字保留。
- 标题不预告枚举，数量信息在正文与表格中呈现。
- 所有未核实事项集中标注，不以推断充当事实；R0 原文引述保留原文件节号或行号。
- 本目录文档属于研究协调与写作准备，按 R0 `README.md` 的 Research Boundary，不构成对实现仓库的直接修改授权。
