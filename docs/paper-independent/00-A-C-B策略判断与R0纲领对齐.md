# A→C→B 策略判断与 R0 纲领对齐

> 依据：R0 本地导出包 `BOUNDED_TRAFFIC_WEAVING_RESEARCH_FOUNDATION_v1.0`（2026-06-14，`MANIFEST.json` 的 files 数组列 20 个文件，磁盘共 21 个含清单自身）、主线分支 `docs/paper/01-选题复位评估卡.md`、现稿 `Computer_Networks_Manuscript.pdf` 全文。
> 定位：策略评估，不含论文正文。R0 文件以节号标注，原文引述逐字保留。

## 结论

**`A→C→B` 作为研究定位的收敛路径成立且推荐；作为按 A、C、B 依次发表的序列不成立，且起点 A 必须改写。**

用户口头的“框架 → 应用”初衷在 R0 里对应的不是一篇贯通论文，而是 Paper 1 与 Paper 2 之间的依赖链；把现稿独立出去（C）是正确动作，但应理解为清场而非拆主线；终点 B 与 R0 的 Paper 2 完全对齐，只是它的投稿闸门尚未打开。按 R0 自己的规定，P1 与 P2 应并行冻结边界，P2 不等待 P1 发表后才开始实验；但 `RESEARCH_BRIEF_v0.2.md` §15 与 §12 本身仍给出先后工作步骤，R0 禁止的是发表时序依赖，不是一切先后步骤。

## 先对齐编号口径

| 来源 | 记号 | 含义 |
|---|---|---|
| `01-选题复位评估卡.md` §论文形态 | A | 框架-应用贯通系统论文：rSwitch 框架层与 jz 应用层写进一篇，应用为并列贡献 |
| 同上 | B | 应用／防御系统论文，框架作支撑；P2 纲领文本本身更接近此形态 |
| 同上 | C | 拆两篇：现稿补实验后投机制短文，加上框架-应用系统论文，即 C 内含 A |
| R0 `PUBLICATION_STRATEGY.md` §1 与 §2 | P1 | Reconfigurable substrate；独立问题：如何构建可组合、可热更新的 XDP/AF_XDP 网络底座；不得依赖 P2 安全收益 |
| 同上 | P2 | Bounded containment；独立问题：bounded traffic weaving 是否改善安全／业务 Pareto 边界；不得主要依赖平台性能 claim |
| R0 `RESEARCH_BRIEF_v0.2.md` §7 | Paper 1 / Paper 2 | `rSwitch: A Profile-Driven Reconfigurable XDP/AF_XDP Network Substrate` / `Bounded Traffic Weaving for Assumed-Breach Networks` |
| 本分支 | S1 | 现稿独立机制论文，不占 P1–P4 编号 |

由此部分闭环 `01-选题复位评估卡.md` §未核实事项中的两处。其一是 R0 协调仓库的可访问性、论文底稿能否取回，以及复位属续写还是重建：现通过本地 `gh` 确认该仓库为 PRIVATE，并取得本地导出包，足以支撑续写；但协调仓库公开状态未变、论文底稿能否取回仍待核实，故只算部分闭环。其二是 P2 究竟指第二篇论文还是课题二：现由 `PUBLICATION_STRATEGY.md` §1 确认 P2 为 Thesis Spine 第二段的 Bounded containment，由 `RESEARCH_BRIEF_v0.2.md` §7 对应到 Paper 2，不是课题二。

映射关系：A 的框架侧约等于 P1，A 的应用侧约等于 P2，A 在 R0 的组合结构中没有对应形态；B 就是 P2；C 的机制短文就是 S1，C 的主线系统论文应改写为 P1 与 P2 并行。

## 关于 A 的判断

A 与 R0 的平台／安全分离结构不相容，不只是证据不足。`PUBLICATION_STRATEGY.md` §2 规定的是 P1 与 P2 各自不得依赖的 claim 独立性，并未明文禁止框架-应用贯通单篇；真正构成约束的是下列 §10.5、G1 闸门、`RESEARCH_CONSTITUTION.md` §3 第 8 条与 §7 的四篇组合结构：

- `PUBLICATION_STRATEGY.md` §2 规定 P1 不得依赖 P2 安全收益、P3 模型、P4 协同；P2 不得主要依赖平台性能 claim、ML 模型、多节点协调。A 把两层写进一篇，正是把被禁止的相互依赖变成论文结构。
- `RESEARCH_BRIEF_v0.2.md` §10.5 的标题即 Separate Platform and Security Claims，原文：`rswitch`论文不能依赖`jz_sniff_rn`才能成立；安全论文可以依赖`rswitch`作为实验平台，但必须证明安全机制本身的收益。
- `RESEARCH_CONSTITUTION.md` §3 第 8 条：论文之间不得重复包装同一主要贡献。
- `RESEARCH_EXECUTION_PLAN_v0.1.md` 的 G1 闸门把失败条件写死：两篇都主要声称“更快、更灵活、更安全”。Week 2 的 Gate 原文：若P1/P2主要claim无法分离，暂时取消P1独立论文，将`rswitch`降级为substrate。
- `KILL_CRITERIA.md` §2 把“Paper 1 所需评估成本明显挤压主线”列为 kill 条件，fallback 是只保留 Paper 2–4 依赖的 qualification。

工程侧同样不支持 A：`jz_sniff_rn/.gitmodules` 声明 rSwitch 为 submodule，但 `git submodule status` 返回 `-c10fbd8… rswitch`（未初始化、目录为空）；`ARCH-03-ANALYSIS-v2.md:8` 明确“双轨制 — standalone 继续开发 + rSwitch 回归作为战略储备”。所以 A 缺的不是文笔，是框架到应用的调用链证据。

**处置**：A 不作为单篇存在。框架贡献落到 P1 并独立冻结实验合同，应用与安全贡献落到 P2；两者靠 `RESEARCH_BRIEF_v0.2.md` §7 与 §12 的“执行底座 → 在该底座上安全执行有界响应”依赖链串联，而不是靠一篇论文。用户口头初衷因此得到保留，同时不与纲领冲突。

## 关于 C 的判断

把现稿独立出去是对的，但 01 卡对 C 的定义要改：那里 C 是“机制短文加框架-应用系统论文”，即 C 已经包含 A。若按用户的 `A→C→B` 读，C 应狭义化为**清场**：把现稿从主线里彻底移出，主线不再背它，也不把它降级成机制子节。

现稿在 R0 组合里确实没有位置。它的对标线是 consistent updates（Reitblatt SIGCOMM 2012）、XDP（CoNEXT 2018）、libxdp 与 devmap 内核语义，问题粒度是“ingress 选中的 devmap entry 与物理输出 bulk queue 保留的 egress program 是两个观察对象”；P1 的合同是平台可组合性与性能，P2 的合同是安全收益与业务损害的 Pareto 边界。现稿全文无 jz_sniff_rn、无流量编织、无威胁模型、无系统级 evaluation，其 §6 还明确不执行完整 rSwitch graph。把它并进 P1 会污染 P1 的 primary metrics；并进 P2 会把一致性诊断包装成安全收益，触犯 `RESEARCH_CONSTITUTION.md` §3 第 8 条。

更关键的是现稿已经自带完整的独立要素，详见 `01-独立论文契约与主线边界.md`：独立 RQ（selected 与 executed identity 的区分）、独立机制（cache-epoch consistency condition 与 exposure-aware 诊断）、独立实验（veth two-generation slice、六个 arm、selective fault controls、bounded model）、独立失败条件（§6.4 的 falsifier 与 observer 干预 rival）。这正是 `PUBLICATION_STRATEGY.md` §3 要求的独立 RQ、独立机制、独立实验、独立失败条件、不重复的主要 claim。**它不并入主线，反而更容易过 Anti-Salami。**

S1 的独立贡献条件依 `PUBLICATION_STRATEGY.md` §3 的 Anti-Salami 规则判定；`RESEARCH_BRIEF_v0.2.md` §7 Optional Paper 5 的成立条件是数据规模、时间真实性与可公开或可复现性，属另一事项，不适用于 S1。R0 全文未定义组合外机制研究这一类别，故 S1 须在 `PAPER_PORTFOLIO.md`（`RESEARCH_EXECUTION_PLAN_v0.1.md` WS1 的待建产物）中显式登记、说明理由，并声明 shared substrate 与 reused section limits。

## 关于 B 的判断

B 与 R0 的 Paper 2 完全对齐，是终点；但“最后投”不等于“最后才开始写”，而且它现在连开题闸门都没过。

R0 对顺序有明文规定。`RESEARCH_BRIEF_v0.2.md` §13 WP5 原文：`Paper 1先冻结平台贡献与实验合同。` 与 `Paper 2同步冻结traffic weaving定义和威胁模型，但不等待Paper 1发表后再开始实验。` 同文件 §15 给的最优工作顺序是：审计现有 claim → 完成相关工作证据地图 → 冻结 Paper 1 和 Paper 2 的研究边界 → 建立统一实验工具链 → 先完成底座性能和安全闭环的可证伪实验；§12 的 Thesis Coherence 亦按 Paper 1 到 Paper 4 的逻辑顺序展开。可见 R0 允许工作步骤有先后，禁止的只是 P2 等 P1 发表后才开始实验。

B 的闸门现状（依据 `01-选题复位评估卡.md` §评测策略与主线 `00-工程事实基线.md`）：唯一 A 级证据为 2026-09-08 的 N=3 真机闭环 3/3 PASS，判据是管线贯通、四维 feeds 在最小实验室配置下为全零值；122 个测试是 B 级工程证据；CI 跑的是 `--dry-run` 的 `"synthetic": true` 记录；`experiments/runs/` 被 gitignore 且无提交实测。而 `RESEARCH_BRIEF_v0.2.md` §7 对 Paper 2 要求七条基线（无防御、alert-only、Suricata+nftables、静态 ACL 或微隔离、二元 XDP DROP、无护栏 weaving、完整 bounded weaving），`KILL_CRITERIA.md` §3 把“业务损害不可可靠测量”列为 kill 条件，`RESEARCH_EXECUTION_PLAN_v0.1.md` 的 G4 要求同时测安全收益与业务损害。按这些判据，B 的主要 claim 仍处于 evidence-seeking，投稿闸门未过。

## 推荐序列

| 阶段 | 动作 | R0 依据 | 出口判据 |
|---|---|---|---|
| 先做 | S1 独立论文补闸门后投机制短文，主线彻底清场 | `PUBLICATION_STRATEGY.md` §3 的独立贡献条件；现稿是唯一有完整受控数据的一篇 | Q0–Q5 与 Claim Gate 通过；artifact 公开；多 boot 独立会话 |
| 并行冻结 | P1 与 P2 的研究边界、贡献合同、claim 依赖矩阵同步冻结，P2 不等待 P1 发表后才开始实验 | `RESEARCH_BRIEF_v0.2.md` §13 WP2 与 §13 WP5；`RESEARCH_EXECUTION_PLAN_v0.1.md` WS3、Week 2 Gate、G1 | P1/P2 主要 claim 可分离；每个 claim 有最强近邻与反例 |
| 补齐 | 统一实验工具链、基线 bring-up、可证伪实验 | `RESEARCH_EXECUTION_PLAN_v0.1.md` WS5、WS6、Week 7–11；G3/G4/G5 | 场景可自动重复、manifest 完整、业务损害可测、护栏有可测贡献 |
| 收尾 | P2（即 B）投稿，P1 视 Kill Criteria 决定独立成篇或降级为 substrate | `KILL_CRITERIA.md` §2；`PUBLICATION_STRATEGY.md` §5 | Claim Gate、Quality Gate、Artifact、Related Work 更新到投稿前、adversarial review、与学位主线一致、商业与隐私检查全过 |

与 `A→C→B` 的差别：起点不是 A 而是 S1；A 被拆成 P1 加 P2；P1 与 P2 并行而非串行；终点 B 的最后一步是投稿而非开写。

## 解读分野

用户原话没有说明 `A→C→B` 是定位收敛还是发表顺序，两种读法都给出处置：

- **若指定位收敛**（A 是初衷，C 清场，B 落地）：**采纳**。它主动承认了工程现实（standalone 双轨、rSwitch 回归为战略储备），比 01 卡原先的“A 为目标形态、C 为过渡策略”更贴近 R0。只需把 A 改写成 P1 加 P2 的依赖链，并把 C 从“拆两篇”改成“移出主线”。
- **若指发表顺序**（先写 A、再写 C、最后写 B）：**不采纳**。A 的证据最弱（`rSwitch_Paper_Key_Points.md` §9.2 待补实验全未勾选、框架到应用调用链未落地），抢跑必被要求补系统级评测；C 反而是唯一有完整数据的一篇。`RESEARCH_BRIEF_v0.2.md` §13 WP5 规定 P2 不等待 P1 发表后再开始实验，§15 另给出先后工作步骤。
- **若指学位主线结构**：按 `PUBLICATION_STRATEGY.md` §6 Thesis Chapter Map，第 2 章 Reconfigurable Network Substrate、第 3 章 Traffic Weaving Model、第 4 章 Bounded Containment 依序展开；S1 的机制诊断最多进第 2 章的 substrate qualification，不单独成章。

## 风险与待决

| 事项 | 状态 | 处置 |
|---|---|---|
| S1 与 P1 共享 rSwitch 冻结版本 | 已识别 | 按 Anti-Salami 声明 shared substrate；不得把 365 vs 0 conflicts 搬进 P1 的吞吐／延迟评测 |
| 现稿研究档案未公开 | 未解决 | 现稿 Data and code availability 自述 `has not been publicly deposited`；R0 Submission Gate 要求 Artifact checklist 通过 |
| 现稿含生成式 AI 声明且模型版本未暴露 | 未解决 | 现稿 §4.7 与 Declaration 自述；投稿前须补 model version 与人工审核责任 |
| P1 是否被 Kill Criteria 降级 | 待决 | `KILL_CRITERIA.md` §2：若平台评估成本挤压主线，则降级为 substrate，平台贡献写入系统实现章节 |
| 具体 venue 与截止时间 | 未核验 | `PUBLICATION_STRATEGY.md` §4 明确“具体venue与截止时间需在投稿前实时核验。”，本轮不填 |
| 本轮未做在线文献检索与专利数据库检索 | 声明 | 沿用主线 `02-素材台账与文献地图.md` 的声明；S1 的最近邻补检见 `03-证据缺口与投稿闸门.md` |
