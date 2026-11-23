# 日志契约

> 依据：R0 `EXPERIMENT_QUALITY_GATE.md` Q0–Q5 与 Q3 执行纪律；现稿 §4.4 的 admission criteria。
> 目标：任何第三方拿到 runs/ 目录即可独立判读，不依赖作者解释。

## 原则

1. **append-only**：原始日志写入后不得修改、不得覆盖；纠错只能追加更正记录并注明原因。
2. **穷尽记录**：每条命令的完整 stdout/stderr 都归档，包括失败命令、被拒绝的操作与环境探测的空输出。
3. **原始计数优先**：先存原始记录，再存汇总；两者不得互相替代。
4. **负结果保留**：`valid-negative` 不得删除或改标为未完成；结果不好、攻击未成功、防御未奏效不得标为 invalid（`EXPERIMENT_QUALITY_GATE.md` §2）。
5. **hash 封存**：每文件落盘后计算 sha256 写入该 run 的 `MANIFEST.sha256`；boot 结束后该清单不得再改。

## 目录结构

```text
runs/
└── <boot_uuid>/
    ├── env.json                 # kernel、BTF、CPU、内存、veth 命名、时间、seed
    ├── probe.log                # ENV_PROBE.sh 完整输出
    ├── setup.log                # veth 创建、BPF 加载、readback 全部输出
    ├── <arm>/                   # direct | clean_mux
    │   ├── trace_off/
    │   │   ├── raw/receiver.jsonl
    │   │   ├── raw/trace_enqueue.jsonl
    │   │   ├── raw/trace_xmit.jsonl
    │   │   ├── sender.log
    │   │   └── reconcile.log
    │   └── trace_on/
    │       └── （同上）
    ├── MANIFEST.json            # 自动生成，字段见下表
    ├── MANIFEST.sha256
    ├── status                   # 六态之一
    └── verdict.json             # judge.py 产出：T1/T2/T3 与依据计数
```

## MANIFEST 字段

| 字段 | 说明 | 对应闸门 |
|---|---|---|
| experiment_id、suite_commit | 套件 commit 与工作树 hash | Q1 |
| boot_uuid、boot 序号 | 独立 boot 标识；boot 间结果不得池化 | Q5 |
| kernel、btf_present、tracing_funcs | 内核版本、BTF 存在性、`available_filter_functions` 命中 | Q0/Q1 |
| veth 命名与创建命令、xdp_mode | 拓扑与模式 | Q1 |
| cpu、mem、time_start/end（单调与墙钟双时间戳） | 资源与时序 | Q0 |
| seed、arm 顺序 | 固定顺序或声明随机化方式 | Q2 |
| capsule/wire 偏移定义 hash | 首次 run 前冻结 | Q2 |
| 发送与接收计数、epoch 计数、segment 计数 | 精确分母 | Q4 |
| 冲突帧计数、诊断通道 mask 分列 | semantic、mux 身份、capsule 绑定、path 签名分开报 | Q4 |
| 异常与环境漂移记录 | 任何偏差逐条列 | Q3 |

## run 状态

`valid-success` / `valid-negative` / `invalid-instrumentation` / `invalid-environment` / `failed-system` / `failed-scenario`。判读规则：只有仪器故障、环境配置错误、场景未启动、数据丢失、validity check 失败可标 invalid；冲突数本身不构成 invalid。

## 与 R0 闸门映射

| 契约项 | 闸门 |
|---|---|
| probe.log、双时间戳、计数器对账 | Q0 |
| env.json、suite_commit、seed | Q1 |
| 预注册判据、等暴露设计、偏移冻结 | Q2 |
| manifest 自动生成、append-only、漂移记录 | Q3 |
| 分列报告、精确分母、负结果保留 | Q4 |
| boot 间独立、另一成员或机器可凭契约复跑 | Q5 |
