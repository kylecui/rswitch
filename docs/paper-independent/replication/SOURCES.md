# 源码规格（v0.1 待交付）

> 说明：以下文件为 go/no-go 复现套件的源码清单与接口规格。**尚未编写、未编译、未验证**；实现顺序在 `ENV_PROBE.sh` 判 `GO` 之后，并须按目标 guest 的实际内核校准。字段偏移在首次 run 前冻结并随 manifest 归档。

## 关键常量（源自现稿 §3–§4，实现时逐条对回论文）

| 项 | 值 |
|---|---|
| devmap 条目 | `BPF_MAP_TYPE_DEVMAP`，2 条（A、B），同指一个输出设备，流量期零更新 |
| cache epoch 结构 | 每 arm 32 epoch × 64 帧；devmap bulk queue 容量 16 帧，每 epoch 自然形成 4 个 transmit segment |
| capsule（元数据路径，主机字节序） | 36 字节：nonce、seq、transition_id、payload_digest（d）、generation、ingress_bank |
| wire record（网络字节序） | 72 字节：观测到的 ingress/egress bank、mux 身份、action、path 签名、32 位语义值 |
| 语义值 | `semantic = lo32(d) ^ hi32(d) ^ I ^ E`；A 盐 `0xa11a0a01`、`0xa33a0a03`；B 盐 `0xb22b0b02`、`0xb44b0b04`；期望一致结果用实际 ingress 代际双盐，保留程序结果用观测 ingress 盐加缓存 egress 盐 |
| 诊断通道 mask | violation 并集、semantic 六谓词、mux 身份、capsule 绑定、path 签名分列（对应现稿 Figure 3） |

## 文件清单

| 文件 | 职责 | 关键接口 |
|---|---|---|
| `bpf/min_slice.bpf.c` | ingress root（snapshot 标量 g → 构造 capsule → `bpf_redirect_map`）、BANK_A/BANK_B egress（改写 egress 盐并计算语义值）、COMMON_MUX（读 capsule 内 generation 分发到不可变 bank，内联 switch，不新增一层 prog_array）、wrong_bank/wrong_mux/wrong_capsule 故障开关（编译期或 map 配置） | section 名、map 名固定；`SEC("xdp")` ingress root 挂 `s1_in`，egress 挂输出设备 |
| `bpf/trace_export.bpf.c` | fentry `dev_map_enqueue`（记 `dst->xdp_prog`）、fexit `dev_map_enqueue`、fentry `bq_xmit_all`（记 `bq->xdp_prog`） | ring buffer → 用户态；事件含 run、CPU、输出设备、epoch 侧计数、程序 id |
| `user/min_ctl.c` | libbpf skeleton 加载与 readback、active-generation 标量发布、AF_PACKET 发送器（64 帧块、barrier 发布）、owned-resource 清理 | `min_ctl <veth_in> <veth_out> <arm> <trace_mode>`；退出码非零即 run 异常 |
| `tools/receiver.py` | AF_PACKET、32 MiB 接收缓冲、wire record 解析、六谓词 semantic endpoint、mask 分列、admission（唯一接收、无重复畸形、人口对账、collector loss） | 输出 `raw/receiver.jsonl` 与汇总；不得丢帧静默 |
| `tools/judge.py` | 读 manifest 与 raw，按三态判读（T1/T2/T3）与过闸线产出 `verdict.json` | 只认契约字段，不做人工口述判读 |
| `run_go_no_go.sh` | 多 boot 编排：probe → setup → arm 矩阵（direct、clean_mux × trace_off/on）→ reconcile → judge | 每 boot 独立目录；boot 间不共享状态 |

## 验证顺序（实现后）

1. `clang -O2 -g -target bpf` 编译两个 BPF 目标，零警告；
2. guest 上先跑 `ENV_PROBE.sh` 至 `VERDICT: GO`；
3. 冒烟：trace-on 下 direct arm 单 epoch 小流量，核对 capsule/wire 偏移与 tracer 程序 id 读数一致；
4. 再进入正式 go/no-go 矩阵；冒烟数据不得并入正式 run。
