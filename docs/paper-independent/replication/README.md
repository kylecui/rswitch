# S1 复现工作区：go/no-go 协议

> 目的：在 Ubuntu guest（kernel 6.8，论文原环境）上，以独立 boot、等暴露、trace-off/on 对照的方式复现 S1 的核心现象，产出过闸或降级决定。
> 状态：**协议与日志契约已冻结（预注册），源码 v0.1 待交付**。宿主沙箱为 Windows，无法执行 XDP 实验——探测记录见 `OPERATIONS_LOG.md`，执行环境必须是 Linux guest。
> 纪律：所有操作与原始日志按 `LOGGING_CONTRACT.md` 穷尽记录；负结果不得删除（`RESEARCH_CONSTITUTION.md` §5）。

## 判据：三态判读

这是 S1 暴露感知方法（零错误不等于零机会）对自身的首次应用，防止单帧 epoch 被误读为机制失败：

| 态 | 观测 | 判读 |
|---|---|---|
| T1 强过闸 | 非干预（不改 threaded-NAPI）条件下出现多帧 cache epoch，且 direct arm 有接收端佐证冲突 | 主张升级为「生产路径可发生」；过闸 |
| T2 中性 | 非干预下全为单帧 epoch（零跨代暴露） | **不是机制失败，是无机会**；先做等暴露增强（提高发送突发、多流交错、多 RX 队列），仍无暴露再按 v4 方式最小干预并显式声明；direct 有冲突且 mux 为 0 才过闸 |
| T3 失败 | 任何条件下都无法复现多帧 epoch 与冲突 | 机制不可复现；触发降级（cache-epoch 条件并入 P1 qualification，论文降为短文或归档） |

量化过闸线：不少于 2 个独立 boot；每 boot 内 direct 与 clean mux 的 opportunity epoch 数可比（等暴露改良：固定 epoch 结构为每 arm 32 epoch × 64 帧，消除 v4 的 13 vs 11 不等暴露）；direct arm 出现接收端佐证冲突且 clean mux arm 为 0。

## 环境要求

- Ubuntu，kernel 6.8.x（论文原环境 6.8.0-139-generic；复跑时记录实际版本，不写笼统 `v2.2.0`）；
- `/sys/kernel/btf/vmlinux` 存在（fentry/fexit 依赖 BTF）；`CONFIG_BPF_TRACING`、`CONFIG_DEBUG_INFO_BTF` 开启；
- root 或 `CAP_BPF|CAP_PERFMON`；`ip`、`tc`、`clang`/`llvm`（不低于 12）、libbpf 不低于 1.0、`bpftool`；
- tracing 可用性以 `/sys/kernel/tracing/available_filter_functions` 同时含 `dev_map_enqueue` 与 `bq_xmit_all` 为准；
- 首步必须运行 `ENV_PROBE.sh`，其输出整体归档，任何一项缺失都不得进入发送阶段。

## 操作序列（guest 上，编号即执行序）

1. `bash ENV_PROBE.sh`，产出 `env_probe_<UTC时间>.log`；六项全绿才继续。
2. 记录本 replication 套件的 git commit 与工作树 hash，写进 manifest。
3. 每个**独立 boot**（重启或独立 VM 快照恢复）：归档 `uname -a`、`dmesg | tail`、CPU/内存清单，生成 `boot_uuid`；创建命名规范的 veth 对（如 `s1_in` / `s1_out`），归档创建命令与链路状态。
4. 加载 BPF 切片并 readback（devmap 条目数、attached 程序 id），归档 readback 输出。
5. 按固定顺序执行 arm：direct、clean mux（每 arm 内先 trace-off 轮再 trace-on 轮）；每 arm 2048 帧、32 epoch × 64 帧、16 帧 transmit 粒度由 devmap bulk queue 自然形成；barrier-assisted 发布 active-generation 标量。
6. receiver 启动到对账全程归档：AF_PACKET 32 MiB 缓冲、唯一接收、无重复与畸形帧、trace 与 receiver 人口对账、零 critical collector loss、owned-resource 清理。
7. `judge.py` 按 `LOGGING_CONTRACT.md` 的 run 状态与 T1/T2/T3 判读，产出 `verdict.json`。
8. 全部原始数据 append-only；boot 间不得合并目录；不同 boot 的结果不得池化后当作独立重复以外的用途。

## 预注册声明

- 主张措辞二选一，由数据决定，不得事后混用：「生产路径可发生」（T1）或「资格测试可暴露该危害」（T2 后过闸）。
- 失败判据预先冻结；修改协议需新增 ADR 条目，不得在看到数据后改判据。
- capsule 与 wire record 的字段偏移由本套件定义并在首次 run 前冻结（论文未公布偏移细节），定义随 manifest 归档。

## 文件清单

| 文件 | 状态 |
|---|---|
| `README.md`（本文件） | 已冻结 |
| `LOGGING_CONTRACT.md` | 已冻结 |
| `ENV_PROBE.sh` | 已交付 |
| `OPERATIONS_LOG.md` | 持续追加 |
| `SOURCES.md` | 已交付（源码规格） |
| `bpf/min_slice.bpf.c` 等源码 | v0.1 待交付，规格见 `SOURCES.md` |
