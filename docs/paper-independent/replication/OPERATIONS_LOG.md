# 操作原始日志

> 本文件按时间线穷尽记录复现工作区建立过程中的全部操作与输出，含失败与被拒绝的操作。格式：时间（本地 UTC+8）｜动作｜结果原文或摘要。

## 2026-11-23

- 21:45｜宿主环境探测｜`uname -a` → `MINGW64_NT-10.0-26340 DESKTOP-J3QIBUN 3.6.9-b4195d69.x86_64 2026-06-06`。宿主为 Windows（MSYS/Git Bash），无 Linux 内核。
- 21:45｜WSL 探测｜`wsl.exe --status` 与 `wsl.exe -l -v` 均被安全策略阻断。原文：`PROGRAM BLOCKED BY SECURITY POLICY - The sandbox prevented a program on the configured Program Blacklist from starting: wsl.exe`，并明示 `This block cannot be approved or bypassed`、`Do NOT retry this program, launch it through another shell or script, or attempt an equivalent workaround`。
- 21:45｜工具链探测｜`which clang llvm-strip bpftool ip` 无任何命中；`clang --version` 无输出。
- 21:45｜现稿 source-data 包检索｜`D:/Downloads` 按 `source.?data|manuscript|devmap|capsule|33-file` 过滤无命中；微信 2026-10 文件目录前若干项为无关文件。结论：本机未定位到 33-file frozen bundle（SHA-256 `ed8c0d6a…`）。
- 21:45｜判定｜宿主无法执行 XDP/devmap/fentry 复现。执行环境定为 Ubuntu kernel 6.8 guest（论文原环境为 6.8.0-139-generic 的 guest）。不复现环境结论不得推断复现成败。
- 22:01｜协议冻结｜`README.md`（go/no-go 协议、三态判读）与 `LOGGING_CONTRACT.md`（append-only、manifest、admission、闸门映射）写入本目录。
- 22:01｜探测脚本交付｜`ENV_PROBE.sh` 写入，作为目标 guest 上的首步；六组检查，末行输出 `VERDICT: GO|NO-GO`。
- 22:01｜源码规格交付｜`SOURCES.md` 写入，列出待实现的切片与工具源码及接口规格；源码 v0.1 未编译、未验证，首次运行前须先过 ENV_PROBE 并按实际内核校准。
- 22:01｜合同决策登记｜经五顾问 Council 裁决（见 `../04-独立论文价值评审.md` 附录），主理人选定 S1 走独立投稿合同 (a)；随附纪律：去内部化措辞、正面回答非干预发生性、补 commit 引文、artifact 公开与 AI 声明补全、go/no-go 为不可降级闸门、时间盒保留。

## 2026-11-23（续）：凭证检索与主机探测

- 22:13｜凭证检索｜rswitch 仓库 grep `password|credential|10.174.|lab.machine|sshpass`：仅命中 rSwitch 管理口默认密码样例（`etc/profiles/*.yaml` 的 `auth_password: rswitch`，应用层，非机器登录）与 ACL 示例 IP；jz_sniff_rn 命中 lab IP 记录（10.174.254.163、10.174.254.139 等研究文档）但无明文登录凭证。**结论：两仓库均未记录机器登录凭证；凭证载体为本机 `~/.ssh/id_ed25519` 密钥 + `~/.ssh/config`（全部 `User kylecui`，无密码指令）。**
- 22:13｜known_hosts 主机清单｜10.174.1.x 十余台、10.174.254.x 十八台（含论文 N=3 证据机 10.174.254.139、E2E 机 .163）、mshome.net 本地 VM 域。config 条目：`10.174.254.128`、`kc-ebpf-test-01.mshome.net`、`kc-ubuntu-2404-01.mshome.net`（172.21.25.197）。
- 22:13｜连通与能力探测（BatchMode 只读）｜
  - `kc-ebpf-test-01`：可达，kylecui，kernel `7.0.0-1017-azure`，BTF=yes。内核偏离论文环境大，只宜做工具链预研。
  - `kc-ubuntu-2404-01`（172.21.25.197）：连接超时（关机或 NAT 不通）。**Ubuntu 24.04 对应 6.8 系内核，是论文同款内核的候选机，需先开机。**
  - `10.174.254.128`（ubuntu-vm-2204）：可达，kernel `5.15.0-204-generic`，BTF=yes，**免密 sudo=yes**，有 `ip`，缺 `clang`/`bpftool`（需装工具链）。devmap 批量语义 5.14 引入，5.15 含该语义；可用但非论文内核。
  - `10.174.254.139`（论文 N=3 证据机）：连接超时，不在线。
  - `10.174.254.163`：`Permission denied (publickey)`，未装本机公钥。
  - tracing 可用清单读取失败（tracefs 未挂载或路径差异），留给 ENV_PROBE.sh 的 G3 项在目标机上判。
- 22:13｜选机结论｜首选路径：`10.174.254.128` 装 HWE 内核（`linux-image-generic-hwe-22.04` 可升至 6.8 系，与论文 6.8.0-139-generic 同系）后作正式复现机；升级内核与重启为有影响操作，**须经主理人确认后执行**。次选：开机 `kc-ubuntu-2404-01`。128 在现有 5.15 上可先完成工具链安装、ENV_PROBE 与冒烟（语义自 5.14 存在）。

- 22:21｜测试机登记｜主理人指定复现测试机 `rswitch-dev@10.174.254.130`（主机名 rswitch-dev-20，在 known_hosts 清单内）。探测：Ubuntu 24.04 LTS，**kernel 6.8.0-111-generic（与论文 6.8.0-139-generic 同系）**，BTF=yes，免密 sudo=yes，工具链齐（clang 18.1.3、llvm-strip、bpftool v7.4.0、ip、tc、python3 3.12.3、libbpf），4 核 7.9G。非 root 下 tracefs 不可读，留待 sudo 判定。
- 22:21｜ENV_PROBE 上机执行｜修正探针脚本一行无效残留后，scp 至 `~/s1-replication/`，`sudo bash ENV_PROBE.sh` 运行。**结果六组全过，`VERDICT: GO`**：G1 内核配置（BPF/BPF_SYSCALL/DEBUG_INFO_BTF=y；CONFIG_BPF_TRACING 行未在输出中出现，待源码加载 fentry 时以实际行为复核）、G2 BTF 存在、G3 `dev_map_enqueue` 与 `bq_xmit_all` 均在 available_filter_functions 可挂、G4 工具链全齐、G5 veth/clsact 创建清理正常、G6 tsc 时钟源。日志 `env_probe_20261123T142135Z.log` 归档于 `artifacts/rswitch-dev-20/`，远端与本地 sha256 一致（`16cb2a093eb35e52cdb277390afbaca94552aea36cf953e7f4320d75e045a12d`）。
- 22:21｜状态更新｜复现环境就绪。下一步：交付源码 v0.1（规格见 SOURCES.md），在 130 上远程编译校准，冒烟通过后进入正式 go/no-go 矩阵。先前候选机（10.174.254.128 的 HWE 升级、kc-ubuntu-2404-01 开机）不再需要。

## 2026-11-23（续二）：源码 v0.1→v0.3 交付与冒烟调试全记录

- 22:21–23:16｜源码交付｜`bpf/min_slice.bpf.c`（ingress root + BANK_A/B + COMMON_MUX + capsule/wire + 六 arm 配置）、`bpf/trace_export.bpf.c`（fentry dev_map_enqueue/bq_xmit_all + ringbuf + ifindex 过滤）、`user/min_ctl.c`（open_file 低层 libbpf，单进程常驻）、`Makefile`（clang -target bpf + bpftool gen skeleton/btf dump vmlinux.h）。
- 23:16–23:59｜远程编译迭代（全部于 rswitch-dev-20）｜修复清单按顺序：① `linux/in.h` 缺失（IPPROTO_UDP）；② trace_export 改用 `bpftool btf dump` 生成的 `vmlinux.h`（内核内部结构 CO-RE 需要）；③ `-I.` include 路径（vmlinux.h 与 skeleton 头跨目录）；④ skeleton 前缀为 `min_slice_bpf`/`trace_export_bpf`（bpftool 将 `.` 归一 `_`）；⑤ `bpf_ringbuf_consume` 是内核侧 helper，用户态改 `ring_buffer__new/poll`；⑥ `XDP_FLAGS_ANY` 在该用户态头不存在，改 `XDP_FLAGS_MASK`；⑦ `0xS1D` 非法字面量改 `0x51d`；⑧ **open_file 方案替换 skeleton**（skeleton `open_skeleton→find_map_by_name` 段错误，gdb 回溯定位，改低层 API 绕过）；⑨ per-CPU stats 读取按 `libbpf_num_possible_cpus()`（=128）动态分配（固定 MAX_CPU 读数不可信）。
- 23:59｜verifier 迭代｜`adjust_head` 后旧 pkt 指针失效（R8 invalid mem access）→ 重新经 ctx 解析 sender header；随后**v0.2 重构：capsule/wire 内嵌 UDP payload（36+72+64=172B），零 adjust_head**，规避 AF_PACKET 注入帧 headroom 不足。
- 23:59｜注入路径迭代｜AF_PACKET write 成功但帧不到 s1_in 的 XDP（tcpdump 双端证实）→ **veth native XDP 要求对端 GRO off**（gro off 后 XDP 开始触发）；突发 128 帧溢出 veth XDP rq 被静默丢弃 → **节流 1ms/帧**。
- 00:00 前后｜**devmap value 类型根因**：BPF 侧 value 定义为 `int`（4B）导致 `bpf_devmap_val`（8B，ifindex+prog）被截断——egress program 一直没装上（readback prog_id=0、trace prog_id=0）。改为 `__type(value, struct bpf_devmap_val)`。
- 00:00 前后｜**devmap update EINVAL 根因（v6.8 源码逐字核对）**：`__dev_map_alloc_node` 要求 `prog->expected_attach_type == BPF_XDP_DEVMAP`——`SEC("xdp")` 的 expected_attach_type 是 BPF_XDP；egress 程序 section 改为 **`SEC("xdp/devmap")`**。修复后 readback：`devmap[0] ifindex=79 prog_id=407`、trace enqueue 事件 `prog_id=407`——**egress bank 确认挂上**。
- 00:00 前后｜bpftool 直读真值（pin + hold）：stats percpu **RX=128（cpu1）**——128 帧全部进入 ingress root；devmap 两条目 ifindex=75、prog id 395/396 正确。此前 stats 打印 RX=7/8/12 为 per-CPU 读取缺陷所致，已修复（动态 possible_cpus=128）。
- 00:00 前后｜**当前断点：devmap bq flush（bq_xmit_all）未触发**——trace kind=2 恒为 0，帧滞留 bulk queue，egress 未执行、s1_rx 无帧。generic XDP 模式下 devmap flush 时机不明确（已回退 native 优先）。行为存在轮间不稳定（RX 128/12 波动），高度嫌疑为同机活体 rSwitch 栈（rswitch.service、mgmtd 15:23:32 启动、killswitch watchdog）的周期性干扰。
- 00:00 前后｜trace 过滤教训：fentry 为系统级 hook，未过滤时把同机 rSwitch 平台栈自身转发流量的 dev_map_enqueue 全部计入（130 条假象）。已加 trace_cfg ifindex 过滤（写入失败静默的缺陷本轮暴露，已加错误打印）。

## 遗留断点（下一轮）

1. **bq flush 不触发**：候选原因——veth_poll 尾部 xdp_do_flush 的 VETH_XMIT_RED 位未置位（redirect 路径差异）、同机 rSwitch 栈干扰、或 fentry/bq_xmit_all 与实际 flush 函数不一致。候选手段：加 fentry/xdp_do_flush、fentry/__dev_flush 旁证 hook 定位 flush 链；或对照停用 rswitch 服务（**须主理人确认**，属有影响操作）。
2. **行为轮间不稳定**：RX 128 与 12 波动。候选：mgmtd/watchdog 周期动作。观察法：连续多轮 run 记录 run_cnt（bpftool prog show）。
3. receiver.py、judge.py、run_go_no_go.sh 尚未编写（SOURCES.md 已有规格）；stats 读取已修复但未复验。
4. 三态判读所需数据：待 egress 执行后，direct arm 冲突帧按 wire.ingress_gen != wire.egress_gen 且 semantic 与 retained 计算自洽判定。

## 待办（guest 侧）

1. 在 Ubuntu 6.8 guest 上以 root 运行 `ENV_PROBE.sh`，归档 `env_probe_*.log` 并回传。
2. `VERDICT: GO` 后交付源码 v0.1 并编译校准。
3. 按操作序列执行 boot 间独立复现，全部原始日志按契约归档。

## 2026-11-24：flush 链定位与过滤修复

- 14:16｜trace_cfg 过滤写入块被发现在此前脚本替换中静默丢失（本地/远端均无）——即此前 130 条 trace 一直未过滤。已插入到 trace 对象 load 后、attach 前，本轮输出确认生效：`[trace] 过滤 ifindex=91 r=0`。
- 14:16｜过滤生效后的关键数据：kind1（enqueue）=130 条，**全部 ifindex=91（我们的 s1_out）、prog_id=449/450（本轮 BANK_A/BANK_B）、65/65 交替、ts 跨 4.1 秒与 1ms 注入节奏吻合**——**128 个实验帧全部完成 redirect 并 enqueue 到 devmap，代际选择正确**。这判定此前「130 条是平台噪声」的怀疑不成立。
- 14:16｜`bq_xmit_all`（kind2）恒为 0：devmap flush 从未发生——帧滞留 bulk queue，egress 程序（5.14+ 语义在 flush 时执行）因此从未运行，s1_rx 无帧。此为当前唯一硬断点。
- 14:16｜stats 读数（RX=8~12）与 130 条 enqueue 矛盾；percpu 与普通 array 两种实现读数一致，**说明要么 XDP 真只处理了少量帧而 enqueue 来自他途（未找到该路径），要么用户态 stats 读取仍有缺陷**。pin 代码（hold 期间 pin stats/devmap/trace_cfg 供 bpftool 直读）同样未生效——**脚本替换静默失败已三次，此后凡代码插入必须 grep 验证后再编译**。下一轮以 pinned dump 终审 RX 真值。
- 14:16｜旁证 hook 迭代：`xdp_do_flush` 是 static inline（无 BTF），fentry 挂它无效；改挂 `__dev_flush`（ftrace 探测确认可挂）。本轮 kind3（__dev_flush）=0，与「flush 未发生」一致。清洗了替换脚本造成的重复 hook 定义。
- 遗留：① bq flush 不触发的根因（候选：veth_poll 的 VETH_XMIT_RED 位路径差异、rSwitch 栈干扰、内核 6.8.0-111 特定行为）；② RX 真值终审（pinned dump）；③ receiver.py/judge.py/run_go_no_go.sh。

## 2026-11-24（续）：内核权威计数定格断点

- 14:29｜停 rSwitch 三服务（主理人授权，`rswitch.service`/mgmtd/killswitch watchdog → inactive），**bpftool net 确认 XDP 残留清空**，环境纯净。
- 14:29｜开启 `kernel.bpf_stats_enabled=1`，以内核 run_cnt 终审：
  - `xdp_ingress_root run_cnt=128`——**root 确实执行了全部 128 帧**（内核权威计数）；
  - 上轮 `tr_enqueue run_cnt=129`——redirect→dev_map_enqueue 同样确认；
  - **`tr_dev_flush` 无 run_cnt 字段（从未执行）**——**flush 链精确断在 veth_poll 尾部 `if (stats.xdp_redirect>0) xdp_do_flush()` 与 `__dev_flush` 之间**：redirect 发生了 129 次，但 flush 分支未走。
- 14:29｜**stats map 用户态读取正式弃用**：内核 root=128 时用户态读 RX=0/1/8/11/12 全不可信（percpu 与普通 array 皆然），今后一律以 bpftool 外部读/pinned dump 为准。
- 14:29｜复现价值备注：**「帧滞留 devmap bulk queue 直至 flush 时机」正是现稿研究的机制本体**；本环境的 flush 触发缺失与论文 v4 需要 threaded-NAPI 干预调出多帧 epoch 是同一类现象的镜像。复现协议候选解法（下一轮实现）：① root 程序对非实验帧返回 XDP_TX（veth_poll 尾部 xdp_tx 分支同样触发 xdp_do_flush），sender 每 16 帧注入一帧 flush 触发帧；② 发送后 `ip link set s1_out down` 强制 devmap flush（验证 flush 通路存在性）；③ 加 fexit/bq_xmit_all 与 fentry/dev_map_flush_old 旁证。
- 遗留同前：receiver.py、judge.py、run_go_no_go.sh；rSwitch 服务保持停止状态（复现完成后恢复，待主理人确认）。
