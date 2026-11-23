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

## 待办（guest 侧）

1. 在 Ubuntu 6.8 guest 上以 root 运行 `ENV_PROBE.sh`，归档 `env_probe_*.log` 并回传。
2. `VERDICT: GO` 后交付源码 v0.1 并编译校准。
3. 按操作序列执行 boot 间独立复现，全部原始日志按契约归档。
