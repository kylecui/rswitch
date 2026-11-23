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

## 待办（guest 侧）

1. 在 Ubuntu 6.8 guest 上以 root 运行 `ENV_PROBE.sh`，归档 `env_probe_*.log` 并回传。
2. `VERDICT: GO` 后交付源码 v0.1 并编译校准。
3. 按操作序列执行 boot 间独立复现，全部原始日志按契约归档。
