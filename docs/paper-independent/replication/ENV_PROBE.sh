#!/usr/bin/env bash
# ENV_PROBE.sh — S1 复现环境探测（目标：Ubuntu kernel 6.8 guest）
# 用法：sudo bash ENV_PROBE.sh
# 输出：env_probe_<UTC时间>.log；六组检查全过（末行 VERDICT: GO）才允许进入发送阶段。
# 纪律：本脚本的完整输出按 LOGGING_CONTRACT.md 归档，包括失败项。

set -u
OUT="env_probe_$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$OUT") 2>&1
echo "== ENV_PROBE start $(date -u +%FT%TZ) =="

echo "== [G1] 内核与权限 =="
uname -a
[ "$(id -u)" -eq 0 ] || echo "FAIL: 需要 root（或 CAP_BPF|CAP_PERFMON）"
grep -E '^(CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_BPF_TRACING=|CONFIG_DEBUG_INFO_BTF=)' /boot/config-"$(uname -r)" 2>/dev/null \
  || zcat /proc/config.gz 2>/dev/null | grep -E '^(CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_BPF_TRACING=|CONFIG_DEBUG_INFO_BTF=)' \
  || echo "FAIL: 找不到内核配置"

echo "== [G2] BTF =="
[ -r /sys/kernel/btf/vmlinux ] && ls -l /sys/kernel/btf/vmlinux || echo "FAIL: 无 BTF，fentry/fexit 不可用"

echo "== [G3] tracing 目标函数 =="
AVAIL=/sys/kernel/tracing/available_filter_functions
[ -r "$AVAIL" ] || AVAIL=/sys/kernel/debug/tracing/available_filter_functions
if [ -r "$AVAIL" ]; then
  grep -cx 'dev_map_enqueue' "$AVAIL" && echo "OK: dev_map_enqueue 可挂" || echo "FAIL: dev_map_enqueue 不在可用清单"
  grep -cx 'bq_xmit_all' "$AVAIL" && echo "OK: bq_xmit_all 可挂" || echo "FAIL: bq_xmit_all 不在可用清单"
else
  echo "FAIL: tracing 可用清单不可读（尝试 mount -t tracefs）"
fi

echo "== [G4] 工具链 =="
for t in clang llvm-strip bpftool ip tc python3; do
  command -v "$t" >/dev/null && echo "OK: $t $($t --version 2>/dev/null | head -1)" || echo "FAIL: 缺 $t"
done
ldconfig -p 2>/dev/null | grep -q 'libbpf.so' && echo "OK: libbpf" || echo "FAIL: 缺 libbpf"

echo "== [G5] veth 与 XDP generic 能力（建完即删） =="
V=s1probe$$
ip link add "$V" type veth peer name "$V"p 2>&1 && echo "OK: veth 创建" || echo "FAIL: veth 创建"
if ip link show "$V" >/dev/null 2>&1; then
  TCID=$((RANDOM))
  ip link set "$V" xdp obj /dev/null 2>/dev/null || echo "NOTE: 无预编译 XDP 对象，generic 挂载能力留待套件加载阶段验证"
  tc qdisc add dev "$V" clsact 2>&1 && echo "OK: clsact" || echo "NOTE: clsact 不可用"
  ip link set "$V"x xdp fd 2>/dev/null || true
  ip link del "$V" 2>&1 && echo "OK: 清理完成"
else
  echo "FAIL: 探测链路不存在，跳过清理"
fi

echo "== [G6] 时钟与资源 =="
cat /sys/devices/system/clocksource/clocksource0/current_clocksource
date -u; cat /proc/uptime
nproc; free -m | head -2

echo "== VERDICT =="
if grep -q 'FAIL' "$OUT"; then echo "VERDICT: NO-GO（存在 FAIL 项，逐条修复后重跑）"; else echo "VERDICT: GO"; fi
echo "== ENV_PROBE end $(date -u +%FT%TZ) =="
echo "归档：$OUT（append-only，勿改；sha256 见 MANIFEST.sha256）"
