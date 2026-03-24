> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch - 开发日志与工作总结

本文档汇总了最近一段时间在 rSwitch 项目中完成的开发、设计讨论、问题排查与修复记录，供工程团队回顾与交接使用。

## 目标
- 将零散的对话与修复记录系统化保存
- 列出已完成工作、重要决策、根因分析与解决方案
- 提供快速参考链接到详细文档与测试步骤

## 总体进展（精要）
- 核心 loader 与尾调用机制完善：`rswitch_loader` 支持更快的 shutdown（100ms 响应），增加 SIGHUP 支持, 优化 cleanup 顺序（flush TX -> detach XDP -> close maps）。
- QoS 模块（egress_qos）与 VOQd 的集成与问题修复：为 QoS 初始化配置、修复 DSCP 重写导致的 IP checksum 问题、添加 egress_final 的校验与修正点。
- AF_XDP / VOQd：实现 VOQd 启动与监控、修复 xsk_manager 中对 libxdp 结构访问的未定义行为、添加 VOQd 校验脚本与健康检查。
- 重启/启动与自动化：实现 `rswitch_start.sh` 启动脚本，解决启动 race（map 未就绪、IRQ affinity 错误），并创建 `rc.local` wrapper 以防早期启动问题。
- 文档：完成 QoS 端口分类、Shutdown 清理文档、Verifier 调优、CO-RE Guide（部分）等多个文档。

## 关键修复项（摘要）
- QoS 未启用：`qos_config_ext_map` 未被初始化，在 `rswitch_loader` 中添加 `initialize_qos_config()` 初始化并设置 `QOS_FLAG_ENABLED`。
- DHCP 优先级被拦截：DHCP UDP 67/68 默认被分配 HIGH 优先级（prio_mask 默认拦截），记录到文档并提供解决方案。
- Shutdown 卡顿 / Kernel watchdog：修复 Signal 处理与 cleanup 序列（先 flush TX，再 detach XDP），缩短 VOQd shutdown等待（5s->2s），减小 sleep 轮询延迟（1s->100ms）。
- VOQd "提前退出"误报：修复 `rswitch_start.sh` 检查 VOQd 启动顺序，等待最多 10s；修复 loader 中 `waitpid` 检查可能的误判。
- AF_XDP 统计泄露/随机值：`xsk_manager_get_stats()` 访问 libxdp 的未定义字段（`rx_packets`/`tx_packets`），导致读取随机内存，修正为返回 socket count 或使用 libxdp stats API。
- IP 校验和错误：DSCP/ECN 改写时使用不正确的增量校验和算法，修正为 RFC1624（对 16-bit word 做增量更新），并在 `egress_final` 中加入校验和验证和修正逻辑。
- VLAN tag 后偏移错误：添加 / 移除 VLAN Tag 未更新 `rs_ctx` 的 `l3_offset`/`l4_offset`，导致后续模块读取错误位置，已修复。
- BPF Verifier 辅助：使用 offset mask（`& 0x3F`）与固定展开来帮助 verifier 做安全检查并通过加载。
- Map Pin/Unpin：Pinning 漏项（qos_stats_map 未 pin），loader 的 unpin_map 规则需要扩展

## 重要文档
- `docs/Startup_Issues_Fixed_2025-11-13.md` — 启动相关问题与修复
- `docs/Shutdown_and_Cleanup_Fixes.md` — Shutdown 性能问题与修复
- `docs/QoS_Port_Classification_Guide.md` — QoS 分类指导
- `docs/VOQd_Integration_Summary.md` — VOQd 集成与设计要点
- `docs/BPF_VERIFIER_OFFSET_MASKING.md` — Verifier 调优技巧

## 变更记录参考（简表）
- `rswitch_loader.c`: 信号处理增强、QoS 初始化、清理顺序修复、VOQd timeout改进。
- `egress_qos.bpf.c`: pin QoS stats map、DSCP 计算与校验和修改
- `egress_final.bpf.c`: IP checksum 验证与修复、verifier 辅助与性能优化
- `afxdp_socket.c`: 修复 libxdp 结构使用（统计）
- `rswitch_start.sh`, `rswitch_diag.sh`, `voqd_check.sh`: 启动 / 诊断 / 健康检查脚本

## 参考测试步骤
- 构建：`make clean && make`
- 手动启动测试：`sudo ./scripts/rswitch_start.sh`
- 验证 VOQd: `ps aux | grep rswitch-voqd` & `tail /tmp/rswitch-voqd.log`
- 验证 QoS stats: `sudo ./build/rsqosctl stats`
- 检查已 pin 的 maps: `ls /sys/fs/bpf/ | grep qos_stats_map`

## 结论
目前代码基础框架与核心模块保持稳定，关键模块已就绪。AF_XDP + QoS 集成的完整版在真实硬件上仍需进一步验证（兼容性和性能）。

---
*文档生成于：* 自动汇总；如需把这些摘要拆分成不同的形式（幻灯片 / Release Notes / 邮件），请告知。

## 最近的实现修复与注意事项

以下是最近合并到主分支的关键修复摘要，便于项目维护人员与运维工程师快速查看影响面：

- **QoS Map Pinning**: 在 `egress_qos` 中修复了 `qos_stats_map` 未 pin 的问题，并在 loader 与启动脚本中加入 map readiness 检查，避免 `rsqosctl stats` 报错
- **IP 校验和**: 使用 RFC1624 的 16-bit 增量更新修正 DSCP/ECN 改写导致的 IP checksum 问题，并在 `egress_final` 中加入校验和验证与自动修正步骤
- **VLAN Offsets**: 在 VLAN push/pop 时更新 `rs_ctx.layers.l3_offset/l4_offset`，确保后续模块（如 `egress_final`）不读取错误偏移
- **Startup/Shutdown Race**: 修复启动竞态（等待 maps/voqd）并改进 loader 的 shutdown 顺序（flush TX → detach → close maps）以避免 netdev watchdog
- **AF_XDP/VOQd 安全**: 修复早期读取 libxdp 内部 struct 字段的问题，改为使用 libxdp API 或受限字段，防止统计异常和内存读取错误
- **Map cleanup / unpin**: 扩展了 loader 的 `unpin_maps()` 规则以包含通用 map 名称（`xsks_map`, `qdepth_map`, `voqd_state_map`, `egress_final_st`），并在脚本中提供清理步骤
- **BPF verifier improvements**: 增加 offset mask（`&0x3F`）、边界检查、循环展开等代码改动，帮助核心模块通过 verifier

更多细节可参见：`docs/Migration_Guide.md`, `docs/Troubleshooting_and_Fixes_Summary.md` 与 `docs/Module_Status_Report.md`。