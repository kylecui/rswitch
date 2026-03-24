> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Troubleshooting & Fixes 总结

本文档汇总了我们在开发测试过程中遇到的常见问题、根因与解决办法（面向工程调试使用）。

## 常见问题与处理

### 1) QoS: "disabled, passing through"
- 症状：板载日志中出现 `QoS: disabled, passing through`
- 根因：`qos_config_ext_map` 未被初始化或没启用 `QOS_FLAG_ENABLED`。
- 解决：在 loader 初始化时调用 `initialize_qos_config()`，设置 flags 并填充 DSCP 或默认表；在 `rswitch_loader` 中进行 map 初始化。

### 2) DHCP 被 VOQd 拦截
- 症状：DHCP 分配失败（UDP 67/68 被拦截）
- 根因：DHCP port 默认被 classify 为 HIGH，默认 `prio_mask=0x0C`（HIGH+CRITICAL）被 redirect 到 VOQd
- 解决：临时解决：`rsqosctl add-class --proto udp --dport 67 --priority normal` 或设置 `prio_mask` 更多接受 NORMAL；长期：在 profile 中增加 DHCP 明确规则

### 3) netdev watchdog & shutdown hang
- 症状：`netdev watchdog transmit queue 0 timed out`，`systemd` shutdown 等待 loader 退出
- 根因：loader cleanup 顺序不正确（detach XDP 导致 TX 队列未 flush）和 sleep(1) 导致响应慢
- 解决：
  - 调整：flush TX queues → detach XDP → 50ms 延迟 → close map FDs
  - 优化：`usleep(100000)` 轮询（100ms），VOQd timeout 缩短到 2s

### 4) IRQ affinity "Value too large"
- 症状：启动时，写 IRQ affinity 失败（Value too large）
- 根因：固定绑定到 CPU 4（不存在），或 CPU 数量假设错误
- 解决：使用 `CPU_ID=$(( (i + 1) % NUM_CPUS ))` 或 `mod nproc` 算法

### 5) "Failed to open QoS stats map: No such file"
- 症状：`rsqosctl stats` 报错找不到 map
- 根因：map 未 pin 到 `/sys/fs/bpf`（遗漏 `__uint(pinning, LIBBPF_PIN_BY_NAME)`）或 rsqosctl 运行过早
- 解决：在 map 定义中加入 `pinning`；在启动脚本中等待 3-5s 再运行配置命令

### 6) VOQd 数值异常（大数字）
- 症状：日志看到 `AF_XDP: RX=3, TX=291977882778984 sockets`
- 根因：读取了未定义/内存偏移（访问 libxdp 结构时类型混淆）
- 解决：修复为使用 libxdp API（`xsk_socket__get_stats()`）或安全地维护统计结构

### 7) DSCP/ECN 重写后校验和错误
- 症状：IP 校验和不正确（报 `bad cksum`）
- 根因：增量校验和算法使用错误（只处理 TOS 字节而非整个 16-bit word）
- 解决：
  - 使用 RFC1624 增量校验和算法（对 16-bit word 做修改）
  - 在 `egress_final` 中添加 `ip_checksum()` 验证与自动修正
  - 使用 BPF verifier 友好的方法（限制 offsets，手动展开等）

### 8) MAC/L2/VLAN 相关
- 症状：add VLAN 后 IP IHL 显示错误或 IP header 无效
- 根因：添加 VLAN tag 后，`rs_ctx.layers.l3_offset` 未更新
- 解决：在 tag push/pop 中更新 `l3_offset/l4_offset` 并同步 `rs_ctx.layers`

### 9) 未释放 maps（loader 退出后）
- 症状：loader quit 后 `/sys/fs/bpf` 仍然存在一些 maps（如 `qdepth_map`, `xsks_map`）
- 根因：`unpin_maps()` 规则匹配不全或 map 未被释放
- 解决：
  - 在 `rswitch_loader` cleanup 执行时，确保 pattern 包含 `egress_final_st`, `xsks_map`, `qdepth_map`, `voqd_state_map`
  - 或显式 unpin 列表（例如：`rs_*`, `qos_*`, `qdepth_map`, `xsks_map`, `voqd_state_map`）

## 调试工具与脚本
- `tools/scripts/jzzn/rswitch_start.sh` — 启动脚本（包含延迟/CPU affinity 检查）
- `tools/scripts/jzzn/rswitch_diag.sh` — 快速诊断脚本
- `rswitch/scripts/voqd_check.sh` — VOQd 健康检查工具

## 最近的实现修复与注意事项

以下是最近集成到代码库中的关键实现修复（便于排查近期问题）：

- **QoS Map Pinning**: `qos_stats_map` 等关键统计 map 已添加 `LIBBPF_PIN_BY_NAME`，确保用户态工具可以打开 `/sys/fs/bpf` 中的 map，防止 `rsqosctl stats` 报错找不到 map。
- **DSCP/ECN 校验和修正**: 在 `egress_qos` 中修正了增量校验和算法（采用 RFC1624 更新 16-bit word），并在 `egress_final` 中增强了 IP 校验和验证与自动修正逻辑。
- **VLAN Tag Offsets**: 在 VLAN push/pop 操作中更新了 `rs_ctx.layers.l3_offset` 与 `l4_offset`，避免后续模块读取错误的 IP 头位置。
- **Startup Race Fixes**: 增加了 `rswitch_start.sh` 的延迟与 VOQd 启动等待逻辑，保证 maps 已就绪并避免 `No such file` 错误；修正 CPU affinity 计算以防止 `Value too large` 错误。
- **VOQd Stats / AF_XDP Safe Access**: 修复了早期因直接访问 libxdp 结构导致的统计异常，`xsk_manager_get_stats()` 现在通过 libxdp API 获取安全统计或使用已验证的字段。
- **Map cleanup & unpinning**: 增强 `unpin_maps()` 规则，loader 在退出/重启时会清理 `qdepth_map`, `xsks_map`, `voqd_state_map`, `egress_final_st` 等常见 map，避免残留 map。
- **BPF Verifier 改进**: 对关键读写加入 offset mask (`& 0x3F`) 与边界检查；对复杂循环采用固定展开或条件检查，从而通过 BPF verifier 验证。

详情参见：`docs/Migration_Guide.md` 的 “最近的实现修复与注意事项” 与 `docs/Module_Status_Report.md`。

---

## 建议的验证测试套件
1. Unit tests for AF_XDP socket create/destroy (smoke test)
2. Integration test for QoS + VOQd (simulate DHCP, SSH traffic)
3. System shutdown/reboot test verifying `rswitch_loader` cleanup
4. Regression test for map pin/unpin and ensure no leftover maps
5. BPF verifier checks for all modules (limit offsets, avoid complex runtime loops)

---

文档链接：
- `docs/Startup_Issues_Fixed_2025-11-13.md`
- `docs/Shutdown_and_Cleanup_Fixes.md`
- `docs/BPF_VERIFIER_OFFSET_MASKING.md`
