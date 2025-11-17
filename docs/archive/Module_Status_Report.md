# Module 状态报告（简要）

本文档列出各模块的当前状态、已完成开发、已验证、已知问题与建议行动。

---

## 1) Loader (rswitch_loader)
- 状态：已完成
- 已完成功能：动态模块加载、map pin/unpin、PID 管理、健康检查、信号处理（SIGHUP、SIGTERM）
- 验证：已在测试环境中进行功能验证
- 已知问题：unpin map 规则需覆盖 `voqd_state_map`/`xsks_map`/`egress_final_st` 等map名称
- 建议：扩展 `unpin_maps()` 模式并确保在关闭前 `flush TX` 并 `detach XDP`。

## 2) VOQd (rswitch-voqd)
- 状态：进行中/已运行（shadow/active 模式）
- 已完成功能：AF_XDP socket 管理（xsks_map pin）、VOQ 管理、调度器（DRR）
- 验证：基本统计、RTT、heartbeats
- 已知问题：libxdp 的结构使用需谨慎；统计值显示异常（已修复读取未定义内存问题）
- 建议：增加 unit test/e2e 测试，并补充资源泄漏回收测试（restart loader 后map是否释放）

## 3) AF_XDP 管理（xsk manager / socket）
- 状态：已完成核心功能
- 已完成功能：sock 创建、UMEM、xsks_map 更新
- 已知问题：早期版本访问自定义 `struct xsk_socket` 字段导致未定义行为（已修复），需要在 `xsk_manager_get_stats()` 中使用 libxdp API
- 建议：增加 libxdp 版本兼容性测试与 CI 测试

## 4) QoS 模块（egress_qos）
- 状态：已完成（但需要更多集成测试）
- 已完成功能：priority mapping、dscp 重写、token-based rate limiting、ECN、qdepth map
- 验证：通过 bpf maps、rsqosctl、测试流量（DHCP 高优先级注意事项）
- 已知问题：DSCP rewrite 校验和计算错误（已修复）；qos_stats_map 未 pin（已修复）
- 建议：对动态规则（rsqosctl）进行长时 stability 测试

## 5) VLAN 模块（egress_vlan）
- 状态：已完成
- 已完成功能：tag push/pop、vlan isolation checks、profile rules
- 已知问题：未更新 `rs_ctx` offset 时导致 ip header offset 失效（已修复）
- 建议：增加对 double-vlan (QinQ) 情形的边界测试

## 6) Egress final
- 状态：已更新并通过 verifier
- 已完成功能：IP checksum 验证与修复、统计 map 的 pin
- 已知问题：最初被 BPF verifier 拒绝，需要按固定展开与范围约束进行优化（已修复）
- 建议：替换为更高效的校验逻辑（可以使用 hardware checksum offload 信息）与定期健康统计

## 7) rsqosctl 与 控制工具
- 状态：已完成基础 CLI
- 已完成功能：add-class、set-dscp、set-rate-limit、enable/disable 等
- 验证：`rsqosctl stats`、`rsqosctl add-class` 等命令已验证
- 已知问题：脚本使用 `--stats` 错误参数（已修复）

---

## 交付与风险
- AF_XDP + QoS 在真实硬件上仍需验证（以验证零拷贝、umem、大流量场景）
- map pin/unpin 的一致性与 loader 清理的顺序仍需要在 CI / VM 之外的硬件上验证

---

## 链接
- `docs/Development_Log_Summary.md` 
- `docs/Startup_Issues_Fixed_2025-11-13.md`
- `docs/Shutdown_and_Cleanup_Fixes.md`
- `docs/QoS_Port_Classification_Guide.md`

## 最近的实现修复与注意事项

以下是已合并的关键实现修复摘要（便于模块维护与验证）：

- **Pin/Unpin Map 改进**: 增加了 `qos_stats_map` 与 `xsks_map` 等 map 的 pinning 与 unpin 策略，避免用户态工具无法访问 map 或 loader 退出后遗留 map。
- **IP 校验和修正**: `egress_qos` 已采用 RFC1624 增量校验和修正；`egress_final` 添加了可验证的 IP 校验和验证/修复逻辑。
- **VLAN Offset 修正**: VLAN push/pop 时更新 `rs_ctx.layers.l3_offset/l4_offset`，避免后续模块解析偏移错误。
- **AF_XDP 安全统计**: 修复了异常的 VOQd 统计读取（使用 libxdp API 或安全方法），并修补 XDP 与 AF_XDP 状态的 race 条件。
- **BPF Verifier 适配**: 在核心 BPF 模块中加入边界检查、offset mask 并重构复杂循环，通过 verifier 验证并提高可移植性。

建议维护者在迭代后执行验证：
- 在虚拟化环境与真实硬件上验证 AF_XDP 零拷贝场景
- 验证 loader 完整退出时 `/sys/fs/bpf` 是否无遗留 map
- 运行 `rsqosctl stats` 与 `rswitch_diag.sh` 验证 QoS 统计是否正常