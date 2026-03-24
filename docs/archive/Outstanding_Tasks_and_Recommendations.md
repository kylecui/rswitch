> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# 未完成任务与建议（Outstanding Tasks & Recommendations）

这是当前存量工作、问题以及可行的下一步建议，便于团队规划后续工作。

## 未完成/需验证项
1. AF_XDP + QoS 集成的完整实测
   - 验证零拷贝（zero-copy）与性能模型（benchmark）
   - 下行和上行流量在真实 NIC 环境（Intel X710, mlx5）下验证

2. Map 清理/Map 所有权一致性验证
   - loader 退出后仍有 map 未自动 unpin
   - 执行 `unpin_maps()` 的 pattern 需覆盖 `egress_final_st`, `xsks_map`, `qdepth_map`, `voqd_state_map` 等

3. 完整 E2E 测试：
   - 启停/重启
   - 负载测试（QoS/VOQd/AF_XDP 并发）
   - DHCP/SSH/HTTP 的优先级分类验证

4. VOQd 健康/回收与内存管理
   - VOQd 退化场景（突然失去 xsks_map、锅炉plate 重连）
   - UMEM 释放/回收策略

5. Crash/安全审计
   - 修复未定义行为并进行代码审计
   - BPF program 能否被恶意构造的包触发边界问题

## 建议的短期任务（Sprint）
- Sprint-1 (2 周)
  - Map 清理与 Loader 清理顺序（确定 pattern）
  - 自动化脚本：重启/回收测试脚本
  - Unit tests for `xsk_manager_get_stats()` and stats access

- Sprint-2 (2-3 周)
  - AF_XDP / VOQd 在真实 NIC 上的 benchmark
  - 继续优化 `ip_checksum` 与 `egress_final` 的性能
  - 增加 `rsqosctl` 端到端测试（规则添加/删除/边界测试）

- Sprint-3 (2 周)
  - 测试和修复 CLI 错误边界情况（`rsqosctl`）
  - 集成测试：stress with multiple flows and VLAN combinations

## 测试清单（Checklist）
- [ ] Loader shutdown/restart cleanup correctness
- [ ] Map pin/unpin matrix validation (all maps listed)
- [ ] AF_XDP zero-copy validation (device dependent)
- [ ] VOQd stability under load
- [ ] Packet integrity after QoS/ECN rewrite (ip checksum)
- [ ] DHCP/low-latency traffic behavior

---

## 推荐的 document / CI 改进
- 1. 在 CI 中加入 `bpftool map show` 验证 map 是否正确 pin/unpin
- 2. 在 CI 中加入 boot + shutdown 测试（`rswitch_start.sh` + reboot）
- 3. 自动化 VOQd 健康检查脚本 `voqd_check.sh` 在 nightly runs
- 4. Add `rswitchctl test-suite` to validate QoS rules

---

## 次级建议
- 使用 `libxdp` 的 `xsk_socket__get_stats()` 获取 socket-level stats，避免对内部结构的强制转换
- 避免 `bpf_xdp_adjust_head()` 不更新 `rs_ctx` 的偏移，写单元测试确保偏移更新
- 将 `egress_final` 中的 checksum 逻辑提取为可测试的函数，并在 loader startup 时进行 smoke tests
