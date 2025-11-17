# rSwitch Map Pinning 重构总结

**日期**: 2025-11-05  
**状态**: ✅ 已完成  
**基础**: 方案 A（LIBBPF 默认路径）

## 重构概览

rSwitch 代码已经正确实现了基于方案 A 的 map pinning 策略，遵循以下原则：

- **Pin 路径**: `/sys/fs/bpf/<map_name>`（LIBBPF 默认）
- **无需** `bpf_object__set_pin_path()` 调用
- **三层分类**: Tier 1（必须 pin）、Tier 2（建议 pin）、Tier 3（不 pin）

## 已验证的 Map 定义

### Tier 1: Core Infrastructure (已正确 Pin)

| Map | 文件 | 状态 |
|-----|------|------|
| `rs_ctx_map` | `bpf/core/uapi.h` | ✅ `LIBBPF_PIN_BY_NAME` |
| `rs_progs` | `bpf/core/uapi.h` | ✅ `LIBBPF_PIN_BY_NAME` |
| `rs_port_config_map` | `bpf/core/map_defs.h` | ✅ `LIBBPF_PIN_BY_NAME` |
| `rs_vlan_map` | `bpf/core/map_defs.h` | ✅ `LIBBPF_PIN_BY_NAME` |
| `rs_stats_map` | `bpf/core/map_defs.h` | ✅ `LIBBPF_PIN_BY_NAME` |
| `rs_mac_table` | `bpf/core/map_defs.h` | ✅ `LIBBPF_PIN_BY_NAME` |

**验证**:
```c
// bpf/core/uapi.h
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // ✅ 正确
} rs_ctx_map SEC(".maps");
```

### Tier 3: Module-Owned (已正确不 Pin)

| Map | 文件 | 状态 |
|-----|------|------|
| `rs_xdp_devmap` | `bpf/modules/lastcall.bpf.c` | ✅ 无 pinning 定义 |
| `rs_events` | `bpf/modules/l2learn.bpf.c` | ✅ 无 pinning 定义 |

**验证**:
```c
// bpf/modules/lastcall.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
    // ✅ 无 pinning 定义 - 正确
} rs_xdp_devmap SEC(".maps");

// bpf/modules/l2learn.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    // ✅ 无 pinning 定义 - 正确
} rs_events SEC(".maps");
```

## 关键代码注释

代码中已包含清晰的注释说明 pinning 策略：

### uapi.h 注释
```c
/* NOTE: rs_events ringbuf removed from here!
 * 
 * Following the Single Owner Pattern (like rs_xdp_devmap in lastcall):
 * - rs_events is now defined in l2learn.bpf.c (its only user)
 * - No pinning needed (single owner)
 * - Loader accesses it via l2learn module object
 */
```

### map_defs.h 注释
```c
/* NOTE: rs_xdp_devmap removed from here!
 * Following PoC pattern: devmap is defined ONLY in lastcall.bpf.c
 * Loader accesses it via lastcall module's object.
 * No pinning needed - single owner, no cross-module sharing.
 */
```

### lastcall.bpf.c 注释
```c
/* XDP devmap for packet forwarding
 * 
 * Following PoC egress_map pattern:
 * - Defined ONLY in lastcall (single user)
 * - Loader populates it via lastcall object
 * - NO pinning needed (not shared across modules)
 * - Uses bpf_devmap_val for potential egress hook attachment
 */
```

### l2learn.bpf.c 注释
```c
/* L2Learn Ringbuf for MAC Learning Events
 * 
 * SINGLE OWNER PATTERN (like rs_xdp_devmap in lastcall):
 * - Defined here, only l2learn uses it
 * - No pinning (not shared across modules)
 * - Loader accesses via l2learn module object for event consumption
 */
```

## 与 PoC 的区别

| 方面 | PoC (src/) | rSwitch (rswitch/) |
|------|-----------|-------------------|
| **策略** | 隐式、不一致 | 明确的三层分类 |
| **路径** | 不明确 | `/sys/fs/bpf/<map_name>` |
| **共享** | 重复定义 | Core 定义，模块复用 |
| **注释** | 无 | 每个 map 都有清晰说明 |
| **文档** | 无 | `MAP_PINNING_STRATEGY.md` |

## 验证步骤

### 1. 检查 Pinned Maps

```bash
# 加载 rswitch
cd /home/kylecui/dev/rSwitch/rswitch
sudo make clean && sudo make
sudo ./build/loader/rswitch_loader

# 验证 pinned maps
sudo ls -l /sys/fs/bpf/

# 应该看到：
# rs_ctx_map
# rs_progs
# rs_port_config_map
# rs_vlan_map
# rs_stats_map
# rs_mac_table

# 不应该看到：
# rs_xdp_devmap
# rs_events
```

### 2. 验证 Map 共享

```bash
# 检查所有加载的 maps
sudo bpftool map show

# 验证 rs_ctx_map 只有一个实例（ID 相同）
sudo bpftool map show | grep rs_ctx_map

# 验证 rs_xdp_devmap 存在但未 pin
sudo bpftool map show | grep devmap
```

### 3. 验证 Cleanup

```bash
# 清理
sudo ./build/loader/rswitch_loader --cleanup

# 验证 maps 已 unpin
sudo ls /sys/fs/bpf/ | grep -E "rs_"
# 应该返回空（所有 maps 已清理）
```

## 文档资源

- **策略文档**: `rswitch/docs/MAP_PINNING_STRATEGY.md` - 完整策略说明
- **代码注释**: 每个 map 定义处都有清晰注释
- **决策树**: 帮助判断新 map 是否应该 pin

## PoC 代码保持不变

**重要**: 所有重构仅在 `rswitch/` 目录进行，`src/`（PoC 代码）保持不变：

```bash
# PoC 代码 - 不修改
src/
├── kSwitchMainHook.bpf.c
├── kSwitchDefaultVLANControl.bpf.c
├── kSwitchLastCall.bpf.c
├── kSwitchLoader.c
└── ...

# 新框架 - 已重构
rswitch/
├── bpf/
│   ├── core/
│   │   ├── uapi.h           # ✅ Tier 1 maps
│   │   └── map_defs.h       # ✅ Tier 1 maps
│   └── modules/
│       ├── lastcall.bpf.c   # ✅ Tier 3 devmap
│       └── l2learn.bpf.c    # ✅ Tier 3 ringbuf
└── docs/
    └── MAP_PINNING_STRATEGY.md  # ✅ 完整文档
```

## 总结

✅ **已完成**:
1. 验证所有 Tier 1 maps 正确使用 `LIBBPF_PIN_BY_NAME`
2. 验证所有 Tier 3 maps 正确不 pin
3. 代码注释清晰说明每个 map 的 pinning 策略
4. 创建完整的策略文档

✅ **代码质量**:
- 遵循 YAGNI 原则（You Aren't Gonna Need It）
- Single Owner Pattern 明确
- 注释详细，易于维护

✅ **PoC 代码**:
- 完全不受影响
- 可以继续独立工作

**下一步**: 可以继续实现其他模块（ACL, Route 等），遵循相同的 pinning 策略。
