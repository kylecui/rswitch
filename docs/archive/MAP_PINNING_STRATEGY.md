> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# rSwitch Map Pinning Strategy

**Version**: 1.0  
**Date**: 2025-11-05  
**Status**: Production Implementation

## 核心原则

rSwitch 使用 **方案 A（LIBBPF 默认路径）** 进行 map pinning：

- **默认行为**: `LIBBPF_PIN_BY_NAME` 将 map pin 到 `/sys/fs/bpf/<map_name>`
- **无需** `bpf_object__set_pin_path()` 调用
- **优势**: 简单、可靠、避免路径管理复杂性

## Map 分类与 Pinning 决策

### Tier 1: Core Infrastructure Maps（必须 Pin）

这些 map 由 `bpf/core/` 定义，所有模块共享：

| Map Name | Type | 定义位置 | Pin 路径 | 理由 |
|----------|------|---------|----------|------|
| `rs_ctx_map` | PERCPU_ARRAY | uapi.h | `/sys/fs/bpf/rs_ctx_map` | 跨模块共享上下文 |
| `rs_progs` | PROG_ARRAY | uapi.h | `/sys/fs/bpf/rs_progs` | Tail-call 程序数组 |
| `rs_port_config_map` | HASH | map_defs.h | `/sys/fs/bpf/rs_port_config_map` | 配置持久化 + rswitchctl 访问 |
| `rs_vlan_map` | HASH | map_defs.h | `/sys/fs/bpf/rs_vlan_map` | VLAN 拓扑持久化 |
| `rs_stats_map` | PERCPU_ARRAY | map_defs.h | `/sys/fs/bpf/rs_stats_map` | 统计数据 + Prometheus 访问 |
| `rs_mac_table` | HASH | map_defs.h | `/sys/fs/bpf/rs_mac_table` | MAC 表 + rswitchctl show mac |

**代码示例** (uapi.h / map_defs.h):
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rs_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ← Pin 到 /sys/fs/bpf/rs_ctx_map
} rs_ctx_map SEC(".maps");
```

### Tier 2: Module-Owned Data Maps（选择性 Pin）

模块私有但需要用户工具访问的 map：

| Map Name | Type | Owner Module | Pin 路径 | 理由 |
|----------|------|--------------|----------|------|
| `rs_acl_rules` | HASH | modules/acl | `/sys/fs/bpf/rs_acl_rules` | rswitchctl acl list |
| `rs_route_table` | LPM_TRIE | modules/route | `/sys/fs/bpf/rs_route_table` | rswitchctl route show |

**代码示例** (modules/acl.bpf.c):
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct acl_key);
    __type(value, struct acl_rule);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // ← Pin（用户工具访问）
} rs_acl_rules SEC(".maps");
```

### Tier 3: Kernel-Only & Transient Maps（不 Pin）

仅内核使用或临时状态的 map：

| Map Name | Type | Owner Module | 不 Pin 理由 |
|----------|------|--------------|-----------|
| `rs_xdp_devmap` | DEVMAP_HASH | modules/lastcall | 仅 XDP redirect 使用，用户空间无需访问 |
| `rs_egress_map` | DEVMAP | core/egress | Devmap egress hook 专用 |
| `rs_events` | RINGBUF | modules/l2learn | 单一消费者（l2learnd），通过 FD 传递 |
| `voq_ringbuf` | RINGBUF | modules/afxdp_divert | 单一消费者（voqd），高频实时数据 |
| `rs_cpumap` | CPUMAP | modules/afxdp_divert | 仅内核 CPU 重定向 |
| `rs_qdepth_map` | HASH | modules/afxdp_divert | 临时拥塞状态，重启应清零 |

**代码示例** (modules/lastcall.bpf.c):
```c
// SINGLE OWNER PATTERN - 不 pin
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, RS_MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);
    // ❌ 无 pinning 定义 - 不 pin
} rs_xdp_devmap SEC(".maps");
```

**代码示例** (modules/l2learn.bpf.c):
```c
// Ringbuf - 单一消费者，不 pin
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    // ❌ 无 pinning 定义 - l2learnd 通过 FD 消费
} rs_events SEC(".maps");
```

## Loader 实现

### 加载 Core Maps

```c
// user/loader/rswitch_loader.c

int load_core_dispatcher(void) {
    struct bpf_object *obj;
    
    obj = bpf_object__open_file("build/core/dispatcher.bpf.o", NULL);
    if (!obj) return -1;
    
    // ✅ 不调用 bpf_object__set_pin_path() - 使用默认路径
    // Maps with LIBBPF_PIN_BY_NAME 会自动 pin 到 /sys/fs/bpf/<map_name>
    
    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        return -1;
    }
    
    return 0;
}
```

### 加载 Module Maps

```c
int load_module(const char *module_name, const char *obj_path) {
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) return -1;
    
    // 遍历 map，处理 Tier 1 复用和 Tier 3 禁用
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        
        // Tier 1 global maps - 复用已 pin 的版本
        if (strcmp(name, "rs_ctx_map") == 0 ||
            strcmp(name, "rs_progs") == 0 ||
            strcmp(name, "rs_port_config_map") == 0 ||
            strcmp(name, "rs_vlan_map") == 0 ||
            strcmp(name, "rs_stats_map") == 0 ||
            strcmp(name, "rs_mac_table") == 0) {
            // 复用已 pin 的 map
            char pin_path[256];
            snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", name);
            int fd = bpf_obj_get(pin_path);
            if (fd > 0) {
                bpf_map__reuse_fd(map, fd);
                close(fd);
            }
            continue;
        }
        
        // Tier 3 不 pin 的 map - 显式禁用
        if (strcmp(name, "rs_events") == 0 ||
            strcmp(name, "rs_xdp_devmap") == 0 ||
            strcmp(name, "rs_egress_map") == 0 ||
            strcmp(name, "rs_cpumap") == 0 ||
            strcmp(name, "voq_ringbuf") == 0 ||
            strcmp(name, "rs_qdepth_map") == 0) {
            bpf_map__set_pin_path(map, NULL);  // 显式不 pin
            continue;
        }
        
        // Tier 2: 其他 map 使用 LIBBPF_PIN_BY_NAME（已在 .bpf.c 中设置）
        // libbpf 会自动 pin 到 /sys/fs/bpf/<map_name>
    }
    
    return bpf_object__load(obj);
}
```

### Cleanup 策略

```c
void cleanup_pinned_maps(int keep_config) {
    if (!keep_config) {
        // 完全清理（包括配置）
        unlink("/sys/fs/bpf/rs_ctx_map");
        unlink("/sys/fs/bpf/rs_progs");
        unlink("/sys/fs/bpf/rs_port_config_map");
        unlink("/sys/fs/bpf/rs_vlan_map");
        unlink("/sys/fs/bpf/rs_stats_map");
        unlink("/sys/fs/bpf/rs_mac_table");
        unlink("/sys/fs/bpf/rs_acl_rules");
        unlink("/sys/fs/bpf/rs_route_table");
    } else {
        // 只清理运行时状态，保留配置
        // 保留: rs_port_config_map, rs_vlan_map
        unlink("/sys/fs/bpf/rs_ctx_map");
        unlink("/sys/fs/bpf/rs_progs");
        unlink("/sys/fs/bpf/rs_stats_map");
        unlink("/sys/fs/bpf/rs_mac_table");
        unlink("/sys/fs/bpf/rs_acl_rules");
        unlink("/sys/fs/bpf/rs_route_table");
    }
}
```

### rswitchctl 访问 Pinned Maps

```c
// user/rswitchctl/mac_table.c

int show_mac_table(void) {
    int fd = bpf_obj_get("/sys/fs/bpf/rs_mac_table");
    if (fd < 0) {
        fprintf(stderr, "Failed to open rs_mac_table: %s\n", strerror(errno));
        return -1;
    }
    
    struct rs_mac_key key = {};
    struct rs_mac_entry entry;
    
    while (bpf_map_get_next_key(fd, &key, &key) == 0) {
        if (bpf_map_lookup_elem(fd, &key, &entry) == 0) {
            printf("%02x:%02x:%02x:%02x:%02x:%02x VLAN %u -> ifindex %u\n",
                   key.mac[0], key.mac[1], key.mac[2],
                   key.mac[3], key.mac[4], key.mac[5],
                   key.vlan, entry.ifindex);
        }
    }
    
    close(fd);
    return 0;
}
```

## Decision Tree

```
需要 Pin 这个 Map 吗？
│
├─ 是否在 core/uapi.h 或 core/map_defs.h 中定义？
│  └─ 是 → ✅ 必须 PIN (Tier 1)
│      理由：框架基础设施，所有模块共享
│      示例：rs_ctx_map, rs_progs, rs_port_config_map
│
├─ 用户工具需要频繁访问？（show/list/config 命令）
│  ├─ 是 → ✅ 建议 PIN (Tier 2)
│  │   理由：rswitchctl/Prometheus 需要稳定路径
│  │   示例：rs_acl_rules, rs_route_table
│  │
│  └─ 否 → 继续判断
│
├─ 只在内核态使用？（devmap/cpumap/xskmap）
│  └─ 是 → ❌ 不 PIN (Tier 3)
│      理由：用户空间无需访问
│      示例：rs_xdp_devmap, rs_egress_map, rs_cpumap
│
├─ 有明确的单一消费者？（通过 FD 传递）
│  └─ 是 → ❌ 不 PIN (Tier 3)
│      理由：通过 loader 传递 FD 即可
│      示例：rs_events (l2learnd), voq_ringbuf (voqd)
│
├─ 是临时运行时状态？（拥塞计数、队列深度）
│  └─ 是 → ❌ 不 PIN (Tier 3)
│      理由：重启后应清零
│      示例：rs_qdepth_map
│
└─ 默认 → ❌ 不 PIN（最小化原则）
```

## 验证

### 检查当前 Pin 状态

```bash
# 查看所有 pinned maps
sudo ls -l /sys/fs/bpf/

# 应该看到：
# rs_ctx_map
# rs_progs
# rs_port_config_map
# rs_vlan_map
# rs_stats_map
# rs_mac_table
# rs_acl_rules (如果加载了 acl 模块)
# rs_route_table (如果加载了 route 模块)

# 不应该看到：
# rs_xdp_devmap (不 pin)
# rs_events (不 pin)
# voq_ringbuf (不 pin)
```

### 验证 Map 共享

```bash
# 加载 dispatcher
sudo ./rswitch_loader --load-core

# 验证 core maps 已 pin
sudo ls /sys/fs/bpf/rs_*

# 加载模块（应该复用已 pin 的 core maps）
sudo ./rswitch_loader --load-module vlan

# 验证模块正确复用（map ID 应该相同）
sudo bpftool map show | grep -E "rs_ctx_map|rs_progs"
```

## 与 PoC 的对比

| 方面 | PoC (src/) | rSwitch (rswitch/) |
|------|-----------|-------------------|
| Pin 策略 | 隐式、不一致 | 明确三层分类 |
| Pin 路径 | 不明确 | `/sys/fs/bpf/<map_name>` |
| Map 共享 | 重复定义同一 map | core 定义一次，模块复用 |
| Cleanup | 不完整 | 差异化（配置保留 vs 完全清理）|
| 文档 | 无 | 本文档 |

## 总结

rSwitch 的 map pinning 策略遵循以下原则：

1. **简单性**：使用 LIBBPF 默认路径，避免自定义路径管理
2. **明确性**：三层分类（Tier 1/2/3），每个决策有明确理由
3. **最小化**：默认不 pin，只在有明确需求时 pin
4. **可维护性**：文档化策略，代码注释清晰

**关键洞察**：
- `LIBBPF_PIN_BY_NAME` 只是标记"需要 pin"
- 实际路径 = `/sys/fs/bpf/<map_name>`（方案 A）
- Pin ≠ 访问权限（CAP_BPF 可访问所有 map）
- Pin = 便捷性（稳定路径 + 持久化）
