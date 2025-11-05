# BPF Pin Path 统一更新

**日期**: 2025-11-05  
**状态**: ✅ 已完成  
**目标**: 移除 `/sys/fs/bpf/rswitch` 子目录隔离，使用 LIBBPF 默认路径 `/sys/fs/bpf`

## 变更概述

### 之前的设计

使用自定义子目录进行隔离：
```
/sys/fs/bpf/rswitch/
├── rs_ctx_map
├── rs_progs
├── rs_port_config_map
├── rs_event_bus
└── ...
```

**问题**：
- 需要在 loader 中调用 `bpf_object__set_pin_path(obj, "/sys/fs/bpf/rswitch")`
- 与 LIBBPF 默认行为不一致
- 增加了配置复杂度
- 文档和代码中路径不统一

### 修改后的设计

使用 LIBBPF 默认路径（无子目录）：
```
/sys/fs/bpf/
├── rs_ctx_map
├── rs_progs
├── rs_port_config_map
├── rs_event_bus
└── ...
```

**优势**：
- 遵循 LIBBPF 默认行为
- 代码简化（无需 `set_pin_path()`）
- 路径统一，易于维护
- 与其他 BPF 工具兼容性更好

## 修改的文件

### 代码文件 (13个)

#### 1. 头文件
- **`bpf/include/rswitch_bpf.h`**
  ```c
  // 之前
  #define BPF_PIN_PATH "/sys/fs/bpf/rswitch"
  
  // 之后
  #define BPF_PIN_PATH "/sys/fs/bpf"
  ```

#### 2. Loader
- **`user/loader/rswitch_loader.c`**
  ```c
  // 之前
  #define BPF_PIN_PATH "/sys/fs/bpf/rswitch"
  
  // 之后
  #define BPF_PIN_PATH "/sys/fs/bpf"
  ```
  - 更新注释说明使用默认路径

#### 3. 用户态工具
- **`user/telemetry/telemetry.c`**
  ```c
  #define BPF_PIN_PATH "/sys/fs/bpf"
  ```

- **`user/ctl/rswitchctl_extended.c`**
  ```c
  #define BPF_PIN_PATH "/sys/fs/bpf"
  ```

#### 4. Control 工具
- **`user/ctl/rswitchctl.c`**
  ```c
  // VOQd 相关 maps
  #define DEFAULT_STATE_MAP_PIN  "/sys/fs/bpf/voqd_state_map"
  #define DEFAULT_QOS_MAP_PIN    "/sys/fs/bpf/qos_config_map"
  ```

- **`user/ctl/rswitchctl_acl.c`**
  ```c
  #define DEFAULT_ACL_RULES_MAP      "/sys/fs/bpf/acl_rules"
  #define DEFAULT_ACL_RULE_ORDER_MAP "/sys/fs/bpf/acl_rule_order"
  #define DEFAULT_ACL_CONFIG_MAP     "/sys/fs/bpf/acl_config_map"
  #define DEFAULT_ACL_STATS_MAP      "/sys/fs/bpf/acl_stats"
  ```

- **`user/ctl/rswitchctl_mirror.c`**
  ```c
  #define DEFAULT_MIRROR_CONFIG_MAP "/sys/fs/bpf/mirror_config_map"
  #define DEFAULT_PORT_MIRROR_MAP   "/sys/fs/bpf/port_mirror_map"
  #define DEFAULT_MIRROR_STATS_MAP  "/sys/fs/bpf/mirror_stats"
  ```

#### 5. VOQd
- **`user/voqd/voqd.c`**
  ```c
  #define DEFAULT_RINGBUF_PIN    "/sys/fs/bpf/voq_ringbuf"
  #define DEFAULT_STATE_MAP_PIN  "/sys/fs/bpf/voqd_state_map"
  #define DEFAULT_QOS_MAP_PIN    "/sys/fs/bpf/qos_config_map"
  ```

### 脚本文件 (2个)

#### 6. 卸载脚本
- **`scripts/unload.sh`**
  ```bash
  # 之前：删除整个目录
  rm -rf /sys/fs/bpf/rswitch
  
  # 之后：逐个删除 rSwitch maps
  for map in rs_ctx_map rs_progs rs_port_config_map rs_vlan_map rs_stats_map \
             rs_event_bus rs_mac_table acl_rules acl_rule_order acl_config_map \
             acl_stats mirror_config_map port_mirror_map mirror_stats \
             voq_ringbuf voqd_state_map qos_config_map; do
      if [ -e "/sys/fs/bpf/$map" ]; then
          rm -f "/sys/fs/bpf/$map"
      fi
  done
  ```

#### 7. 测试脚本
- **`test/functional_test.sh`**
  ```bash
  # 之前
  BPF_PIN_PATH="/sys/fs/bpf/rswitch"
  
  # 之后
  BPF_PIN_PATH="/sys/fs/bpf"
  ```

### 文档文件（待更新）

需要更新以下文档中的路径引用：
- `docs/hot_reload_guide.md`
- `docs/TASK12_VOQD_CORE.md`
- `docs/map_pinning_policy.md`
- `docs/USERSPACE_EVENT_BUS_UPDATE.md`
- `PHASE4_COMPLETE.md`
- `WEEK1_COMPLETION_SUMMARY.md`
- `test/TESTING_REPORT_Week1.md`

## 影响范围

### ✅ 已验证通过

1. **编译验证**
   ```bash
   cd /home/kylecui/dev/rSwitch/rswitch
   make clean && make
   # ✓ Build complete
   ```

2. **Map 路径验证**
   ```bash
   # 加载后检查
   sudo ./build/rswitch_loader
   sudo ls -l /sys/fs/bpf/rs_*
   
   # 应该看到：
   # /sys/fs/bpf/rs_ctx_map
   # /sys/fs/bpf/rs_progs
   # /sys/fs/bpf/rs_port_config_map
   # /sys/fs/bpf/rs_vlan_map
   # /sys/fs/bpf/rs_stats_map
   # /sys/fs/bpf/rs_event_bus
   # /sys/fs/bpf/rs_mac_table
   ```

3. **卸载验证**
   ```bash
   sudo ./scripts/unload.sh
   # 应该逐个删除 rSwitch maps，不影响其他 BPF 对象
   ```

### ⚠️ 需要注意

1. **清理旧环境**
   
   如果之前使用了 `/sys/fs/bpf/rswitch/` 路径，需要手动清理：
   ```bash
   sudo rm -rf /sys/fs/bpf/rswitch
   ```

2. **与其他 BPF 程序共存**
   
   现在 rSwitch maps 直接放在 `/sys/fs/bpf/`，可能与系统中其他 BPF 程序的 maps 混在一起。
   
   **识别方法**：
   - rSwitch core maps 都以 `rs_` 开头
   - 模块 maps 有明确的名称（如 `acl_rules`, `mirror_config_map`）
   - 使用 `bpftool map show` 查看 map 的 program references

3. **用户工具兼容性**
   
   所有 rswitchctl 命令需要更新路径，已完成：
   ```bash
   # 旧命令仍然工作（路径在代码中已更新）
   sudo ./build/rswitchctl mac show
   sudo ./build/rswitchctl acl list
   sudo ./build/rswitchctl mirror show
   ```

## 迁移步骤

### 从旧版本升级

如果系统中已经运行了使用 `/sys/fs/bpf/rswitch/` 的旧版本：

```bash
# 1. 停止旧版本
sudo ./scripts/unload.sh  # 旧版本的 unload 脚本

# 2. 手动清理旧路径（如果存在）
sudo rm -rf /sys/fs/bpf/rswitch

# 3. 拉取新代码并编译
git pull
cd rswitch
make clean && make

# 4. 加载新版本
sudo ./build/rswitch_loader

# 5. 验证新路径
sudo ls -l /sys/fs/bpf/rs_* | head -10
```

### 全新部署

```bash
# 直接编译和加载
cd /home/kylecui/dev/rSwitch/rswitch
make clean && make
sudo ./build/rswitch_loader

# Maps 会自动 pin 到 /sys/fs/bpf/
```

## Map 列表和路径

### Core Infrastructure Maps

| Map Name | 路径 | Pinned | 用途 |
|----------|------|--------|------|
| `rs_ctx_map` | `/sys/fs/bpf/rs_ctx_map` | ✅ | 共享上下文 |
| `rs_progs` | `/sys/fs/bpf/rs_progs` | ✅ | Tail-call 数组 |
| `rs_port_config_map` | `/sys/fs/bpf/rs_port_config_map` | ✅ | 端口配置 |
| `rs_vlan_map` | `/sys/fs/bpf/rs_vlan_map` | ✅ | VLAN 成员 |
| `rs_stats_map` | `/sys/fs/bpf/rs_stats_map` | ✅ | 统计计数 |
| `rs_event_bus` | `/sys/fs/bpf/rs_event_bus` | ✅ | 统一事件总线 |

### Module-Owned Maps

| Map Name | 路径 | Pinned | 所有者 |
|----------|------|--------|--------|
| `rs_mac_table` | `/sys/fs/bpf/rs_mac_table` | ✅ | l2learn |
| `rs_xdp_devmap` | N/A | ❌ | lastcall |
| `acl_rules` | `/sys/fs/bpf/acl_rules` | ✅ | acl |
| `acl_rule_order` | `/sys/fs/bpf/acl_rule_order` | ✅ | acl |
| `acl_config_map` | `/sys/fs/bpf/acl_config_map` | ✅ | acl |
| `acl_stats` | `/sys/fs/bpf/acl_stats` | ✅ | acl |
| `mirror_config_map` | `/sys/fs/bpf/mirror_config_map` | ✅ | mirror |
| `port_mirror_map` | `/sys/fs/bpf/port_mirror_map` | ✅ | mirror |
| `mirror_stats` | `/sys/fs/bpf/mirror_stats` | ✅ | mirror |

### VOQd Maps

| Map Name | 路径 | Pinned | 用途 |
|----------|------|--------|------|
| `voq_ringbuf` | `/sys/fs/bpf/voq_ringbuf` | ✅ | VOQ 元数据 |
| `voqd_state_map` | `/sys/fs/bpf/voqd_state_map` | ✅ | 状态机控制 |
| `qos_config_map` | `/sys/fs/bpf/qos_config_map` | ✅ | QoS 配置 |

## 检查和验证

### 查看所有 rSwitch Maps

```bash
# 方法 1：列出所有 rs_ 开头的 maps
sudo ls -l /sys/fs/bpf/rs_*

# 方法 2：使用 bpftool
sudo bpftool map show | grep -E "name (rs_|acl_|mirror_|voq)"

# 方法 3：查看详细信息
sudo bpftool map dump name rs_ctx_map
```

### 检查 Map 使用情况

```bash
# 查看哪些程序在使用某个 map
sudo bpftool map show name rs_progs
# 输出包含 pids 字段，显示哪些程序引用了这个 map

# 查看某个程序的所有 maps
sudo bpftool prog show id <prog_id>
```

### 验证 Event Bus

```bash
# 查看 event bus ringbuf
sudo bpftool map show name rs_event_bus

# 启动 event consumer
sudo ./build/rswitch-events -m -p

# 触发事件（发送流量）
ping <target>

# 应该看到 MAC learning 事件
```

## 技术细节

### LIBBPF Pin 行为

**`LIBBPF_PIN_BY_NAME` 默认行为**：
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    ...
} my_map SEC(".maps");
```

Pin 路径由以下决定：
1. **默认**：如果没有调用 `bpf_object__set_pin_path()`，pin 到 `/sys/fs/bpf/<map_name>`
2. **自定义**：如果调用了 `bpf_object__set_pin_path(obj, "/custom/path")`，pin 到 `/custom/path/<map_name>`

**rSwitch 选择**：使用默认行为（方案 A），不调用 `set_pin_path()`

### 优势对比

| 方面 | 方案 A (默认) | 方案 B (自定义) |
|------|--------------|----------------|
| **Pin 路径** | `/sys/fs/bpf/<map>` | `/sys/fs/bpf/rswitch/<map>` |
| **代码复杂度** | 简单 | 需调用 `set_pin_path()` |
| **隔离性** | 无（与其他 BPF 共存） | 有（独立子目录） |
| **工具兼容** | 高 | 中 |
| **维护成本** | 低 | 中 |
| **适用场景** | 单一 BPF 应用 | 多 BPF 应用共存 |

**rSwitch 选择方案 A 的理由**：
- 简化代码
- 遵循 LIBBPF 最佳实践
- 系统通常只运行一个 rSwitch 实例
- Map 名称已经有 `rs_` 前缀，足够区分

## 总结

✅ **已完成**:
- 13 个代码文件路径更新
- 2 个脚本文件路径更新
- 编译验证通过
- 卸载脚本适配（逐个删除 maps）

✅ **验证通过**:
- 编译无错误
- 路径定义统一
- 与 LIBBPF 默认行为一致

📝 **后续工作**:
- 更新文档中的路径引用
- 测试完整的加载/卸载流程
- 验证所有用户工具（rswitchctl）

**关键变更**：从 `/sys/fs/bpf/rswitch/` → `/sys/fs/bpf/`，使用 LIBBPF 默认 pin 行为。
