# rSwitch中的BPF Map固定 (Pinning)

## 固定路径 (Pin Path) 规范

rSwitch使用两级固定方案：

| 范围 | 固定路径 | 示例 |
|-------|----------|---------|
| **核心共享Map** | `/sys/fs/bpf/<map_name>` (扁平，`rs_` 前缀) | `/sys/fs/bpf/rs_ctx_map` |
| **用户/下游模块Map** | `/sys/fs/bpf/<project>/<map_name>` (子目录) | `/sys/fs/bpf/jz_sniff/capture_ring` |

### 核心Map (扁平路径)

所有rSwitch框架Map都使用 `rs_` 前缀直接固定到 `/sys/fs/bpf/`。这是 `LIBBPF_PIN_BY_NAME` 的默认行为，并确保所有核心Map都能在已知位置被发现。

### 用户/下游模块Map (子目录路径)

基于rSwitch构建的外部项目**应当**将其私有Map固定在项目特定的子目录下：`/sys/fs/bpf/<project>/`。这提供了命名空间隔离 —— 多个下游项目可以共存而不会发生Map名称冲突。

在固定之前创建子目录：

```c
/* 在用户空间加载器或设置脚本中 */
mkdir("/sys/fs/bpf/my_project", 0700);
```

或者使用带有完整路径的 `bpf_obj_pin()` —— 当使用 `bpftool` 时，内核会自动创建中间目录。

## 共享Map发现表

下游模块可能需要访问的核心Map：

| Map名称 | 类型 | 用途 | 典型访问方式 |
|----------|------|---------|----------------|
| `rs_ctx_map` | `PERCPU_ARRAY` | 流水线阶段之间每数据包共享的上下文 | 所有流水线模块读/写 |
| `rs_progs` | `PROG_ARRAY` | 入站尾调用程序数组 | 由加载器/热重载写入；模块通过 `RS_TAIL_CALL_NEXT` 间接使用 |
| `rs_progs_egress` | `PROG_ARRAY` | 出站尾调用程序数组 | 由加载器/热重载写入 |
| `rs_event_bus` | `RINGBUF` | 用于可观测性的结构化事件环形缓冲区 | 模块通过 `RS_EMIT_EVENT` 写入；由用户空间消费者读取 |
| `rs_port_config_map` | `HASH` | 每端口VLAN和模式配置 | 由mgmtd写入；由VLAN/转发模块读取 |
| `rs_stats_map` | `PERCPU_ARRAY` | 每模块流水线统计 | 由模块写入；由监控工具读取 |

> **注意**：使用 `bpf_obj_get("/sys/fs/bpf/<map_name>")` 从用户空间打开核心Map。对于下游Map，请使用完整的子目录路径：`bpf_obj_get("/sys/fs/bpf/my_project/my_map")`。

## 模块Map定义

每个需要用户空间访问的Map必须包含 `pinning` 属性：

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct my_value);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");
```

## 用户空间访问

使用以下方式从用户空间打开已固定的Map：

```c
/* 核心 rSwitch Map */
int fd = bpf_obj_get("/sys/fs/bpf/rs_ctx_map");

/* 下游项目 Map */
int fd = bpf_obj_get("/sys/fs/bpf/my_project/my_map");
```

## Map命名规范

| 前缀 / 模式 | 所有者 | 固定位置 |
|------------------|-------|--------------|
| `rs_*` | rSwitch框架共享Map | `/sys/fs/bpf/rs_*` (扁平) |
| 模块特定 (无 `rs_` 前缀) | 模块私有Map (例如 `acl_5tuple_map`) | `/sys/fs/bpf/<map_name>` (扁平，rSwitch内部模块) |
| `<project>_*` | 下游项目Map | `/sys/fs/bpf/<project>/<map_name>` (子目录) |

## 历史说明

早期开发阶段曾使用 `/sys/fs/bpf/rswitch/` 作为所有Map的子目录。该方式已被弃用，核心Map改为使用扁平的 `rs_*` 前缀（符合libbpf默认设置），同时保留子目录用于下游命名空间隔离。存档文档中任何对 `/sys/fs/bpf/rswitch/` 的引用均已过时。
