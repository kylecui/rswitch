# 热重载架构

> **状态**: 已在rSwitch v2.0中实现（`user/reload/hot_reload.c`，1100+ 行）。
>
> 热重载通过交换prog_array条目实现零停机模块更新，无需从网络接口分离XDP。

---

## 1. 工作原理

rSwitch模块通过共享的 `rs_progs` prog_array map以尾调用链方式执行。每个流水线槽位对应一个模块。热重载原子性地替换单个槽位：

```
                  prog_array (rs_progs)
                  ┌────────────────────┐
  slot 0 (解析器) │  prog_fd = 42      │
                  ├────────────────────┤
  slot 1 (VLAN)   │  prog_fd = 55      │  ◄── bpf_map_update_elem(slot, &new_fd)
                  ├────────────────────┤       （从内核角度看是原子操作）
  slot 2 (ACL)    │  prog_fd = 63      │
                  ├────────────────────┤
  slot 3 (转发)   │  prog_fd = 71      │
                  └────────────────────┘

  XDP 保持挂载在网卡上 → 流量永不中断
```

### 重载流程

1. **加载**：从磁盘读取新模块BPF对象
2. **验证ABI兼容性**：主版本号必须匹配，次版本号 ≤ 平台版本
3. **验证模块名称和钩子类型**：必须与被替换槽位匹配
4. **加载BPF程序到内核**：BPF验证器运行
5. **交换prog_array条目**（`bpf_map_update_elem`）— 这是原子操作步骤
6. **验证交换成功**：回读条目进行确认
7. **关闭旧BPF对象**：内核会保持旧程序存活直到最后一个引用释放

关键点：`bpf_map_update_elem` 对prog_array的操作从内核角度看是原子的。任何正在执行旧程序的数据包都会完成处理；后续尾调用将跳转到新程序。

---

## 2. 什么是原子的

- **单个prog_array条目更新**：内核原子交换文件描述符指针。数据包不会看到部分更新的状态。
- **流量连续性**：XDP挂载不受影响。整个重载过程中数据包持续流经网卡。
- **逐槽隔离**：替换槽位N的模块不影响其他槽位的模块。

---

## 3. 当前限制

| 限制 | 详情 |
|------|------|
| **无法热添加新模块** | 模块必须已加载在流水线中。无法动态添加新槽位 — 需要通过 `rswitch_loader` 进行完整的流水线重载。|
| **ABI版本必须匹配** | 主版本号必须等于平台的ABI主版本。次版本号必须 ≤ 平台次版本。不匹配的模块在交换前被拒绝。|
| **钩子类型必须相同** | 入站模块不能热替换到出站槽位（反之亦然）。交换前会验证钩子类型。|
| **阶段/槽位必须匹配** | 新模块声明的阶段必须与被替换的槽位匹配。这防止意外的流水线重排序。|
| **仅有预交换流水线验证** | 如果BPF验证器拒绝新模块，交换中止且旧模块保持活跃。但没有交换后的语义验证。|
| **成功交换无自动回滚** | 交换成功后旧模块即被移除。回滚需要重新加载旧模块二进制文件。|
| **无多模块原子交换** | 每个槽位独立交换。如果需要原子替换模块A和B，会有短暂窗口期A已更新但B尚未更新。|

---

## 4. 使用方法

### CLI — `hot_reload` 工具

```bash
# 重载（替换）单个模块
sudo ./user/reload/hot_reload reload <module_name>

# 试运行 — 仅验证不执行
sudo ./user/reload/hot_reload reload <module_name> --dry-run

# 列出当前已加载的模块
sudo ./user/reload/hot_reload list

# 验证特定阶段的流水线完整性
sudo ./user/reload/hot_reload verify <stage1> [stage2 ...]

# 详细输出
sudo ./user/reload/hot_reload reload <module_name> --verbose
```

### 包装脚本

```bash
# 便捷包装
sudo ./scripts/hot-reload.sh reload my_module
```

### 选项

| 参数 | 说明 |
|------|------|
| `-n`, `--dry-run` | 验证新模块但不执行交换 |
| `-v`, `--verbose` | 重载过程中输出详细进度 |
| `-p`, `--prog-fd <fd>` | 手动指定rs_progs map FD（默认自动检测）|
| `-h`, `--help` | 显示使用帮助 |

---

## 5. 故障模式与恢复

### 模块加载失败（验证器拒绝）

**现象**：BPF验证器拒绝新模块。交换从未尝试。

**恢复方法**：修复模块源码，重新编译，重试。旧模块继续正常运行。

### ABI不匹配

**现象**：新模块声明ABI v1，但平台运行ABI v2（或反之）。交换在加载前被拒绝。

**恢复方法**：使用正确的SDK版本重新编译模块。

### 模块名称不匹配

**现象**：模块二进制的 `RS_DECLARE_MODULE(name, ...)` 与传给 `reload` 的名称不一致。交换被拒绝。

**恢复方法**：传入正确的模块名称（与 `RS_DECLARE_MODULE` 声明匹配）。

### 交换验证失败

**现象**：`bpf_map_update_elem` 之后，回读检查发现prog_id与预期不同。极为罕见，表示存在并发修改。

**恢复方法**：工具会尝试恢复旧程序。如果恢复失败，需要通过 `rswitch_loader` 进行完整流水线重载。

### 模块运行时崩溃

**现象**：新模块通过了验证器但存在逻辑错误（例如始终返回XDP_DROP）。

**恢复方法**：使用之前已知正常的二进制文件重新运行 `hot_reload reload <module_name>`。没有自动回滚机制。

---

## 6. 架构细节

### 文件布局

```
user/reload/
├── hot_reload.c              # 热重载主实现（1100+ 行）
└── Makefile                   # 构建规则（链接 libbpf）
```

### 核心数据结构

```c
struct reload_ctx {
    struct reload_module modules[MAX_MODULES];  // 跟踪的模块
    int num_modules;
    int rs_progs_fd;          // rs_progs prog_array 的文件描述符
    int rs_prog_chain_fd;     // rs_prog_chain（出站）的文件描述符
    int verbose;
    int dry_run;
};
```

### Map依赖

| Map | 用途 |
|-----|------|
| `rs_progs` | Prog_array — 实际交换目标。固定在 `/sys/fs/bpf/rs_progs`。|
| `rs_prog_chain` | 出站流水线链接。重载出站模块时更新。|

---

*另见：[模块开发指南](Module_Developer_Guide.md) · [ABI策略](ABI_POLICY.md) · [平台架构](Architecture.md)*
