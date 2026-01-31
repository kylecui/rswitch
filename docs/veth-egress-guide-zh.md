# VOQd Veth 出口路径

## 概述

本文档描述了 veth 出口路径的实现，该实现使 VOQd（虚拟输出队列守护进程）发送的数据包能够经过 XDP 出口处理。

### 问题陈述

当 VOQd 通过 AF_XDP TX 发送数据包时，会绕过 XDP devmap 出口钩子：

```
标准 AF_XDP TX 路径（出口处理失效）：
  VOQd AF_XDP TX → 网卡驱动 → 线路
                   ↑
                   跳过了 devmap 出口程序！
                   没有 VLAN 标记，没有 QoS 标记
```

### 解决方案

通过 veth 对将 VOQd TX 重新引入 XDP 路径：

```
Veth 出口路径（正确）：
  VOQd AF_XDP TX → veth_voq_in → veth_voq_out (XDP) → devmap 重定向 → 物理网卡
                                      ↑
                                      出口模块在此运行：
                                      - VLAN 标记
                                      - QoS 标记
                                      - 统计信息
```

### 性能

veth 上的原生 XDP 是零拷贝的（仅传输指针）：
- 吞吐量：~194 Gbps（200G 网卡基准测试）
- 延迟开销：~15μs

---

## 架构

### 组件

| 组件 | 文件 | 用途 |
|------|------|------|
| BPF 模块 | `bpf/modules/veth_egress.bpf.c` | veth_voq_out 的 XDP 程序 |
| 共享头文件 | `bpf/core/veth_egress_common.h` | `voq_tx_meta` 结构定义 |
| 设置脚本 | `scripts/setup_veth_egress.sh` | 创建/销毁 veth 对 |
| VOQd 数据面 | `user/voqd/voqd_dataplane.c` | 支持 veth 的 TX 路径 |
| 加载器 | `user/loader/rswitch_loader.c` | 加载 veth 出口 XDP 程序 |
| 配置解析器 | `user/loader/profile_parser.c` | 从 YAML 解析 veth 配置 |

### 数据包流程

```
┌─────────────────────────────────────────────────────────────────────┐
│                        用户空间 (VOQd)                               │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  1. 从 VOQ 出队数据包                                            │ │
│  │  2. 添加 voq_tx_meta 头部（16 字节）                              │ │
│  │  3. AF_XDP TX 发送到 veth_voq_in                                 │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ↓ AF_XDP TX
┌─────────────────────────────────────────────────────────────────────┐
│  veth_voq_in                                                         │
│  （无 XDP 程序，仅接收数据包）                                         │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ↓ veth 对端传输（零拷贝）
┌─────────────────────────────────────────────────────────────────────┐
│  veth_voq_out                                                        │
│  XDP 程序：veth_egress_redirect                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  1. 解析 voq_tx_meta 头部                                        │ │
│  │  2. 剥离头部 (bpf_xdp_adjust_head)                               │ │
│  │  3. 恢复 rs_ctx 供出口模块使用                                    │ │
│  │  4. bpf_redirect_map() 到 voq_egress_devmap                      │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ↓ devmap 重定向（触发出口程序）
┌─────────────────────────────────────────────────────────────────────┐
│  物理网卡 (eth0, eth1, ...)                                          │
│  Devmap 出口程序：rswitch_egress                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  1. 运行 egress_qos 模块（QoS 标记）                              │ │
│  │  2. 运行 egress_vlan 模块（VLAN 标记）                            │ │
│  │  3. 运行 egress_final 模块（统计信息）                            │ │
│  │  4. 发送到线路                                                   │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### 元数据头部

VOQd 在每个数据包前添加 16 字节的元数据头部：

```c
struct voq_tx_meta {
    __u32 egress_ifindex;    // 目标物理接口
    __u32 ingress_ifindex;   // 原始入口接口
    __u8  prio;              // QoS 优先级 (0-3)
    __u8  flags;             // 处理标志
    __u16 vlan_id;           // VLAN ID（如适用）
    __u32 reserved;          // 保留字段
} __attribute__((packed));   // 总计：16 字节
```

标志位：
- `VOQ_TX_FLAG_SKIP_VLAN (0x01)`：跳过 VLAN 标记
- `VOQ_TX_FLAG_SKIP_QOS (0x02)`：跳过 QoS 处理
- `VOQ_TX_FLAG_FROM_VOQ (0x80)`：VOQ 来源数据包标记

---

## 配置

### YAML 配置文件

```yaml
voqd_config:
  enabled: true
  mode: active
  enable_afxdp: true
  
  # Veth 出口配置
  use_veth_egress: true           # 启用 veth 出口路径
  veth_in_ifname: veth_voq_in     # VOQd TX 目标接口（默认值）
```

### 配置选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `use_veth_egress` | bool | true（当 VOQd 启用时） | 启用 veth 出口路径 |
| `veth_in_ifname` | string | "veth_voq_in" | VOQd TX 目标接口名 |

---

## 修改/创建的文件

### 新建文件

1. **`bpf/core/veth_egress_common.h`**
   - 包含 `voq_tx_meta` 结构的共享头文件
   - 标志位定义
   - BPF 和用户空间共用

2. **`bpf/modules/veth_egress.bpf.c`**
   - XDP 程序 `veth_egress_redirect`
   - 解析元数据、剥离头部、重定向到 devmap
   - 映射表：`veth_egress_config_map`、`veth_egress_stats`、`voq_egress_devmap`

3. **`scripts/setup_veth_egress.sh`**
   - 创建具有 XDP 兼容设置的 veth 对
   - 禁用卸载功能（GRO、GSO、TSO）
   - 设置适当的队列长度

### 修改的文件

1. **`user/voqd/voqd_dataplane.h`**
   - 在配置中添加 `use_veth_egress`、`veth_in_ifname`、`veth_in_ifindex`
   - 在数据面结构中添加 `veth_xsk_mgr`

2. **`user/voqd/voqd_dataplane.c`**
   - `voqd_dataplane_init()`：初始化 veth XSK 管理器
   - `voqd_dataplane_tx_process()`：添加元数据、TX 到 veth
   - `voqd_dataplane_destroy()`：清理 veth 资源

3. **`user/loader/rswitch_loader.c`**
   - 添加 `setup_veth_egress()` 函数
   - 加载 veth_egress BPF 程序
   - 将 XDP 附加到 veth_voq_out
   - 填充 voq_egress_devmap

4. **`user/loader/profile_parser.h`**
   - 在 `rs_profile_voqd` 中添加 `use_veth_egress`、`veth_in_ifname`

5. **`user/loader/profile_parser.c`**
   - 从 YAML 解析新配置选项

6. **`etc/profiles/qos-voqd-test.yaml`**
   - 添加 veth 出口配置部分
   - 添加 veth 设置的部署命令

7. **`etc/profiles/l3-qos-voqd-simple.yaml`**
   - 添加 veth 出口配置

---

## 系统要求

### 内核
- Linux 4.19+ 支持原生 veth XDP
- 推荐 Linux 5.8+ 以获得完整 XDP 功能

### 依赖
- libbpf
- libxdp（用于 AF_XDP）
- clang/LLVM（用于 BPF 编译）

### 硬件
- 支持 XDP 的网络接口
- 足够的 CPU 用于 VOQd 处理

---

## 故障排除

### Veth XDP 附加失败

```bash
# 检查 veth 对是否存在
ip link show veth_voq_in veth_voq_out

# 检查现有的 XDP 程序
ip link show veth_voq_out | grep xdp

# 尝试 generic 模式（较慢，用于测试）
ip link set veth_voq_out xdpgeneric obj build/bpf/veth_egress.bpf.o sec xdp
```

### 数据包未到达物理网卡

```bash
# 检查 devmap 是否已填充
sudo bpftool map dump name voq_egress_devmap

# 检查 veth 出口统计
sudo bpftool map dump name veth_egress_stats

# 启用跟踪
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect/enable
cat /sys/kernel/debug/tracing/trace_pipe
```

### 性能问题

1. 确保使用原生 XDP 模式（非 generic）：
   ```bash
   ip link show veth_voq_out | grep xdp
   # 应显示：prog/xdp（不是 xdpgeneric）
   ```

2. 检查卸载功能是否已禁用：
   ```bash
   ethtool -k veth_voq_in | grep -E "generic|tcp"
   ethtool -k veth_voq_out | grep -E "generic|tcp"
   ```

3. 验证 VOQd 配置中有足够的 UMEM 头部空间

---

## 参考资料

- [XDP on veth - Loophole Labs](https://loopholelabs.io/blog/xdp-redirect-veth)
- [AF_XDP 文档](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf 文档](https://libbpf.readthedocs.io/)
