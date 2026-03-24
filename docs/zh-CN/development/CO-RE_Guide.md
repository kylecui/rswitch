> 📖 [English Version](../../development/CO-RE_Guide.md)

# CO-RE 可移植性指南 (CO-RE Portability Guide)

**CO-RE (Compile Once - Run Everywhere，一次编译，到处运行)** 使得在某一内核版本上编译的 rSwitch BPF module 无需重新编译即可在任何其他内核版本 (5.8+) 上运行。本指南涵盖了 CO-RE 的工作原理、如何编写符合 CO-RE 规范的 module 以及如何跨内核版本进行部署。

---

## 概览 (Overview)

### 传统 BPF vs CO-RE

| 维度 | 传统方式 | CO-RE |
|--------|------------|-------|
| **头文件** | 多个 `<linux/*.h>` 文件 | 单个 `vmlinux.h` + 辅助函数 |
| **可移植性** | 必须针对每个内核重新编译 | 一次编译，到处运行 |
| **字段访问** | 直接访问结构体（布局改变时会崩溃） | 加载时进行 BTF 感知的重定位 (relocation) |
| **依赖关系** | 构建和目标机器均需内核头文件 | 仅构建机器需要；目标机器需要 BTF |
| **二进制大小** | 较大（冗余的类型定义） | 减小 20-30% |
| **运行时开销** | 无 | 无（重定位发生在加载时） |

### 工作原理

1. **BTF (BPF Type Format)**: 内核通过 `/sys/kernel/btf/vmlinux` 导出类型信息
2. **vmlinux.h**: 从 BTF 生成，包含单个头文件中的所有内核类型定义
3. **libbpf 重定位**: 在加载时，libbpf 读取目标内核的 BTF 并调整结构体字段偏移量
4. **特性检测**: `bpf_core_field_exists()` 允许在运行时适配内核能力

---

## 系统要求 (System Requirements)

### 内核

- **最低版本**: Linux 5.8+
- **必要配置**:
  ```
  CONFIG_DEBUG_INFO_BTF=y          # BTF 支持 (必填)
  CONFIG_DEBUG_INFO_BTF_MODULES=y  # Module BTF (可选)
  ```

### 验证 BTF 支持

```bash
# 检查 BTF 是否可用
ls /sys/kernel/btf/vmlinux

# 检查 BTF 内容
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -20
```

### 构建工具

| 工具 | 最低版本 | 用途 |
|------|-----------------|---------|
| bpftool | 5.8+ | 生成 vmlinux.h |
| libbpf | 0.6+ | 加载时进行 CO-RE 重定位 |
| clang/LLVM | 10+ | 在编译对象中生成 BTF |

---

## 生成 vmlinux.h

在首次构建之前（或内核升级之后）：

```bash
cd rswitch/
make vmlinux
```

这将从当前运行内核的 BTF 生成 `bpf/include/vmlinux.h`。注意：

- vmlinux.h 约有 150,000 行；它已包含在 `.gitignore` 中
- 每个开发环境都会生成自己的版本
- 仅在内核版本更改后才需要重新生成

---

## 编写 CO-RE Module

### 头文件引用

```c
// CO-RE 方式 (正确)
#include "../include/rswitch_bpf.h"   // 包含 vmlinux.h + 所有辅助函数

// 传统方式 (不要在新的 module 中使用)
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
```

### 数据包访问辅助函数

`rswitch_bpf.h` 为数据包解析提供了 CO-RE 安全的辅助函数：

```c
// 安全的 Ethernet 报头访问
struct ethhdr *eth = get_ethhdr(ctx);
if (!eth) return XDP_DROP;

// 安全的 IPv4 报头访问
struct iphdr *iph = get_iphdr(ctx, l3_offset);
if (!iph) return XDP_DROP;

// 安全的 IPv6 报头访问
struct ipv6hdr *ip6h = get_ipv6hdr(ctx, l3_offset);

// 通用报头访问宏
struct tcphdr *tcp = GET_HEADER(ctx, l4_offset, struct tcphdr);
```

### CO-RE 字段访问

对于跨版本可能发生布局变化的内核结构体：

```c
// CO-RE 安全读取 (推荐用于内核结构体)
__u64 tstamp;
bpf_core_read(&tstamp, sizeof(tstamp), &skb->tstamp);

// 宏简写
READ_KERN(dst, src);

// 对于布局固定的 XDP 结构体，直接访问是安全的
void *data = (void *)(long)ctx->data;       // OK — xdp_md 是稳定的
void *data_end = (void *)(long)ctx->data_end;  // OK
```

### 运行时特性检测

在运行时适配内核能力：

```c
SEC("xdp")
int adaptive_module(struct xdp_md *ctx)
{
    // 检查当前运行内核中是否存在某个字段
    if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
        // 使用 rx_queue_index 特性 (内核 5.18+)
        __u32 queue;
        bpf_core_read(&queue, sizeof(queue), &ctx->rx_queue_index);
        rs_debug("RX queue: %u", queue);
    } else {
        // 旧版本内核的备选方案
        rs_debug("rx_queue_index not available");
    }

    return XDP_PASS;
}
```

### 字段存在性与大小

```c
// 检查结构体字段是否存在
if (FIELD_EXISTS(struct my_struct, my_field)) {
    // 字段可用 — 使用它
}

// 获取字段大小
size_t sz = FIELD_SIZE(struct iphdr, ihl);
```

### 边界检查 (Bounds Checking)

```c
// 验证指针是否在数据包边界内
if (!CHECK_BOUNDS(ctx, ptr, size)) {
    return XDP_DROP;
}
```

---

## 偏移掩码以确保 Verifier 合规 (Offset Masking for Verifier Compliance)

BPF verifier 要求可证明的有界内存访问。请使用偏移掩码：

```c
// 错误 —— verifier 无法证明偏移量是有界的
struct iphdr *iph = data + ctx->layers.l3_offset;

// 正确 —— 掩码将偏移量限制在已知范围内
struct iphdr *iph = data + (ctx->layers.l3_offset & RS_L3_OFFSET_MASK);
if ((void *)(iph + 1) > data_end)
    return XDP_DROP;
```

| 掩码 | 值 | 最大值 | 用途 |
|------|-------|---------|-----|
| `RS_L3_OFFSET_MASK` | `0x3F` | 63 字节 | L2 报头偏移 |
| `RS_L4_OFFSET_MASK` | `0x7F` | 127 字节 | L3 报头偏移 |
| `RS_PAYLOAD_MASK` | `0xFF` | 255 字节 | 完整报头栈 |

---

## 跨内核部署 (Cross-Kernel Deployment)

编译后的 `.bpf.o` 文件可以部署到任何具有兼容内核的机器上：

```bash
# 在开发机上构建 (内核 5.15)
cd rswitch/
make vmlinux    # 从本地内核生成 vmlinux.h
make            # 编译 BPF 对象

# 部署到生产服务器 (内核 6.1)
scp build/bpf/*.bpf.o server:/opt/rswitch/bpf/
ssh server "cd /opt/rswitch && sudo ./rswitch_loader --profile profiles/l2.yaml --ifaces eth0"
# libbpf 会自动为内核 6.1 适配结构体布局
```

**目标机器的要求：**
- 内核 5.8+ 且开启 BTF (`/sys/kernel/btf/vmlinux` 必须存在)
- 已安装 libbpf
- 不需要内核头文件或 vmlinux.h

---

## 将现有 Module 迁移到 CO-RE

### 第 1 步：替换头文件

```diff
- #include <linux/if_ether.h>
- #include <linux/ip.h>
- #include <linux/tcp.h>
+ #include "../include/rswitch_bpf.h"
```

### 第 2 步：更新字段访问 (如果需要)

对于 `xdp_md` 字段（布局稳定），直接访问即可：
```c
void *data = (void *)(long)ctx->data;  // 无需更改
```

对于可能发生变化的内核内部结构体：
```diff
  struct sk_buff *skb = ...;
- __u64 tstamp = skb->tstamp;           // 内核更改时可能会崩溃
+ __u64 tstamp;
+ bpf_core_read(&tstamp, sizeof(tstamp), &skb->tstamp);  // CO-RE 安全
```

### 第 3 步：添加特性检测 (可选)

```c
if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
    // 使用新特性
} else {
    // 备选方案
}
```

### 第 4 步：重新构建并测试

```bash
make vmlinux     # 重新生成 vmlinux.h (如果尚未完成)
make clean && make
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml --ifaces eth0 --verbose
```

---

## 当前 CO-RE 状态

所有 rSwitch module 均兼容 CO-RE，并可在内核 5.8+ 之间移植：

| 组件 | CO-RE 状态 |
|-----------|-------------|
| `dispatcher.bpf.c` | 完全 CO-RE |
| `egress.bpf.c` | 完全 CO-RE |
| `vlan.bpf.c` | 完全 CO-RE |
| `acl.bpf.c` | 完全 CO-RE |
| `l2learn.bpf.c` | 完全 CO-RE |
| `lastcall.bpf.c` | 完全 CO-RE |
| `afxdp_redirect.bpf.c` | 完全 CO-RE |
| `core_example.bpf.c` | 完全 CO-RE (参考实现) |
| `route.bpf.c` | 完全 CO-RE |
| `mirror.bpf.c` | 完全 CO-RE |
| `egress_vlan.bpf.c` | 完全 CO-RE |
| `egress_qos.bpf.c` | 完全 CO-RE |
| `egress_final.bpf.c` | 完全 CO-RE |

---

## 性能影响 (Performance Impact)

| 阶段 | 影响 | 备注 |
|-------|--------|-------|
| 编译时间 | +10-20% | 处理 vmlinux.h (~150K 行) |
| 加载时间 | +5-10% | libbpf BTF 重定位 |
| **运行时** | **0%** | 重定位后的代码与直接访问完全一致 |
| 二进制大小 | -20-30% | 减少了冗余的类型定义 |

使用 `ccache` 来减轻编译时间的开销：

```bash
sudo apt install ccache
export CC="ccache clang"
make
```

---

## 故障排除 (Troubleshooting)

### vmlinux.h 生成失败

```bash
# 错误: 找不到 bpftool
sudo apt install linux-tools-$(uname -r)
# 或者显式指定路径:
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### 目标机器上 BTF 不可用

```bash
# 错误: 找不到 /sys/kernel/btf/vmlinux
# 解决方案: 升级内核到 5.8+ 并开启 CONFIG_DEBUG_INFO_BTF=y
# 或者重新构建开启了 BTF 的内核
```

### 加载时重定位失败

```bash
# 错误: libbpf: failed to relocate field offset
# 原因: 目标内核中不存在该字段
# 解决方案: 使用 bpf_core_field_exists() 并配合备选逻辑
```

### 编译时间太慢

```bash
# vmlinux.h 约有 150K 行 — 使用 ccache
sudo apt install ccache
export CC="ccache clang"
make clean && make
```

---

## 最佳实践 (Best Practices)

1. **始终为新 module 使用 `rswitch_bpf.h`** — 永远不要包含单独的 `<linux/*.h>` 头文件
2. **每个环境生成一次 vmlinux.h** — 并将其添加到 `.gitignore`
3. **使用 `bpf_core_field_exists()`** 来处理可能在旧版本内核中不存在的内核 5.18+ 特性
4. **在多个内核上进行测试** — 验证至少在 5.15, 6.1 和 6.6 上可以正常加载
5. **记录最低内核版本**，针对任何带有特性门控 (feature-gated) 的代码路径
6. **使用 `core_example.bpf.c` module** 作为 CO-RE 模式的参考

---

## 参考资料 (References)

- [BPF CO-RE 参考 (Nakryiko)](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [libbpf CO-RE API](https://github.com/libbpf/libbpf)
- [BTF 规范](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [CO-RE 可移植性模式](../../paperwork/CO-RE_Portability_Patterns.md) — rSwitch 特有的深度解析

---

## 另请参阅 (See Also)

- [Architecture.md](./Architecture.md) — 系统架构概览
- [Module_Developer_Guide.md](./Module_Developer_Guide.md) — Module 开发教程
- [API_Reference.md](./API_Reference.md) — 完整 API 参考
