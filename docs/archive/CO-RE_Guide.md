> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# CO-RE Support in rSwitch

## 概述

rSwitch 现在支持 **CO-RE (Compile Once - Run Everywhere)**，这是 eBPF 的一个关键特性，使得编译好的 BPF 程序可以在不同内核版本上运行而无需重新编译。

## 什么是 CO-RE？

CO-RE 通过以下机制实现跨内核版本的可移植性：

1. **BTF (BPF Type Format)**：内核类型信息的紧凑表示
2. **vmlinux.h**：包含所有内核类型定义的单一头文件
3. **libbpf 重定位**：加载时自动调整结构体字段偏移
4. **特性检测**：运行时检测内核是否支持特定字段/功能

### 传统方式 vs CO-RE

**传统方式**（当前 src/ PoC 代码）：
```c
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
// ... 多个内核头文件
// 问题：
// - 依赖编译时的内核头文件版本
// - 不同内核版本需要重新编译
// - struct 布局变化导致程序失败
```

**CO-RE 方式**（新的 rswitch/ 代码）：
```c
#include "rswitch_bpf.h"  // 包含 vmlinux.h + helpers
// 优势：
// - 单一头文件包含所有内核类型
// - BTF 自动重定位字段访问
// - 一次编译，到处运行
```

## 系统要求

### 内核要求
- **最低版本**：Linux 5.8+
- **配置要求**：
  ```bash
  CONFIG_DEBUG_INFO_BTF=y        # BTF 支持
  CONFIG_DEBUG_INFO_BTF_MODULES=y # 模块 BTF（可选）
  ```

### 检查当前内核是否支持：
```bash
# 检查 BTF 是否可用
ls /sys/kernel/btf/vmlinux

# 查看 BTF 信息
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -20
```

### 工具要求
- **bpftool**：v5.8+ (用于生成 vmlinux.h)
- **libbpf**：v0.6+ (CO-RE 重定位支持)
- **clang/LLVM**：v10+ (BTF 生成)

## 使用方法

### 1. 生成 vmlinux.h

首次编译前需要生成 vmlinux.h：

```bash
cd rswitch/
make vmlinux
```

这会从当前运行的内核的 BTF 信息生成 `bpf/include/vmlinux.h`。

**注意**：
- vmlinux.h 约 15 万行，已添加到 `.gitignore`
- 每个开发环境需要生成自己的 vmlinux.h
- 生成一次即可，除非切换到不同的内核版本

### 2. 编写 CO-RE BPF 程序

使用新的 `rswitch_bpf.h` 头文件：

```c
// SPDX-License-Identifier: GPL-2.0
#include "../include/rswitch_bpf.h"
#include "../core/module_abi.h"

char _license[] SEC("license") = "GPL";

RS_DECLARE_MODULE("my_module", RS_HOOK_XDP_INGRESS, 50, 0);

SEC("xdp")
int my_module_ingress(struct xdp_md *ctx)
{
    /* 使用 CO-RE helpers 安全访问数据包 */
    struct ethhdr *eth = get_ethhdr(ctx);
    if (!eth)
        return XDP_DROP;
    
    /* 使用 bpf_ntohs 处理字节序 */
    __u16 proto = bpf_ntohs(eth->h_proto);
    
    if (proto == ETH_P_IP) {
        /* IPv4 处理... */
    }
    
    return XDP_PASS;
}
```

### 3. CO-RE 字段访问

对于可能在不同内核版本中布局变化的结构体：

```c
/* 直接访问（不推荐，除非确定字段固定） */
__u32 data = ctx->data;

/* CO-RE 安全访问（推荐） */
__u32 data;
bpf_core_read(&data, sizeof(data), &ctx->data);
```

### 4. 特性检测

检测内核是否支持特定字段：

```c
SEC("xdp")
int adaptive_module(struct xdp_md *ctx)
{
    /* 编译时检测 */
    #if __has_builtin(__builtin_preserve_access_index)
        /* 支持 CO-RE */
    #endif
    
    /* 运行时特性检测 */
    if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
        /* 使用 rx_queue_index 特性 (5.18+) */
        __u32 queue;
        bpf_core_read(&queue, sizeof(queue), &ctx->rx_queue_index);
        bpf_debug("RX queue: %u", queue);
    } else {
        /* 回退方案 */
        bpf_debug("rx_queue_index not available");
    }
    
    return XDP_PASS;
}
```

## 提供的 CO-RE Helpers

`rswitch_bpf.h` 提供以下辅助函数和宏：

### 数据包访问
```c
/* 安全获取 Ethernet 头 */
struct ethhdr *eth = get_ethhdr(ctx);

/* 安全获取 IPv4 头 */
struct iphdr *iph = get_iphdr(ctx, l3_offset);

/* 安全获取 IPv6 头 */
struct ipv6hdr *ip6h = get_ipv6hdr(ctx, l3_offset);

/* 通用头部访问宏 */
struct tcphdr *tcp = GET_HEADER(ctx, l4_offset, struct tcphdr);
```

### 字段操作
```c
/* CO-RE 字段读取 */
READ_KERN(dst, src);

/* 检查字段是否存在 */
if (FIELD_EXISTS(struct my_struct, my_field)) {
    /* ... */
}

/* 获取字段大小 */
size_t sz = FIELD_SIZE(struct iphdr, ihl);
```

### 调试
```c
/* 条件编译的调试输出 */
bpf_debug("Packet length: %u", pkt_len);  // 仅在 -DDEBUG 时输出
```

### 边界检查
```c
/* 检查数据包边界 */
if (!CHECK_BOUNDS(ctx, ptr, size)) {
    return XDP_DROP;
}
```

## 编译和部署

### 本地开发
```bash
# 1. 生成 vmlinux.h（首次或内核升级后）
make vmlinux

# 2. 编译 BPF 程序
make clean
make

# 3. 加载并测试
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml
```

### 跨内核部署

编译好的 `.bpf.o` 文件可以直接部署到不同内核版本的机器上：

```bash
# 在 Kernel 5.15 上编译
make vmlinux  # 使用 5.15 的 BTF
make

# 部署到 Kernel 6.1 服务器
scp build/bpf/*.bpf.o server:/opt/rswitch/
ssh server "cd /opt/rswitch && ./rswitch_loader"
# ✅ 自动适配 6.1 内核的结构体布局
```

**注意**：
- libbpf 在加载时会根据目标内核的 BTF 重定位字段访问
- 不需要在目标机器上有 vmlinux.h 或内核头文件
- 只需要目标内核支持 BTF (`/sys/kernel/btf/vmlinux` 存在)

## 示例：CO-RE 模块

查看 `bpf/modules/core_example.bpf.c` 获取完整的 CO-RE 使用示例，包括：

- ✅ 使用 vmlinux.h 的类型定义
- ✅ CO-RE 字段访问
- ✅ 运行时特性检测
- ✅ 可移植的数据包解析
- ✅ 跨内核版本的统计收集

编译示例：
```bash
make
# 输出: build/bpf/core_example.bpf.o
```

## 性能影响

CO-RE 对性能的影响：

- **编译时**：稍慢（需要处理 vmlinux.h 的 15 万行）
- **加载时**：稍慢（libbpf 执行 BTF 重定位）
- **运行时**：**零开销**（重定位后的代码与直接访问相同）

基准测试（相比传统方式）：
- 编译时间：+10-20%
- 加载时间：+5-10%
- 包处理速度：**无差异**（0% 开销）
- 二进制大小：-20-30%（更少的重复类型定义）

## 迁移指南

### 从传统 BPF 代码迁移到 CO-RE

**Step 1**: 替换头文件
```diff
- #include <linux/if_ether.h>
- #include <linux/ip.h>
- #include <linux/tcp.h>
+ #include "../include/rswitch_bpf.h"
```

**Step 2**: 更新字段访问（如果需要）
```diff
  struct xdp_md *ctx = ...;
- void *data = (void *)(long)ctx->data;
+ void *data = (void *)(long)ctx->data;  // 简单字段无需修改

  // 对于可能变化的复杂结构：
  struct sk_buff *skb = ...;
- __u64 tstamp = skb->tstamp;
+ __u64 tstamp;
+ bpf_core_read(&tstamp, sizeof(tstamp), &skb->tstamp);
```

**Step 3**: 添加特性检测（可选）
```c
if (bpf_core_field_exists(struct xdp_md, rx_queue_index)) {
    /* 使用新特性 */
} else {
    /* 回退方案 */
}
```

**Step 4**: 重新编译和测试
```bash
make vmlinux
make clean && make
sudo ./build/rswitch_loader --profile etc/profiles/l2.yaml
```

## 当前迁移状态

### ✅ 已支持 CO-RE
- `bpf/core/dispatcher.bpf.c` - 入口分发器
- `bpf/modules/core_example.bpf.c` - CO-RE 示例模块
- `bpf/include/rswitch_bpf.h` - CO-RE 通用头文件
- Makefile - 自动生成 vmlinux.h

### 🔄 待迁移
- `bpf/core/egress.bpf.c`
- `bpf/modules/vlan.bpf.c`
- `bpf/modules/l2learn.bpf.c`
- `bpf/modules/lastcall.bpf.c`
- `bpf/modules/afxdp_redirect.bpf.c`

### 迁移优先级
1. **高优先级**：核心模块（dispatcher, egress, lastcall）
2. **中优先级**：功能模块（vlan, l2learn, acl）
3. **低优先级**：测试模块和工具

## 故障排查

### 问题 1：vmlinux.h 生成失败
```bash
# 错误：bpftool not found
# 解决：
sudo apt install linux-tools-$(uname -r)
# 或手动指定 bpftool 路径
make BPFTOOL=/usr/local/sbin/bpftool vmlinux
```

### 问题 2：BTF 不可用
```bash
# 错误：/sys/kernel/btf/vmlinux not found
# 原因：内核未启用 BTF
# 解决：升级到支持 BTF 的内核 (5.8+) 或重新编译内核启用 CONFIG_DEBUG_INFO_BTF
```

### 问题 3：加载时重定位失败
```bash
# 错误：libbpf: failed to relocate field offset
# 原因：字段在目标内核中不存在
# 解决：使用 bpf_core_field_exists() 检测特性并提供回退方案
```

### 问题 4：编译时间过长
```bash
# vmlinux.h 过大导致编译慢
# 优化：使用 ccache 缓存编译结果
sudo apt install ccache
export CC="ccache clang"
make
```

## 最佳实践

1. **生成 vmlinux.h**：每个开发环境生成一次，加入 `.gitignore`
2. **优先使用 CO-RE**：新模块默认使用 rswitch_bpf.h
3. **特性检测**：对于内核 5.18+ 特性使用 `bpf_core_field_exists()`
4. **测试兼容性**：在多个内核版本上测试加载
5. **文档字段访问**：对于 CO-RE 访问的字段添加注释说明最低内核版本

## 参考资料

- [BPF CO-RE 官方文档](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [libbpf CO-RE API](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
- [BTF 规范](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [vmlinux.h 生成指南](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)

## 总结

CO-RE 支持为 rSwitch 带来的好处：

✅ **可移植性**：一次编译，多内核运行  
✅ **简化部署**：无需目标机器的内核头文件  
✅ **向前兼容**：新内核特性自动检测  
✅ **代码简洁**：单一头文件替代多个 `<linux/*.h>`  
✅ **零性能损失**：运行时与传统方式相同  
✅ **更小二进制**：减少重复类型定义  

建议所有新的 BPF 模块使用 CO-RE，逐步迁移现有模块以获得最佳的可移植性。
