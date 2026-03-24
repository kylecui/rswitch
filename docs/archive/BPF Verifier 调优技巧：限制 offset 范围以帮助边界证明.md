> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# BPF Verifier 调优技巧：限制 offset 范围以帮助边界证明

## 背景问题

在 eBPF/XDP 程序中，常见的加载错误为：

```
invalid access to packet, off=X size=Y, Rn offset is outside of the packet
```

其根本原因是：verifier 无法证明 `data + offset < data_end` 对所有路径都成立。当 `offset` 是一个大范围动态值（例如 `__u16`），verifier 认为其可能高达 65535，从而无法保证边界安全。

例如：

```c
__u16 l3_off = ctx->layers.l3_offset;
if (data + l3_off + sizeof(struct iphdr) > data_end)
    return XDP_DROP;
```

在 verifier 看来，`l3_off` 可能高达 65535，无法证明该访问一定安全。

---

## 技巧核心：使用按位与限制范围

通过将 `l3_off` 与 `0xFF` 按位与，可将可能范围收缩到 `[0, 255]`，使 verifier 能够推导出安全性。

```c
__u16 l3_off = ctx->layers.l3_offset & 0xFF;
if (data + l3_off + sizeof(struct iphdr) > data_end)
    return XDP_DROP;

struct iphdr *iph = data + l3_off;
__u8 ttl = iph->ttl;
```

这样 verifier 能够证明：

> 如果 `data_end - data >= 275` (255 + 20)，则访问 IPv4 头 20 字节安全。

---

## 原理解释

| 项目                      | 原值                               | 限制后                | 影响                   |
| ----------------------- | -------------------------------- | ------------------ | -------------------- |
| `ctx->layers.l3_offset` | `__u16`，范围 0–65535               | `& 0xFF` 后范围 0–255 | 大幅收窄 verifier 需考虑的路径 |
| verifier 证明目标           | `data + offset + 20 <= data_end` | offset ≤ 255，轻松成立  | 几乎所有以太网帧都 >64B       |
| 实际以太网 L3 偏移             | 14（Ethernet）/18（VLAN）            | ≤255 足够            | 无功能副作用               |

---

## 实际验证效果

### 修改前

```
invalid access to packet, off=16 size=4, R8 offset is outside of the packet
```

### 修改后

```
prog load successful: verified 168 insns, stack depth 64B
```

verifier 能证明 `data + (l3_off & 0xFF) + 20 <= data_end`，从而允许对 `iph->ttl`、`iph->daddr` 等字段访问。

---

## 适用场景

✅ 推荐：

* XDP 层解析 IPv4/IPv6/TCP/UDP header
* VLAN/QinQ/PPPoE 动态 L3 偏移场景
* 自定义 L2/L3 解析器

❌ 不建议：

* AF_XDP zero-copy 场景（使用固定 metadata 更安全）
* 隧道协议偏移 > 255 的情况（VXLAN/GRE/GENEVE）

---

## 延伸思路

* 限制范围不仅可用于 offset，也可用于动态长度字段（如 payload_len、hdr_len）
* 对于复杂情况，可用 `min(offset, 255)` 或 `offset & 0x1FF` 等形式手动约束
* 核心思想是：**让 verifier 能在静态范围内完成数学推导**

---

## 总结

> eBPF verifier 并非“执行”代码，而是进行符号范围推理。
> 缩小不确定范围（通过掩码、裁剪或 clamp）是帮助 verifier 证明安全访问的核心技巧。

---

**一句话记忆：**

> `offset &= 0xFF;` —— 小小一行，换来 verifier 的安心。

## Layer Offset分析
### L2层（Ethernet + VLAN）
- 基础Ethernet: 14字节
- 单层VLAN (802.1Q): +4字节 = 18字节
- 双层VLAN (QinQ 802.1ad): +4字节 = 22字节
- L3_offset最大值: 22字节

### L3层（IP）
- L2最大 + IPv4最小: 22 + 20 = 42字节
- L2最大 + IPv4最大（带options）: 22 + 60 = 82字节
- L2最大 + IPv6: 22 + 40 = 62字节（不含扩展头）
- IPv6扩展头（Hop-by-Hop, Routing等）: 可能额外+数十字节
- L4_offset最大值: ~120字节（保守估计）

### L4层（TCP/UDP）
- L2+L3最大 + TCP最小: 120 + 20 = 140字节
- L2+L3最大 + TCP最大（带options）: 120 + 60 = 180字节
- L2+L3最大 + UDP: 120 + 8 = 128字节
- Payload_offset最大值: ~200字节（保守估计）

### Mask选择策略
有两种思路：

#### 方案1：最小够用（当前使用）
- 0xFF (255) 足够覆盖所有情况
- 优点：简单统一
- 缺点：不够精确，允许了不合理的值

#### 方案2：精确限制（更安全）
- L3: 0x3F (63) - 覆盖到64字节
- L4: 0x7F (127) - 覆盖到128字节
- Payload: 0xFF (255) - 覆盖到256字节
- 优点：更严格的验证，避免异常值
- 缺点：需要针对每层调整