> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# QoS 端口分类与优先级管理指南

## 快速概览

rSwitch QoS 模块通过**端口号**和**协议**自动分类流量优先级，并可以通过 `rsqosctl` 工具动态覆盖默认规则。

---

## 优先级级别

```
Level 3: CRITICAL  - 关键管理流量（SSH, SNMP, DNS）
Level 2: HIGH      - 高优先级流量（HTTP/HTTPS, ICMP）
Level 1: NORMAL    - 默认流量（未分类的流量）
Level 0: LOW       - 低优先级流量（FTP, SMTP, 备份）
```

---

## 默认端口分类规则

这些规则硬编码在 `rswitch/bpf/modules/egress_qos.bpf.c` 中（line 325-360）：

### CRITICAL (Level 3)
| 协议 | 端口 | 服务 | 说明 |
|------|------|------|------|
| TCP | 22 | SSH | 远程管理 |
| TCP | 23 | Telnet | 远程管理（不安全） |
| TCP | 161 | SNMP | 网络管理 |
| TCP | 162 | SNMP Trap | 网络告警 |
| UDP | 53 | DNS | 域名解析 |
| UDP | 123 | NTP | 时间同步 |
| UDP | 161 | SNMP | 网络管理 |
| UDP | 162 | SNMP Trap | 网络告警 |

### HIGH (Level 2)
| 协议 | 端口 | 服务 | 说明 |
|------|------|------|------|
| TCP | 80 | HTTP | Web 流量 |
| TCP | 443 | HTTPS | 加密 Web 流量 |
| TCP | 8080 | HTTP-alt | 备用 HTTP |
| UDP | 53 | DNS | 域名解析（注意：也在 CRITICAL 中） |
| UDP | 67 | DHCP Server | 地址分配 **⚠️ 注意：会被拦截！** |
| UDP | 68 | DHCP Client | 地址请求 **⚠️ 注意：会被拦截！** |
| UDP | 123 | NTP | 时间同步（注意：也在 CRITICAL 中） |
| ICMP | - | ICMP | 网络诊断（ping/traceroute） |

### LOW (Level 0)
| 协议 | 端口 | 服务 | 说明 |
|------|------|------|------|
| TCP | 20 | FTP-data | 文件传输数据 |
| TCP | 21 | FTP | 文件传输控制 |
| TCP | 25 | SMTP | 邮件传输 |

### NORMAL (Level 1)
所有未匹配的流量默认为 NORMAL 优先级。

---

## 与 VOQd 的关系

VOQd 通过 `prio_mask` 配置决定拦截哪些优先级的流量：

```yaml
prio_mask: 0x0C  # 0b1100 = Bit 2 (HIGH) + Bit 3 (CRITICAL)
```

| `prio_mask` | 二进制 | 拦截的优先级 | 使用场景 |
|-------------|--------|--------------|----------|
| `0x00` | `0b0000` | 无 | VOQd 禁用（等同于 BYPASS） |
| `0x01` | `0b0001` | LOW | 测试用，不推荐 |
| `0x02` | `0b0010` | NORMAL | 测试用，不推荐 |
| `0x04` | `0b0100` | HIGH | 只拦截高优先级（推荐用于测试） |
| `0x08` | `0b1000` | CRITICAL | 只拦截关键流量 |
| `0x0C` | `0b1100` | HIGH + CRITICAL | **默认配置**，平衡性能和控制 |
| `0x0E` | `0b1110` | NORMAL + HIGH + CRITICAL | 只有 LOW 走快速路径 |
| `0x0F` | `0b1111` | 全部 | 所有流量经过 VOQd（高 CPU 负载） |

---

## 如何修改端口优先级

### 场景 1: DHCP 无法工作（被 VOQd 拦截）

**问题**：DHCP (UDP 67/68) 默认是 HIGH，被 `prio_mask=0x0C` (HIGH + CRITICAL) 拦截，导致客户端无法获取 IP 地址。

**症状**：
- `dhclient` 一直尝试获取 IP，但超时失败
- 观察 trace 看到 DHCP 包被 afxdp_redirect 拦截
- 客户端显示 "No DHCP offers received"

**解决方案 A**：修改 DHCP 的优先级为 NORMAL（推荐）

```bash
# 加载 profile 后执行
sudo ./build/rsqosctl add-class --proto udp --dport 67 --priority normal
sudo ./build/rsqosctl add-class --proto udp --dport 68 --priority normal

# 验证修改
sudo bpftool map dump name qos_class_map | grep -E "67|68"

# 现在 DHCP 走快速路径，不经过 VOQd
```

**解决方案 B**：修改 `prio_mask`，只拦截 CRITICAL

```yaml
# 修改 profile 文件
prio_mask: 0x08  # 只拦截 CRITICAL，不拦截 HIGH (DHCP, HTTP, ICMP)
```

或运行时修改：

```bash
sudo ./build/rsvoqctl set-mode --mode active --prio-mask 0x08
```

**解决方案 C**：完全禁用 VOQd（测试用）

```bash
sudo ./build/rsvoqctl set-mode --mode bypass
```

---

### 场景 2: SSH 被 VOQd 拦截，想让它走快速路径

**问题**：SSH (port 22) 默认是 CRITICAL，被 `prio_mask=0x0C` 拦截。

**解决方案 A**：修改 SSH 的优先级为 NORMAL（推荐）

```bash
# 加载 profile 后执行
sudo ./build/rsqosctl add-class --proto tcp --dport 22 --priority normal

# 验证修改
sudo bpftool map dump name qos_class_map

# 现在 SSH 走快速路径，不经过 VOQd
```

**解决方案 B**：修改 `prio_mask`，只拦截 CRITICAL 以外的流量

```yaml
# 修改 profile 文件
prio_mask: 0x04  # 只拦截 HIGH，不拦截 CRITICAL
```

或运行时修改：

```bash
sudo ./build/rsvoqctl set-mode --mode active --prio-mask 0x04
```

**解决方案 C**：完全禁用 VOQd

```bash
sudo ./build/rsvoqctl set-mode --mode bypass
```

---

### 场景 3: 自定义应用端口分类

假设你有一个自定义应用运行在 TCP 9000，想将其归类为 HIGH 优先级：

```bash
# 添加自定义分类规则
sudo ./build/rsqosctl add-class --proto tcp --dport 9000 --priority high

# 验证
sudo bpftool map dump name qos_class_map | grep 9000

# 删除自定义规则（恢复默认）
sudo ./build/rsqosctl del-class --proto tcp --dport 9000
```

---

### 场景 4: 基于 DSCP 分类

如果流量已经携带了 DSCP 标记（例如来自上游路由器），可以基于 DSCP 分类：

```bash
# DSCP 46 (EF) → CRITICAL
sudo ./build/rsqosctl add-class --proto tcp --dscp 46 --priority critical

# DSCP 34 (AF41) → HIGH
sudo ./build/rsqosctl add-class --proto tcp --dscp 34 --priority high
```

**注意**：DSCP 分类优先级**高于**端口分类。

---

## 分类查找顺序

QoS 模块按照以下顺序查找分类规则：

```
1. qos_class_map 查找 (proto + dscp + dport)
   ↓ 未命中
2. qos_class_map 查找 (proto + dport, dscp=0)
   ↓ 未命中
3. 硬编码的默认端口规则（见上表）
   ↓ 未命中
4. 返回 NORMAL 优先级
```

**关键点**：`qos_class_map` 中的规则**优先级最高**，可以覆盖硬编码的默认规则。

---

## 调试技巧

### 查看当前分类表

```bash
# 查看所有自定义分类规则
sudo bpftool map dump name qos_class_map

# 输出示例：
# key: 06 00 16 00  value: 01 00 00 00 00 00 00 00
#      ^^    ^^^^           ^^
#      |     |              └─ priority (01 = NORMAL)
#      |     └─ dport (0x0016 = 22)
#      └─ proto (06 = TCP)
```

### 查看优先级统计

```bash
# 查看每个优先级处理了多少包
sudo ./build/rsqosctl --stats

# 或手动读取
sudo bpftool map dump name qos_stats_map
```

### 实时观察 QoS 分类

```bash
# 启用 debug 模式（需要重新编译 BPF）
# 在 rswitch/bpf/modules/egress_qos.bpf.c 中设置 RS_DEBUG_LEVEL=1

# 观察日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "QoS:"
```

输出示例：
```
<...>-12345 [002] d.s. 12345.678901: bpf_trace_printk: QoS: proto=6 dport=22 → priority=3
<...>-12345 [002] d.s. 12345.678902: bpf_trace_printk: QoS: proto=6 dport=80 → priority=2
```

---

## 常见问题

### Q1: 为什么 DHCP 无法工作？

**A**: DHCP (UDP 67/68) 默认被分类为 HIGH，而默认的 `prio_mask=0x0C` 会拦截 HIGH 和 CRITICAL。解决方法：
1. 修改 `prio_mask=0x08`（推荐，只拦截 CRITICAL）
2. 改变 DHCP 优先级为 NORMAL（使用 `rsqosctl add-class`）
3. 临时禁用 VOQd（`rsvoqctl set-mode --mode bypass`）

---

### Q2: 为什么 SSH 会被 VOQd 拦截？

**A**: SSH (port 22) 默认被分类为 CRITICAL，而默认的 `prio_mask=0x0C` 包含了 CRITICAL。使用上面的方法改变 SSH 优先级或调整 `prio_mask`。

---

### Q3: 如何让所有流量都走快速路径？

**A**: 三种方法：
1. 设置 `prio_mask=0x00`（但 VOQd 仍然运行）
2. 设置 VOQd `mode=bypass`（完全禁用 VOQd）
3. 不加载 `afxdp_redirect` 模块（最彻底）

---

### Q4: 自定义分类规则会持久化吗？

**A**: 不会。规则存储在 BPF map 中，重启 loader 后会丢失。要持久化，有两种方法：
1. 将规则写入 profile 文件（未来支持）
2. 创建启动脚本调用 `rsqosctl`

---

### Q5: 可以基于源 IP 或目的 IP 分类吗？

**A**: 当前版本不支持。分类键只包含 `{proto, dscp, dport}`。如果需要 IP 级别的分类，可以：
1. 修改 `struct qos_class_key` 添加 IP 字段（需要重新编译）
2. 使用 ACL 模块进行更复杂的策略（未来功能）

---

### Q6: DSCP 和端口分类冲突时，哪个优先？

**A**: DSCP 优先。分类查找会先尝试 `{proto, dscp, dport}`，命中则不再查找 `{proto, 0, dport}`。

---

## 相关文档

- **QoS 实现详细说明**：`rswitch/docs/QoS_and_Telemetry_Implementation.md`
- **VOQd 集成**：`rswitch/docs/VOQd_Integration_Summary.md`
- **AF_XDP 重定向**：`rswitch/docs/afxdp_redirect_module.md`
- **测试配置**：`rswitch/etc/profiles/l3-qos-voqd-test.yaml`

---

## 代码位置

- **QoS 模块**：`rswitch/bpf/modules/egress_qos.bpf.c`
- **控制工具**：`rswitch/user/tools/rsqosctl.c`
- **优先级常量**：`rswitch/bpf/core/afxdp_common.h` (line 25-28)
- **默认分类规则**：`egress_qos.bpf.c` line 325-360

---

## 总结

**关键要点**：
1. 端口分类有硬编码的默认规则（SSH=CRITICAL, HTTP=HIGH, FTP=LOW）
2. `qos_class_map` 中的规则可以覆盖默认规则
3. VOQd 的 `prio_mask` 决定拦截哪些优先级
4. 使用 `rsqosctl add-class` 可以运行时修改分类，无需重启

**推荐工作流**：
1. 使用默认配置启动
2. 观察 QoS 统计和 VOQd 行为
3. 根据需要使用 `rsqosctl` 微调分类规则
4. 性能稳定后，将规则固化到 profile 或启动脚本
