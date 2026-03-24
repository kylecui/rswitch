> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Veth Egress Path - Test Instructions
# Veth 出口路径 - 测试说明

This document provides step-by-step instructions to test the veth egress path implementation.
本文档提供逐步说明来测试 veth 出口路径实现。

---

## Prerequisites / 前置条件

### System Requirements / 系统要求

```bash
# Check kernel version (need 4.19+, recommend 5.8+)
# 检查内核版本（需要 4.19+，推荐 5.8+）
uname -r

# Check BPF support
# 检查 BPF 支持
ls /sys/kernel/btf/vmlinux

# Check required tools
# 检查必需工具
which clang llvm-strip bpftool
```

### Network Interfaces / 网络接口

You need at least 2 physical network interfaces for testing.
测试需要至少 2 个物理网络接口。

```bash
# List available interfaces
# 列出可用接口
ip link show

# Example: eth0, eth1 (or enp3s0, enp4s0)
# 示例：eth0, eth1（或 enp3s0, enp4s0）
```

---

## Phase 1: Build / 阶段 1：构建

### Step 1.1: Build rSwitch / 步骤 1.1：构建 rSwitch

```bash
cd /path/to/rSwitch/rswitch

# Clean and build
# 清理并构建
make clean && make

# Expected output should include:
# 预期输出应包含：
#   CC [BPF]  build/bpf/veth_egress.bpf.o
#   ✓ Build complete
```

### Step 1.2: Verify Build Artifacts / 步骤 1.2：验证构建产物

```bash
# Check veth_egress BPF object exists
# 检查 veth_egress BPF 对象是否存在
ls -la build/bpf/veth_egress.bpf.o

# Check BPF program symbols
# 检查 BPF 程序符号
readelf -s build/bpf/veth_egress.bpf.o | grep -E "veth_egress|voq_egress"

# Expected symbols:
# 预期符号：
#   veth_egress_redirect (FUNC)
#   veth_egress_config_map (OBJECT)
#   veth_egress_stats (OBJECT)
#   voq_egress_devmap (OBJECT)
```

**✅ PASS Criteria / 通过标准:**
- `veth_egress.bpf.o` exists / 存在
- Contains `veth_egress_redirect` function / 包含 `veth_egress_redirect` 函数
- Contains required maps / 包含所需映射表

---

## Phase 2: Veth Pair Setup / 阶段 2：Veth 对设置

### Step 2.1: Create Veth Pair / 步骤 2.1：创建 Veth 对

```bash
# Make script executable (if needed)
# 使脚本可执行（如需要）
chmod +x scripts/setup_veth_egress.sh

# Create veth pair
# 创建 veth 对
sudo ./scripts/setup_veth_egress.sh create
```

### Step 2.2: Verify Veth Pair / 步骤 2.2：验证 Veth 对

```bash
# Check interfaces exist and are UP
# 检查接口是否存在且为 UP 状态
ip link show veth_voq_in
ip link show veth_voq_out

# Expected output for each:
# 每个的预期输出：
#   <ifindex>: veth_voq_in@veth_voq_out: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
#   <ifindex>: veth_voq_out@veth_voq_in: <BROADCAST,MULTICAST,UP,LOWER_UP> ...

# Check offloads are disabled
# 检查卸载功能是否已禁用
ethtool -k veth_voq_in | grep -E "generic-receive-offload|tcp-segmentation-offload|generic-segmentation-offload"
ethtool -k veth_voq_out | grep -E "generic-receive-offload|tcp-segmentation-offload|generic-segmentation-offload"

# All should show: off
# 所有应显示：off

# Check TX queue length
# 检查 TX 队列长度
ip link show veth_voq_in | grep qlen
ip link show veth_voq_out | grep qlen

# Should show: qlen 10000
# 应显示：qlen 10000
```

**✅ PASS Criteria / 通过标准:**
- Both interfaces exist and are UP / 两个接口都存在且为 UP 状态
- GRO, GSO, TSO are all OFF / GRO、GSO、TSO 均为 OFF
- TX queue length is 10000 / TX 队列长度为 10000

---

## Phase 3: Load rSwitch with Veth Egress / 阶段 3：加载带 Veth 出口的 rSwitch

### Step 3.1: Prepare Configuration / 步骤 3.1：准备配置

Edit the profile to match your interfaces:
编辑配置文件以匹配您的接口：

```bash
# View current profile
# 查看当前配置文件
cat etc/profiles/qos-voqd-test.yaml | grep -A5 "voqd_config:"

# Ensure these settings exist:
# 确保存在这些设置：
#   use_veth_egress: true
#   veth_in_ifname: veth_voq_in
```

### Step 3.2: Load rSwitch / 步骤 3.2：加载 rSwitch

```bash
# Replace eth0,eth1 with your actual interface names
# 将 eth0,eth1 替换为您实际的接口名称
sudo ./build/rswitch_loader \
    --profile etc/profiles/qos-voqd-test.yaml \
    --ifaces eth0,eth1

# Or for the simple profile:
# 或使用简单配置文件：
sudo ./build/rswitch_loader \
    --profile etc/profiles/l3-qos-voqd-simple.yaml \
    --ifaces enp3s0,enp4s0,enp5s0
```

### Step 3.3: Verify XDP Programs Loaded / 步骤 3.3：验证 XDP 程序已加载

```bash
# Check XDP on physical interfaces
# 检查物理接口上的 XDP
ip link show eth0 | grep xdp
ip link show eth1 | grep xdp

# Check XDP on veth_voq_out
# 检查 veth_voq_out 上的 XDP
ip link show veth_voq_out | grep xdp

# Expected: prog/xdp id <N> (native mode)
# 预期：prog/xdp id <N>（原生模式）
# If you see xdpgeneric, native mode failed (still works, but slower)
# 如果看到 xdpgeneric，原生模式失败（仍可工作，但较慢）

# List all loaded BPF programs
# 列出所有已加载的 BPF 程序
sudo bpftool prog list | grep -E "xdp|veth"
```

### Step 3.4: Verify BPF Maps / 步骤 3.4：验证 BPF 映射表

```bash
# List maps
# 列出映射表
sudo bpftool map list | grep -E "veth_egress|voq_egress"

# Check voq_egress_devmap is populated
# 检查 voq_egress_devmap 是否已填充
sudo bpftool map dump name voq_egress_devmap

# Expected: entries for each physical interface
# 预期：每个物理接口的条目
# key: <ifindex>  value: { ifindex: <ifindex>, prog_id: <egress_prog_id> }

# Check veth_egress_config_map
# 检查 veth_egress_config_map
sudo bpftool map dump name veth_egress_config_map

# Expected: enabled=1, veth_out_ifindex=<ifindex of veth_voq_out>
# 预期：enabled=1, veth_out_ifindex=<veth_voq_out 的 ifindex>
```

**✅ PASS Criteria / 通过标准:**
- XDP attached to veth_voq_out / XDP 已附加到 veth_voq_out
- voq_egress_devmap contains physical interfaces / voq_egress_devmap 包含物理接口
- veth_egress_config_map shows enabled=1 / veth_egress_config_map 显示 enabled=1

---

## Phase 4: Start VOQd / 阶段 4：启动 VOQd

### Step 4.1: Start VOQd Daemon / 步骤 4.1：启动 VOQd 守护进程

```bash
# Start VOQd in active mode
# 以 active 模式启动 VOQd
sudo ./build/rswitch-voqd \
    -m active \
    -p 2 \
    -P 0x0C \
    -i eth0,eth1 \
    -v

# Parameters:
# 参数：
#   -m active    : Active mode (intercept high-priority traffic)
#                  Active 模式（拦截高优先级流量）
#   -p 2         : Number of ports
#                  端口数量
#   -P 0x0C      : Priority mask (HIGH + CRITICAL)
#                  优先级掩码（HIGH + CRITICAL）
#   -i eth0,eth1 : Interface names
#                  接口名称
#   -v           : Verbose output
#                  详细输出
```

### Step 4.2: Verify VOQd Running / 步骤 4.2：验证 VOQd 运行中

```bash
# Check VOQd process
# 检查 VOQd 进程
ps aux | grep rswitch-voqd

# Check AF_XDP sockets created
# 检查 AF_XDP 套接字是否已创建
sudo ss -f link | grep -i xdp
```

**✅ PASS Criteria / 通过标准:**
- VOQd process running / VOQd 进程运行中
- AF_XDP sockets created for interfaces / 为接口创建了 AF_XDP 套接字

---

## Phase 5: Traffic Test / 阶段 5：流量测试

### Test Setup / 测试设置

```
┌──────────────┐                              ┌──────────────┐
│   Client     │──────── Network ─────────────│   Server     │
│              │                              │  (rSwitch)   │
│  Generate    │        eth0 ◄───────────────►│  eth0        │
│  traffic     │        eth1 ◄───────────────►│  eth1        │
└──────────────┘                              └──────────────┘
```

### Step 5.1: Enable Tracing / 步骤 5.1：启用跟踪

```bash
# On rSwitch server, enable XDP tracepoints
# 在 rSwitch 服务器上，启用 XDP 跟踪点
sudo su -

# Enable redirect tracing
# 启用重定向跟踪
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect/enable
echo 1 > /sys/kernel/debug/tracing/events/xdp/xdp_redirect_err/enable

# Start trace monitoring in another terminal
# 在另一个终端启动跟踪监控
cat /sys/kernel/debug/tracing/trace_pipe | grep -E "xdp|veth"
```

### Step 5.2: Generate High-Priority Traffic / 步骤 5.2：生成高优先级流量

From the client machine, generate traffic that will be classified as high-priority:
从客户端机器，生成将被分类为高优先级的流量：

```bash
# SSH traffic (CRITICAL priority)
# SSH 流量（CRITICAL 优先级）
ssh user@<rswitch_ip>

# ICMP traffic (HIGH priority)
# ICMP 流量（HIGH 优先级）
ping -c 10 <rswitch_ip>

# HTTP traffic (HIGH priority)
# HTTP 流量（HIGH 优先级）
curl http://<rswitch_ip>/
```

### Step 5.3: Monitor Statistics / 步骤 5.3：监控统计信息

```bash
# Check veth egress statistics
# 检查 veth 出口统计
sudo bpftool map dump name veth_egress_stats

# Expected fields:
# 预期字段：
#   rx_packets    : Packets received from veth
#                   从 veth 接收的数据包
#   tx_packets    : Packets redirected to physical NIC
#                   重定向到物理网卡的数据包
#   rx_bytes      : Bytes received
#                   接收的字节数
#   tx_bytes      : Bytes transmitted
#                   发送的字节数
#   errors        : Processing errors
#                   处理错误
#   drops         : Dropped packets
#                   丢弃的数据包

# Check QoS statistics
# 检查 QoS 统计
sudo bpftool map dump name qos_stats_map

# Check egress statistics
# 检查出口统计
sudo bpftool map dump name rs_stats_map
```

### Step 5.4: Verify End-to-End Flow / 步骤 5.4：验证端到端流程

The complete flow should be:
完整流程应为：

1. **Ingress on physical NIC / 物理网卡入口**
   ```
   NIC RX → dispatcher → vlan → qos → afxdp_redirect → xsks_map
   ```

2. **VOQd Processing / VOQd 处理**
   ```
   AF_XDP RX → VOQ enqueue → DRR scheduling → dequeue
   ```

3. **Veth Egress Path / Veth 出口路径**
   ```
   VOQd AF_XDP TX (+ voq_tx_meta) → veth_voq_in → veth_voq_out
   ```

4. **veth_egress_redirect XDP / veth_egress_redirect XDP 程序**
   ```
   Parse meta → Strip header → Restore rs_ctx → devmap redirect
   ```

5. **Physical NIC Egress / 物理网卡出口**
   ```
   devmap egress → egress_qos → egress_vlan → egress_final → TX
   ```

**Verification points / 验证点:**

```bash
# 1. Check packets reached veth_egress
# 1. 检查数据包是否到达 veth_egress
sudo bpftool map dump name veth_egress_stats | grep rx_packets

# 2. Check packets redirected to physical NIC
# 2. 检查数据包是否重定向到物理网卡
sudo bpftool map dump name veth_egress_stats | grep tx_packets

# 3. Check egress processing ran
# 3. 检查出口处理是否运行
sudo bpftool map dump name rs_stats_map | grep egress

# 4. Use tcpdump to verify packets exit physical interface
# 4. 使用 tcpdump 验证数据包是否从物理接口发出
sudo tcpdump -i eth0 -c 10 -n
```

**✅ PASS Criteria / 通过标准:**
- veth_egress_stats shows rx_packets > 0 / veth_egress_stats 显示 rx_packets > 0
- veth_egress_stats shows tx_packets > 0 / veth_egress_stats 显示 tx_packets > 0
- tx_packets ≈ rx_packets (minimal drops) / tx_packets ≈ rx_packets（丢包极少）
- tcpdump shows packets on physical interface / tcpdump 在物理接口显示数据包

---

## Phase 6: VLAN Tagging Verification / 阶段 6：VLAN 标记验证

### Step 6.1: Configure VLAN / 步骤 6.1：配置 VLAN

```bash
# Add VLAN configuration via rswitchctl
# 通过 rswitchctl 添加 VLAN 配置
sudo ./build/rsvlanctl add --vlan 100 --ports eth0,eth1 --tagged

# Or use bpftool directly
# 或直接使用 bpftool
# (depends on your VLAN map structure)
# （取决于您的 VLAN 映射表结构）
```

### Step 6.2: Verify VLAN Tags Applied / 步骤 6.2：验证 VLAN 标记已应用

```bash
# Capture packets on physical interface
# 在物理接口上捕获数据包
sudo tcpdump -i eth0 -e -c 10 -n vlan

# Expected: VLAN tags visible in output
# 预期：输出中可见 VLAN 标记
# Example: 12:34:56:78:9a:bc > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), vlan 100
```

**✅ PASS Criteria / 通过标准:**
- Packets show VLAN tags when captured / 捕获时数据包显示 VLAN 标记
- VLAN ID matches configuration / VLAN ID 与配置匹配

---

## Phase 7: Cleanup / 阶段 7：清理

```bash
# Stop VOQd
# 停止 VOQd
sudo pkill rswitch-voqd

# Unload rSwitch (detach XDP programs)
# 卸载 rSwitch（分离 XDP 程序）
sudo ip link set eth0 xdp off
sudo ip link set eth1 xdp off
sudo ip link set veth_voq_out xdp off

# Delete veth pair
# 删除 veth 对
sudo ./scripts/setup_veth_egress.sh delete

# Verify cleanup
# 验证清理
ip link show veth_voq_in 2>&1 | grep -q "does not exist" && echo "Veth pair removed"
```

---

## Troubleshooting / 故障排除

### Problem: XDP fails to attach to veth_voq_out
### 问题：XDP 无法附加到 veth_voq_out

```bash
# Check kernel support
# 检查内核支持
cat /boot/config-$(uname -r) | grep CONFIG_XDP

# Try generic mode (slower but more compatible)
# 尝试 generic 模式（较慢但兼容性更好）
sudo ip link set veth_voq_out xdpgeneric obj build/bpf/veth_egress.bpf.o sec xdp
```

### Problem: Packets not reaching veth_egress
### 问题：数据包未到达 veth_egress

```bash
# Check VOQd is using veth path
# 检查 VOQd 是否使用 veth 路径
# Look for TX to veth_voq_in in VOQd logs
# 在 VOQd 日志中查找 TX 到 veth_voq_in

# Check veth pair is UP
# 检查 veth 对是否为 UP
ip link show veth_voq_in veth_voq_out

# Check packets are traversing veth
# 检查数据包是否穿过 veth
sudo tcpdump -i veth_voq_in -c 5
sudo tcpdump -i veth_voq_out -c 5
```

### Problem: Packets dropped in veth_egress
### 问题：数据包在 veth_egress 中被丢弃

```bash
# Check stats for drop reason
# 检查统计信息中的丢弃原因
sudo bpftool map dump name veth_egress_stats

# Common causes:
# 常见原因：
# 1. Invalid voq_tx_meta header / 无效的 voq_tx_meta 头部
# 2. devmap entry missing for target interface / 目标接口的 devmap 条目缺失
# 3. rs_ctx_map lookup failure / rs_ctx_map 查找失败

# Check devmap
# 检查 devmap
sudo bpftool map dump name voq_egress_devmap
```

### Problem: Egress processing not running
### 问题：出口处理未运行

```bash
# Verify devmap has egress program fd
# 验证 devmap 是否有出口程序 fd
sudo bpftool map dump name voq_egress_devmap

# Each entry should have prog_id set
# 每个条目应设置 prog_id
# If prog_id is 0, egress program not attached
# 如果 prog_id 为 0，出口程序未附加
```

---

## Summary Checklist / 总结检查清单

| Step | Verification | Expected |
|------|--------------|----------|
| Build | `ls build/bpf/veth_egress.bpf.o` | File exists |
| Veth | `ip link show veth_voq_out` | UP state |
| XDP | `ip link show veth_voq_out \| grep xdp` | prog/xdp attached |
| Maps | `bpftool map dump name voq_egress_devmap` | Contains NICs |
| VOQd | `ps aux \| grep voqd` | Process running |
| Traffic | `bpftool map dump name veth_egress_stats` | rx_packets > 0 |
| Egress | `tcpdump -i eth0` | Packets visible |

| 步骤 | 验证 | 预期 |
|------|------|------|
| 构建 | `ls build/bpf/veth_egress.bpf.o` | 文件存在 |
| Veth | `ip link show veth_voq_out` | UP 状态 |
| XDP | `ip link show veth_voq_out \| grep xdp` | prog/xdp 已附加 |
| 映射表 | `bpftool map dump name voq_egress_devmap` | 包含网卡 |
| VOQd | `ps aux \| grep voqd` | 进程运行中 |
| 流量 | `bpftool map dump name veth_egress_stats` | rx_packets > 0 |
| 出口 | `tcpdump -i eth0` | 数据包可见 |
