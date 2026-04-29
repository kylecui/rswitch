# Native XDP 物理机场景排错复盘

> 适用对象：后续维护者、二次开发者、平台研发、现场排障人员。
>
> 这不是一份抽象设计文档，而是一份基于真实问题链路的复盘材料。建议在修改 management、loader、mgmtd、killswitch、systemd wiring 之前先读完。

## 1. 这份复盘记录什么

这次问题不是一个单点 bug，而是一串**连续误判风险很高**的系统性问题：

- 虚拟机可用，不代表物理机 native XDP 可用
- 能收包，不代表能完成回复链路
- management namespace 设计正确，不代表 systemd wiring 正确
- SSH 断开，不代表只有一个根因
- DHCP 不通、SSH 不通、killswitch 不通，可能分别来自完全不同层次

本文按时间线梳理每个关键判断、症状、根因与最后修复。

## 2. 场景背景

目标设备是 `10.174.1.191`。

目标要求：

- 全部物理口进入交换面
- 不再预留额外 management 物理口
- 管理入口通过 `mgmt-br <-> mgmt0` + namespace 提供
- 必须使用 **native XDP**，不能退回 `XDP_FLAGS_SKB_MODE`

同时，我们还有一个对照环境：`10.174.254.134`。

它的价值不在于“直接照搬”，而在于帮助我们识别：

- 哪些行为是架构正确性
- 哪些行为只是 `xdpgeneric` 下“碰巧能工作”

## 3. 第一阶段：错误地把“134 能跑”当成“191 也应自然能跑”

### 3.1 初始直觉

一开始容易产生的想法是：

- `134` 上管理面能工作
- `191` 只是设备不同
- 多半是 profile、服务、接口名之类的小问题

这个判断后来证明不够。

### 3.2 真正差异

`134` 与 `191` 的核心差异不是“机器不同”，而是：

- `134` 在验证阶段大量依赖了 `xdpgeneric` 行为
- `191` 的目标是**纯 native XDP**

这会直接影响：

- veth devmap redirect 行为
- checksum/offload 行为
- 管理面回包路径

## 4. 第二阶段：发现 mgmt0 完全不收包

### 4.1 症状

在 `191` 上，管理面起不来，`mgmt0` 看不到应该有的 DHCP/管理流量。

### 4.2 容易误判的方向

这时最容易怀疑的是：

- devmap 没写对
- VLAN membership 错了
- `mgmt-br` 没加进端口配置
- `BPF_F_BROADCAST` 不工作

这些都值得检查，但不是最终根因。

### 4.3 真根因：veth peer 没有 NAPI

最终确认的根因是：

- native XDP 场景下，devmap redirect 到 veth peer 时
- `mgmt0` 如果没有激活 NAPI
- `veth_xdp_xmit()` 会静默丢包

这就是为什么：

- `134` 可以“看起来没事”
- `191` 却完全不通

### 4.4 修复

在 `setup_mgmt_veth()` 里给 `mgmt0` 挂一个最小 `XDP_PASS` 程序。

### 4.5 经验

以后只要遇到 native XDP + devmap redirect + veth peer 完全不收包，就不要先在 VLAN / MAC learning 上绕圈，先检查接收侧是否真的满足内核路径要求。

## 5. 第三阶段：mgmt0 开始收包，但 DHCP 仍然不起

### 5.1 症状

有了 `XDP_PASS` 之后，`mgmt0` 已经能看到 ARP broadcast、UDP multicast 等流量，但仍然没有 DHCP 地址。

### 5.2 关键判断

这说明：

- 数据面 ingress 到 `mgmt0` 基本通了
- 问题不再是“完全收不到包”
- 问题更可能在**管理进程编排**上

### 5.3 真根因：没有自动启动 DHCP client

原来的 `rswitch-mgmtd-start.sh` 只是等 namespace、起 `rswitch-mgmtd`，但没有负责启动 `dhcpcd`。

### 5.4 修复

在 `rswitch-mgmtd-start.sh` 中显式加入：

```bash
ip netns exec "$NS_NAME" dhcpcd -b --noipv4ll mgmt0
```

### 5.5 经验

“服务拓扑正确”和“进程实际被拉起”是两回事。

## 6. 第四阶段：DHCP 与手工静态地址都可见，但 SSH 仍连不上

### 6.1 症状

- `mgmt0` 能拿到 IP
- 或者人工配置静态 IP 后可以被 ping 到
- 但是 SSH 连接一直失败

### 6.2 更进一步的抓包观察

在 `mgmt0` 抓包发现：

- 能看到对端发来的 TCP SYN
- 也能看到本机回 SYN-ACK
- 但三次握手始终完不成

### 6.3 pcap 结论

对 `tmp/221.pcapng` 的分析显示：

- `10.174.1.248 -> 10.174.1.228` 的 SYN-ACK 包 checksum 错误
- 错误不是随机的，而是典型的“checksum 留给 offload 但最终没人替你算完”

### 6.4 真根因：veth 上的 TX checksum / SG / TSO offload

根因不是 SSH，也不是 namespace，也不是路由，而是：

- 内核发包时认为后续 offload 会帮它补 checksum
- 但这条回复链路通过 XDP redirect 出去
- 不再经过标准发包路径

### 6.5 修复

在 `mgmt0` 和 `mgmt-br` 两端关闭：

- `tx-checksumming`
- `scatter-gather`
- `tcp-segmentation-offload`

### 6.6 经验

以后只要看到 SYN 能到、SYN-ACK 也能看到、连接却起不来，第一怀疑项就该是 offload，而不是 ACL 或会话状态。

## 7. 第五阶段：服务存在，但没有自动拉起

### 7.1 症状

即使代码已经修好了，如果 `rswitch-mgmtd`、`rswitch-mgmt-sshd`、`rswitch-killswitch-watchdog` 没有被 systemd 正确拉起，现场仍然表现为：

- 没 DHCP
- 没 SSH
- 没 killswitch

### 7.2 真根因

不是“服务文件不存在”，而是：

- 服务没有 `enable`
- `rswitch.service` 也没有显式 `Wants=` 它们

### 7.3 修复

- 对依赖服务执行 `systemctl enable`
- 给 `rswitch.service` 加上：

```ini
Wants=network-online.target rswitch-mgmtd.service rswitch-mgmt-sshd.service rswitch-killswitch-watchdog.service
```

### 7.4 经验

以后看到“主服务起来了，但辅助能力都没起来”，先查 systemd wiring，不要一上来就怀疑代码逻辑。

## 7A. 补充：sshd 报 "Missing privilege separation directory: /run/sshd"

### 7A.1 症状

`rswitch-mgmt-sshd.service` 启动失败或 `ip netns exec rswitch-mgmt /usr/sbin/sshd` 直接报错退出：

```
Missing privilege separation directory: /run/sshd
```

### 7A.2 真根因

OpenSSH 需要 `/run/sshd` 目录做 privilege separation。宿主机的 sshd 服务通常会自动创建它，但以下场景中该目录可能不存在：

- 宿主机 sshd 未启动过（例如 rswitch 启动太早，或 sshd 被 disable 了）
- `/run` 是 tmpfs，重启后丢失
- systemd 的 RuntimeDirectory 只给宿主 sshd 创建，namespace 内的 sshd 实例不受其管理

### 7A.3 修复

在 `rswitch-mgmt-sshd.service` 的 `ExecStartPre` 中提前创建：

```ini
ExecStartPre=/bin/mkdir -p /run/sshd
```

这一行必须排在 namespace 等待逻辑之前。当前 service 模板（`etc/systemd/rswitch-mgmt-sshd.service`）已包含此修复。

### 7A.4 经验

namespace 内的 sshd 共享宿主机 `/run`，但不共享宿主机 sshd 的 systemd RuntimeDirectory 保障。任何在 namespace 中独立启动的 daemon，都需要自行确保其运行时目录存在。

## 8. 第六阶段：killswitch watchdog 一直重启

### 8.1 症状

`rswitch-killswitch-watchdog.service` 起不来，不断 auto-restart。

### 8.2 真根因

`/etc/rswitch/killswitch.key` 文件格式与 watchdog 实现不一致。

watchdog 期望的是：

```text
<stop-key-hex>
<reboot-key-hex>
```

而不是：

```text
stop_key=...
reboot_key=...
port=19999
```

### 8.3 修复

改回两行纯 hex，重置 systemd failure counter，再重启服务。

## 9. 为什么 `XDP_FLAGS_SKB_MODE` 在实验中曾经“看起来更好用”

因为它走的是更宽松、更接近普通内核网络栈的路径。它曾经帮助暴露问题，但不能作为最终交付方案，因为它会掩盖 native XDP 的真实约束。

## 10. 本次排错中最重要的验证方法

关键分层方法：

1. `mgmt0` 是否收包
2. DHCP client 是否真实启动
3. `mgmt0` 是否有 IP
4. SSH SYN 是否能到
5. SYN-ACK 是否能回
6. SYN-ACK checksum 是否正确
7. 服务是否真的被 systemd 拉起

## 11. 给后续开发者的硬性建议

### 11.1 修改 management 代码前先问自己

- 这是在修 ingress、egress、还是 service wiring？
- 是虚拟机行为，还是物理机 native XDP 行为？
- 是否会影响 namespace 内 DHCP / SSH / mDNS / Web 同时工作？

### 11.2 每次改动后至少验证这几个点

```bash
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
sudo ip netns exec rswitch-mgmt tcpdump -ni mgmt0
sudo ip netns exec rswitch-mgmt ethtool -k mgmt0
sudo systemctl status rswitch-mgmtd rswitch-mgmt-sshd rswitch-killswitch-watchdog
```

### 11.3 不要再硬编码接口名

这次已经确认，硬编码 probe port 行为不可接受。后续任何管理面探测逻辑都必须基于动态发现，而不是把 `ens34`、`enp2s0` 一类名字写死。

### 11.4 不要再把 native XDP 问题用 generic mode 掩盖掉

generic mode 只能帮助定位问题，不能充当最终验收结论。

## 12. 本次排错最终收敛到的修复集合

最终要让 `191` 正常工作的，不是一个 patch，而是一组修复：

1. `mgmt0` 挂 `XDP_PASS`
2. `mgmt0/mgmt-br` 关闭 TX checksum / SG / TSO offload
3. `rswitch-mgmtd-start.sh` 自动启动 `dhcpcd`
4. `rswitch.service` 通过 `Wants=` 拉起管理相关服务
5. 管理相关服务本身 `enable`
6. killswitch key 文件格式修正
7. mDNS 广播补齐
8. probe port 动态发现

## 13. 最终结论

这次最重要的结论不是“191 通了”，而是：

- rSwitch 的 management namespace 方案在物理机 native XDP 上是可行的
- 但它高度依赖多个跨层条件同时成立
- 这些条件横跨：
  - 内核行为
  - XDP redirect 语义
  - veth/NAPI
  - checksum offload
  - DHCP client 进程
  - systemd wiring
  - 配置文件格式

后续任何二次开发如果只盯着其中一层，而忽略整条链路，就很容易把问题重新引入。
