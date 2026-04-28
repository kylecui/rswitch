# 物理机 Native XDP 部署与运维手册

> 适用对象：首次在实体设备上部署 rSwitch 的开发、测试、运维人员。
>
> 强烈建议先读本文，再执行 `systemctl start rswitch`。本文覆盖了这次在 `10.174.1.191` 上实际验证过的关键步骤与坑点。

## 1. 这份文档解决什么问题

本文针对的是这样一类部署：

- 目标是**物理机**，不是普通虚拟机实验环境
- 要求所有前面板口都进入交换面
- 不再预留单独的 management 物理口
- 管理面通过 `mgmt-br <-> mgmt0` veth + `rswitch-mgmt` namespace 提供
- 数据面坚持使用 **native XDP**
- 管理 IP 通过 **DHCP** 自动获取，入口通过 **mDNS / SSH / Web Portal** 暴露

如果你部署的是这类场景，本文不是可选阅读，而是必读材料。

## 2. 最终目标状态

以 `10.174.1.191` 为例，期望状态如下：

- 物理口 `enp2s0` ~ `enp5s0` 全部作为交换端口
- `rswitch.service` 启动后，原本绑在前面板口上的宿主机 IP 会失效，这是**预期行为**
- `mgmt0` 位于 `rswitch-mgmt` namespace 内，通过 DHCP 获得管理 IP
- 管理能力从 `mgmt0` 暴露：
  - SSH
  - Web Portal `:8080`
  - `rswitch.local` mDNS 名称
- killswitch watchdog 正常运行

## 3. 前期准备

### 3.1 系统与内核要求

- Linux kernel 5.8+
- 建议 Ubuntu 22.04+/Debian 12+
- 要有 BTF：

```bash
uname -r
ls /sys/kernel/btf/vmlinux
```

### 3.2 必需软件包

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    clang \
    llvm \
    pkg-config \
    libxdp-dev \
    libbpf-dev \
    libsystemd-dev \
    libssl-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    ethtool \
    iproute2 \
    dhcpcd
```

必须特别注意：

- `libsystemd-dev` 缺失会导致相关构建或 systemd 集成不完整
- `dhcpcd` 缺失时，`mgmt0` 不会自动拿到 DHCP 地址
- `ethtool` 缺失时，无法完成本文要求的 offload 检查

### 3.3 网络与现场条件

部署前要先确认：

- DHCP server 在交换网络里真实可达
- 测试人员知道：启动后原本的宿主机 SSH 可能会立即断开
- 最好有**隐藏管理口 / 控制台 / 带外入口**，避免锁死
- 最好准备同一二层网段的辅助测试机，便于验证 killswitch、mDNS、DHCP

## 4. 编译与安装

### 4.1 拉代码与编译

```bash
git clone --recurse-submodules <repo-url>
cd rswitch

make vmlinux
make
```

### 4.2 安装到目标目录

```bash
sudo make install
```

默认安装到：

- `/opt/rswitch/build/`
- `/opt/rswitch/etc/`
- `/opt/rswitch/scripts/`

## 5. 关键部署模型

### 5.1 管理面拓扑

```text
物理交换口(enp2s0~enp5s0)
        |
        v
  XDP ingress/egress pipeline
        |
        +--> mgmt-br (default ns)
                 |
                 | veth pair
                 |
              mgmt0 (rswitch-mgmt ns)
                 |
                 +--> dhcpcd
                 +--> sshd
                 +--> rswitch-mgmtd (:8080)
                 +--> mDNS (rswitch.local)
```

这个模型的关键点：

- `mgmt-br` 不是旁路口，而是**真正加入交换面的逻辑端口**
- `mgmt0` 不是宿主机接口，而是 namespace 内的管理接口
- native XDP 下，管理面能否工作，不取决于“能不能收到包”这一个点，而是取决于**整条收发链路**是否完整

### 5.2 为什么启动后原宿主机 IP 会失联

因为前面板物理口已经交给 rSwitch 数据面了。宿主机原来的 `10.174.1.191` 这类地址如果还绑在 `enp2s0` 上，启动后就不应再作为你的主运维入口。

正确入口应该切换到：

- `mgmt0` 的 DHCP 地址
- `rswitch.local`
- 或者显式配置的静态管理地址

## 6. systemd 服务要求

以下服务必须存在，并且建议 `enable`：

- `rswitch.service`
- `rswitch-mgmtd.service`
- `rswitch-mgmt-sshd.service`
- `rswitch-killswitch-watchdog.service`

建议检查：

```bash
sudo systemctl is-enabled rswitch rswitch-mgmtd rswitch-mgmt-sshd rswitch-killswitch-watchdog
```

推荐同时让 `rswitch.service` 显式 `Wants=` 这些依赖服务，避免只启动主服务却忘了拉起管理面。

```ini
Wants=network-online.target rswitch-mgmtd.service rswitch-mgmt-sshd.service rswitch-killswitch-watchdog.service
```

## 7. 启动前必须确认的事项

### 7.1 不要再给前面板口保留宿主机管理地址

如果目标是“所有端口都进入交换面”，那就不要再把 `enp2s0` 当专用管理口保留。

### 7.2 killswitch key 文件格式

watchdog 当前读取的是**两行纯 hex**：

```text
<stop_key_hex>
<reboot_key_hex>
```

不是：

```text
stop_key=...
reboot_key=...
port=19999
```

后者会导致 watchdog 起不来。

### 7.3 DHCP 客户端必须可用

当前自动启动逻辑会尝试在 `rswitch-mgmt` namespace 内执行：

```bash
dhcpcd -b --noipv4ll mgmt0
```

如果没有 `dhcpcd`，`mgmt0` 不会自动拿到地址。

## 8. 启动流程

```bash
sudo systemctl daemon-reload
sudo systemctl enable rswitch rswitch-mgmtd rswitch-mgmt-sshd rswitch-killswitch-watchdog
sudo systemctl start rswitch
```

启动后不要继续盯着原 IP，要立即转向检查 `mgmt0`：

```bash
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
sudo ip netns exec rswitch-mgmt ip route
sudo ip netns exec rswitch-mgmt ss -tlnp
```

## 9. 启动后如何验证

### 9.1 检查 mgmt0 是否拿到 DHCP

```bash
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
```

预期看到：

- `state UP`
- IPv4 DHCP 地址
- `xdp/id:...`

### 9.2 检查 SSH / Web / mDNS

```bash
ssh <mgmt-ip>
curl http://<mgmt-ip>:8080/
ping rswitch.local
```

### 9.3 检查 XDP_PASS 是否已附着

```bash
sudo bpftool prog list | grep xdp_pass
sudo ip netns exec rswitch-mgmt ip -d link show mgmt0
```

### 9.4 检查 checksum offload 是否真的关闭

```bash
sudo ip netns exec rswitch-mgmt ethtool -k mgmt0 | grep -E 'tx-checksumming|scatter|tcp-seg'
sudo ethtool -k mgmt-br | grep -E 'tx-checksumming|scatter|tcp-seg'
```

预期：

- `tx-checksumming: off`
- `scatter-gather: off`
- `tcp-segmentation-offload: off`

这不是“优化项”，而是**必须项**。

## 10. 这次验证中确认过的必需操作

### 10.1 必须给 mgmt0 挂一个最小 XDP_PASS 程序

原因：native XDP 下，devmap redirect 到 veth peer 时，`mgmt0` 如果没有激活 NAPI，会出现“能创建链路，但完全收不到包”的现象。

### 10.2 必须关闭 mgmt0 / mgmt-br 的 TX checksum / SG / TSO offload

原因：XDP redirect 绕开了你以为会帮你补 checksum 的常规发包路径。典型症状是 SYN-ACK 发出去了，但 checksum 错，对端不 ACK。

### 10.3 必须显式启动 DHCP 客户端

仅仅起 `rswitch-mgmtd` 并不会天然让 `mgmt0` 自动拿到地址。必须确认 namespace 内真实启动了 `dhcpcd`。

## 11. 常用排错命令

```bash
sudo ip netns exec rswitch-mgmt ip addr
sudo ip netns exec rswitch-mgmt ip route
sudo ip netns exec rswitch-mgmt ip neigh
sudo ip netns exec rswitch-mgmt tcpdump -ni mgmt0
sudo ip netns exec rswitch-mgmt tcpdump -ni mgmt0 tcp port 22
sudo journalctl -u rswitch -n 100 --no-pager
sudo journalctl -u rswitch-mgmtd -n 100 --no-pager
sudo journalctl -u rswitch-mgmt-sshd -n 100 --no-pager
sudo journalctl -u rswitch-killswitch-watchdog -n 100 --no-pager
```

## 12. 常见故障与处理

### 故障 A：启动后原 IP 消失，SSH 断开

这通常不是 bug，而是设计结果。不要再等原 IP 恢复，直接转向 `mgmt0` 的 DHCP 地址。

### 故障 B：mgmt0 能看到广播包，但拿不到 DHCP

优先排查：

1. `dhcpcd` 是否真的启动
2. `mgmt0` 是否已在 namespace 内 `UP`
3. DHCP reply 是否真的能回来
4. `mgmt-br` / `mgmt0` 的 XDP 与 offload 状态是否正确

### 故障 C：mgmt0 能收到 SSH SYN，也能发 SYN-ACK，但连接失败

优先排查 TX checksum offload。这个坑已经在 `191` 上实锤过。

### 故障 D：watchdog 不起

先看 `/etc/rswitch/killswitch.key` 格式是否仍是 `key=value` 形式。

### 故障 E：服务存在但没有自动拉起

检查两件事：

```bash
sudo systemctl is-enabled rswitch-mgmtd rswitch-mgmt-sshd rswitch-killswitch-watchdog
sudo systemctl cat rswitch.service
```

## 13. 人工兜底命令

### 13.1 手工申请 DHCP

```bash
sudo ip netns exec rswitch-mgmt dhcpcd -b mgmt0
```

### 13.2 手工起 namespace 内 sshd

```bash
sudo mkdir -p /run/sshd   # 必须先确保存在，否则 sshd 报 privilege separation 错误
sudo ip netns exec rswitch-mgmt /usr/sbin/sshd
```

> **注意**：`/run/sshd` 是 OpenSSH privilege separation 所需目录。`rswitch-mgmt-sshd.service` 已通过 `ExecStartPre=/bin/mkdir -p /run/sshd` 自动处理，但手工启动时需要自行创建。详见[排错复盘 §7A](../development/Native_XDP_Physical_Debugging_Postmortem.md#7a-补充sshd-报-missing-privilege-separation-directory-runsshd)。

### 13.3 手工给静态 IP（只用于临时抢救）

```bash
sudo ip netns exec rswitch-mgmt ip addr add 10.174.1.200/24 dev mgmt0
sudo ip netns exec rswitch-mgmt ip route add default via 10.174.1.254
```

## 14. 建议的现场发布流程

1. 确认依赖齐全，尤其是 `libsystemd-dev`、`dhcpcd`、`ethtool`
2. 确认 profile 与目标口名一致
3. 确认 killswitch key 文件格式正确
4. 确认相关 systemd units 已 `enable`
5. 准备控制台或带外入口
6. `sudo systemctl start rswitch`
7. 立即从控制台检查 `mgmt0`
8. 通过 DHCP 地址验证 SSH / Web / mDNS
9. 验证 killswitch
10. 最后再移除人工临时配置

## 15. 本次物理机验证结论

这次在 `10.174.1.191` 上已经验证：

- native XDP + 全部物理口接管是可行的
- 管理面不需要额外预留单独 management 口
- `mgmt0` 可以通过 DHCP 自动获取地址
- `rswitch.local`、SSH、Web Portal 都可以工作
- 但前提是必须同时满足：
  - `mgmt0` 挂 `XDP_PASS`
  - `mgmt0/mgmt-br` 关闭 TX checksum / SG / TSO offload
  - namespace 内真实启动 DHCP client
  - systemd 依赖服务 wiring 正确

少任何一个条件，现场体验都会非常差，而且容易误判成“转发表错误”或“native XDP 不可用”。
