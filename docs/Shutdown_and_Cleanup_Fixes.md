# Shutdown and Cleanup Fixes - Critical Improvements

## 问题诊断

### 症状 1: `netdev watchdog: NETDEV WATCHDOG: transmit queue 0 timed out`

**根本原因**：
- XDP 程序附加到网卡后，如果在 shutdown 过程中 BPF maps 先于 XDP 程序被清理，XDP 程序会访问失效的 map
- 这会导致 XDP 程序崩溃或返回错误，进而阻塞 TX 队列
- 内核的 netdev watchdog 检测到 TX 队列长时间无响应，触发告警

**错误的清理顺序**：
```
1. Detach XDP       ← XDP 还在访问 maps
2. Close maps       ← maps 被清理，XDP 访问失效
3. Close objects    ← 太晚了，TX 队列已经阻塞
```

---

### 症状 2: `shutdown[1] waiting for process (rswitch_loader)`

**根本原因**：
1. **信号响应慢**：主循环使用 `sleep(1)`，信号到达时可能需要等待最多 1 秒
2. **VOQd 关闭超时**：等待 VOQd graceful shutdown 的时间是 5 秒
3. **累积延迟**：总共可能需要 6-10 秒才能完成 cleanup
4. **systemd 默认超时**：systemd 的 `TimeoutStopSec` 通常是 90 秒，但某些发行版设置为 30 秒

**时间线分析**：
```
T+0s:   收到 SIGTERM
T+1s:   主循环从 sleep(1) 返回
T+1s:   开始 cleanup
T+1s:   发送 SIGTERM 给 VOQd
T+6s:   VOQd 超时，发送 SIGKILL
T+6s:   Detach XDP (如果 TX 队列阻塞，这里会卡很久)
T+??:   系统 watchdog 触发，强制 kill
```

---

## 解决方案

### 修复 1: 改进信号处理

**变更**：
- 添加 `shutdown_in_progress` 标志，防止重复信号干扰
- 添加 SIGHUP 处理（系统重启时可能发送）
- 打印信号名称，方便调试

```c
static volatile int keep_running = 1;
static volatile int shutdown_in_progress = 0;

static void sig_handler(int sig)
{
    if (shutdown_in_progress) {
        return;  /* 忽略重复信号 */
    }
    
    shutdown_in_progress = 1;
    keep_running = 0;
    
    const char *sig_name = (sig == SIGINT) ? "SIGINT" : 
                           (sig == SIGTERM) ? "SIGTERM" : 
                           (sig == SIGHUP) ? "SIGHUP" : "Unknown";
    fprintf(stderr, "\n\nReceived %s, initiating shutdown...\n", sig_name);
}
```

**注册信号**：
```c
signal(SIGINT, sig_handler);
signal(SIGTERM, sig_handler);
signal(SIGHUP, sig_handler);  /* 新增：处理系统重启 */
```

---

### 修复 2: 优化主循环响应速度

**变更**：
- 将 `sleep(1)` 改为 `usleep(100000)` (100ms)
- 响应速度从最坏 1 秒降低到 100ms（**10倍提升**）
- 添加周期性健康检查，监控 VOQd 状态

```c
/* 旧代码 - 响应慢 */
while (keep_running) {
    sleep(1);  /* 最坏情况延迟 1 秒 */
}

/* 新代码 - 响应快 */
int loop_count = 0;
while (keep_running) {
    usleep(100000);  /* 100ms - 快速响应 */
    
    /* 每 10 秒检查一次 VOQd 健康 */
    if (++loop_count >= 100) {
        loop_count = 0;
        
        if (ctx.voqd_enabled && ctx.voqd_pid > 0) {
            int status;
            if (waitpid(ctx.voqd_pid, &status, WNOHANG) != 0) {
                fprintf(stderr, "Warning: VOQd died unexpectedly\n");
                ctx.voqd_pid = 0;
                ctx.voqd_enabled = 0;
            }
        }
    }
}
```

**时间节省**：
- 旧：信号响应最多 1 秒 + VOQd 关闭 5 秒 = **6 秒**
- 新：信号响应最多 0.1 秒 + VOQd 关闭 2 秒 = **2.1 秒** (**3倍加速**)

---

### 修复 3: 修正清理顺序（最关键）

**原理**：TX 队列阻塞是因为 XDP 程序在 maps 失效后仍在运行。

**正确的清理顺序**：

```c
/* Step 0: 停止 VOQd（如果在运行）*/
stop_voqd();

/* Step 1: 刷新 TX 队列 - 防止 watchdog 超时 */
for (i = 0; i < num_interfaces; i++) {
    /* 将接口设置为 DOWN，强制刷新队列 */
    system("ip link set <iface> down");
}
usleep(100000);  /* 等待队列刷新 */

/* Step 2: Detach XDP - 此时 maps 仍然有效 */
detach_xdp();

/* Step 3: 短暂延迟 - 确保 XDP 完全分离 */
usleep(50000);

/* Step 4: 关闭 maps */
close_map_fds();

/* Step 5: 关闭 BPF objects */
close_bpf_objects();

/* Step 6: 清理 pinned maps */
unpin_maps();
```

**关键改进**：
1. ✅ **先刷新队列**：避免 watchdog 超时
2. ✅ **Detach 时 maps 有效**：XDP 可以正常清理状态
3. ✅ **延迟确保分离**：给内核时间完全卸载 XDP
4. ✅ **恢复接口状态**：Detach 后将接口设置回 UP

---

### 修复 4: 改进 XDP Detach 逻辑

**变更**：
- 添加强制 detach 失败重试（使用 `ip link set xdp off`）
- Detach 后恢复接口到 UP 状态
- 改进错误提示

```c
static void detach_xdp(struct loader_ctx *ctx)
{
    for (i = 0; i < ctx->num_interfaces; i++) {
        __u32 ifindex = ctx->interfaces[i];
        char ifname[IF_NAMESIZE];
        char cmd[256];
        
        if_indextoname(ifindex, ifname);
        
        /* 尝试正常 detach */
        if (bpf_xdp_detach(ifindex, ctx->xdp_flags, NULL) < 0) {
            fprintf(stderr, "  Warning: Failed to detach from %s: %s\n",
                    ifname, strerror(errno));
            
            /* Fallback: 使用 ip 命令强制 detach */
            snprintf(cmd, sizeof(cmd), "ip link set %s xdp off 2>/dev/null", ifname);
            if (system(cmd) == 0) {
                printf("  Force detached from %s using ip command\n", ifname);
            }
        } else {
            printf("  ✓ Detached from %s (ifindex=%u)\n", ifname, ifindex);
        }
        
        /* 恢复接口到 UP 状态 */
        snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", ifname);
        system(cmd);
        printf("  ✓ Restored %s to UP state\n", ifname);
    }
}
```

---

### 修复 5: 减少 VOQd 关闭超时

**变更**：
- 将 graceful shutdown 超时从 5 秒减少到 2 秒
- 使用 `usleep(100ms)` 代替 `sleep(1s)` 进行更精细的控制

```c
/* 旧代码 */
int timeout = 5;
while (timeout > 0) {
    if (waitpid(ctx->voqd_pid, &status, WNOHANG) != 0) {
        break;
    }
    sleep(1);     /* 1 秒粒度 */
    timeout--;
}

/* 新代码 */
int timeout = 20;  /* 20 * 100ms = 2 秒 */
while (timeout > 0) {
    if (waitpid(ctx->voqd_pid, &status, WNOHANG) != 0) {
        break;
    }
    usleep(100000);  /* 100ms 粒度 - 更精确 */
    timeout--;
}
```

**优势**：
- 如果 VOQd 快速响应（例如 500ms），新代码会立即检测到
- 旧代码即使 VOQd 已经退出，仍然会等满 1 秒才检查

---

## 性能对比

| 阶段 | 旧实现 | 新实现 | 改进 |
|------|--------|--------|------|
| 信号响应 | 最多 1s | 最多 0.1s | **10x** |
| VOQd 关闭 | 5s 固定 | 0.5-2s 动态 | **2.5-10x** |
| XDP Detach | 可能卡死 | 强制 flush + 重试 | **可靠性** |
| 总清理时间 | 6-10s | 1-3s | **3-5x** |

---

## 测试验证

### 测试 1: 正常关闭

```bash
# 启动 loader
sudo ./build/rswitch_loader --profile etc/profiles/l3-qos-voqd-test.yaml \
                             --ifaces enp3s0,enp4s0,enp5s0

# 等待几秒钟
sleep 5

# 发送 SIGTERM（模拟 systemd 关闭）
sudo killall -TERM rswitch_loader

# 观察输出 - 应该在 2-3 秒内完成清理
```

**预期输出**：
```
Received SIGTERM, initiating shutdown...

========== Cleanup Started ==========

Stopping VOQd (PID: 12345)...
  ✓ VOQd stopped gracefully

Flushing TX queues...
  Flushed enp3s0
  Flushed enp4s0
  Flushed enp5s0

Detaching XDP programs:
  ✓ Detached from enp3s0 (ifindex=2)
  ✓ Restored enp3s0 to UP state
  ✓ Detached from enp4s0 (ifindex=3)
  ✓ Restored enp4s0 to UP state
  ✓ Detached from enp5s0 (ifindex=4)
  ✓ Restored enp5s0 to UP state

Closing map file descriptors:
  ...

========== Cleanup Complete ==========
```

---

### 测试 2: 系统重启时的行为

```bash
# 启动 loader
sudo ./build/rswitch_loader --profile etc/profiles/l3-qos-voqd-test.yaml \
                             --ifaces enp3s0,enp4s0,enp5s0 &

# 触发系统重启
sudo reboot

# 观察系统日志
journalctl -u rswitch-loader -f
```

**预期**：
- ✅ 不应该出现 "waiting for process" 告警
- ✅ 不应该出现 "transmit queue timed out"
- ✅ 关闭应该在 3 秒内完成

---

### 测试 3: VOQd 崩溃情况

```bash
# 启动 loader
sudo ./build/rswitch_loader --profile etc/profiles/l3-qos-voqd-test.yaml \
                             --ifaces enp3s0,enp4s0,enp5s0

# 在另一个终端，强制杀死 VOQd
sudo killall -9 rswitch-voqd

# 观察 loader 输出 - 应该在 10 秒内检测到
```

**预期输出**（10 秒后）：
```
Warning: VOQd process died unexpectedly
```

---

## 故障排查

### 问题 1: 仍然出现 "transmit queue timed out"

**可能原因**：
- NIC 驱动不支持 XDP 的快速 detach
- 仍然有未发送的包在队列中

**解决方案**：
```bash
# 增加队列刷新延迟
# 在代码中修改：
usleep(100000);  → usleep(200000);  /* 从 100ms 增加到 200ms */
```

---

### 问题 2: XDP Detach 失败

**症状**：
```
Warning: Failed to detach from enp3s0: Device or resource busy
```

**解决方案**：
```bash
# 手动清理 XDP
sudo ip link set enp3s0 xdpgeneric off
sudo ip link set enp3s0 xdpdrv off
sudo ip link set enp3s0 xdpoffload off

# 或者强制清理所有
for iface in enp3s0 enp4s0 enp5s0; do
    sudo ip link set $iface xdp off 2>/dev/null
done
```

---

### 问题 3: VOQd 不响应 SIGTERM

**症状**：
```
VOQd did not stop gracefully, forcing...
✓ VOQd killed
```

**可能原因**：
- VOQd 正在处理大量包，无法及时响应信号
- VOQd 的信号处理有 bug

**解决方案**：
1. 检查 VOQd 代码的信号处理逻辑
2. 如果经常需要 SIGKILL，考虑缩短超时到 1 秒

---

## systemd 集成建议

如果将 rSwitch 作为 systemd 服务运行，建议配置：

```ini
[Unit]
Description=rSwitch Reconfigurable Switch
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rswitch_loader \
          --profile /etc/rswitch/l3-qos-voqd-test.yaml \
          --ifaces enp3s0,enp4s0,enp5s0
ExecStop=/bin/kill -TERM $MAINPID
TimeoutStopSec=5s        # 5 秒超时（新代码 2-3 秒足够）
KillMode=mixed           # SIGTERM → 进程组，超时后 SIGKILL 主进程
KillSignal=SIGTERM       # 默认信号
SendSIGKILL=yes          # 超时后发送 SIGKILL
Restart=on-failure
RestartSec=5s

# 性能优化
Nice=-10                 # 高优先级
LimitMEMLOCK=infinity   # BPF 需要
LimitNOFILE=65536       # 大量 FD

[Install]
WantedBy=multi-user.target
```

**关键配置**：
- `TimeoutStopSec=5s`：新代码 2-3 秒可以完成，5 秒足够安全余量
- `KillMode=mixed`：先发 SIGTERM 给进程组（包括 VOQd），超时后强杀主进程
- `SendSIGKILL=yes`：确保超时后一定清理干净

---

## 总结

### 关键改进

1. ✅ **信号响应加速 10 倍**（1s → 0.1s）
2. ✅ **清理时间减少 3-5 倍**（6-10s → 2-3s）
3. ✅ **修复 TX 队列阻塞**（正确的清理顺序）
4. ✅ **添加强制 detach 重试**（提高可靠性）
5. ✅ **周期性健康检查**（及时发现 VOQd 崩溃）

### 最佳实践

1. **启动时**：确保所有接口在 UP 状态
2. **运行时**：监控 VOQd 健康状态
3. **关闭时**：先刷新队列，再 detach XDP，最后关闭 maps
4. **失败时**：使用 `ip link set xdp off` 强制清理

### 代码位置

所有修改在：
- `rswitch/user/loader/rswitch_loader.c`
  - Line 155-176: 改进的信号处理
  - Line 1347-1381: 改进的 XDP detach
  - Line 1458-1544: 修正的 cleanup 顺序
  - Line 1752-1756: 添加 SIGHUP 处理
  - Line 1798-1824: 优化的主循环
  - Line 1469-1492: 减少 VOQd 关闭超时
