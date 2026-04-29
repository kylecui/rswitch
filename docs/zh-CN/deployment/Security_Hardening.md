# 安全加固指南rSwitch生产部署的安全加固参考。覆盖操作系统层、应用层和BPF专项安全措施。

## 概述rSwitch需要root权限加载XDP/BPF程序并访问原始网络接口。本指南说明在保持完整功能的前提下如何缩小攻击面。

### 安全审计状态

[安全审计](../../SECURITY_AUDIT.md) 中的全部20个发现已修复，包括：

- **C-1**: 通过 `system()`/`popen()` 的命令注入 → 替换为 `fork()`+`execvp()`
- **C-2**: 明文凭据 → SHA-256散列密码 + `constant_time_compare()`
- **C-3**: 认证端点的CORS通配符 → 可配置的来源限制

## 操作系统加固

### 内核配置

```bash
# 推荐sysctl设置cat >> /etc/sysctl.d/99-rswitch.conf <<EOF
# 禁用内核IP转发（rSwitch在XDP中处理转发）
net.ipv4.ip_forward = 0

# BPF加固kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
EOF

sudo sysctl --system
```

| 设置 | 值 | 目的 |
|------|----|----|
| `unprivileged_bpf_disabled=1` | 阻止非root BPF程序加载 | 仅root可加载BPF |
| `bpf_jit_harden=2` | 完全JIT加固 | 缓解JIT spray攻击 |

### 文件权限

```bash
# 限制安装目录sudo chmod 750 /opt/rswitch/
sudo chmod 640 /opt/rswitch/etc/profiles/*.yaml

# 限制包含凭据的配置文件sudo chmod 600 /etc/rswitch/rswitch.env

# BPF挂载目录sudo chmod 700 /sys/fs/bpf/
```

## 管理门户安全

### 认证配置

管理门户支持SHA-256散列密码：

```yaml
management:
 auth_enabled: true
 auth_user: admin
 auth_password: "<你的密码>" # 启动时自动SHA-256散列
```

启动时，`mgmtd` 对明文密码进行SHA-256散列，并用 `explicit_bzero()` 覆盖内存中的原文。密码验证使用 `constant_time_compare()` 防止时序侧信道攻击。

### CORS配置

生产环境**禁止**使用 `Access-Control-Allow-Origin: *`：

```yaml
management:
 cors_origin: "https://your-management-host.example.com"
```

### 命名空间隔离

管理门户在专用Linux网络命名空间（`rswitch-mgmt`）中运行，确保管理流量与数据平面转发隔离。

验证：

```bash
ip netns list | grep rswitch-mgmt
sudo ip netns exec rswitch-mgmt ss -tlnp | grep 8080
```

### TLS建议

应在 `mgmtd` 前部署反向代理（nginx、HAProxy）进行TLS终止：

```nginx
server {
 listen 443 ssl;
 server_name rswitch-mgmt.example.com;
 ssl_certificate /etc/ssl/certs/rswitch.crt;
 ssl_certificate_key /etc/ssl/private/rswitch.key;
 location / {
 proxy_pass http://127.0.0.1:8080;
 proxy_http_version 1.1;
 proxy_set_header Upgrade $http_upgrade;
 proxy_set_header Connection "upgrade";
 }
}
```

## BPF Map安全BPF maps挂载在 `/sys/fs/bpf/rs_*`，需限制访问权限：

```bash
sudo chmod 700 /sys/fs/bpf/
```

关键maps及暴露风险：

| Map | 内容 | 暴露风险 |
|-----|------|---------|
| `rs_acl_map` | ACL规则 | 策略绕过 |
| `rs_port_config_map` | 端口配置 | 配置篡改 |
| `rs_vlan_map` | VLAN成员 | VLAN跳跃 |
| `rs_route_map` | 路由表 | 流量劫持 |

## 安全检查清单

| 项目 | 检查 | 命令 |
|------|------|------|
| 非特权BPF已禁用 | `= 1` | `sysctl kernel.unprivileged_bpf_disabled` |
| JIT加固已启用 | `= 2` | `sysctl net.core.bpf_jit_harden` |
| 门户认证已启用 | `auth_enabled: true` | 检查配置YAML |
| CORS已限制 | `cors_origin` 设为特定主机 | 检查配置YAML |
| 命名空间隔离 | mgmtd在 `rswitch-mgmt` 中 | `ip netns list` |
| BPF挂载已限制 | 模式700 | `ls -la /sys/fs/bpf/` |
| 无明文密码 | 启动时自动散列 | 设计保证（C-2修复） |

## 事件响应

### 疑似入侵

```bash
# 1. 隔离: 停止rSwitch
sudo systemctl stop rswitch

# 2. 保留证据sudo bpftool prog list > /tmp/incident-progs.txt 2>/dev/null
sudo journalctl -u 'rswitch*' --since "24 hours ago" > /tmp/incident-logs.txt

# 3. 检查未授权BPF程序sudo bpftool prog list | grep -v rswitch

# 4. 清理并从可信源重新部署sudo rm -rf /sys/fs/bpf/rs_*
```

## 另请参阅

- [安全审计](../../SECURITY_AUDIT.md) — 完整审计发现和修复
- [管理门户](Management_Portal.md) — 门户架构和API
- [运维指南](../operations/Operations_Guide.md) — 日常运维
