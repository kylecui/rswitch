# 管理门户用户指南rSwitch Web管理门户的操作参考，覆盖访问、功能页面和REST API。

## 访问门户

### 前提条件

- 活动配置中已启用管理门户（`management.enabled: true`）
- rSwitch loader和 `rswitch-mgmtd` 正在运行
- 浏览器所在设备与交换机端口在同一L2网络

### 查找门户IP

```bash
# 查看管理接口IP
sudo ip netns exec rswitch-mgmt ip addr show mgmt0
```

在浏览器中打开 `http://<管理IP>:8080`。

### 登录

启用认证（`auth_enabled: true`）时：

1. 导航到门户URL
2. 输入用户名和密码（在配置YAML中设置）
3. 点击 **登录**

> **安全提示**: 生产部署前应更改默认密码。参见[安全加固指南](../deployment/Security_Hardening.md)。

## 仪表盘 (index.html)

主仪表盘提供系统概览：

| 区域 | 信息 |
|------|------|
| **系统信息** | 主机名、rSwitch版本、运行时间、管理IP |
| **端口摘要** | 总端口数、上线/下线端口、总吞吐量 |
| **快速统计** | MAC表条目、VLAN数量、活跃模块 |

## 端口管理 (ports.html)

### 端口状态面板

可视化面板显示所有交换端口：

- **颜色编码**: 绿色（上线/有链路）、灰色（下线/无链路）、红色（错误）
- 点击端口查看详细信息：接口名、ifindex、RX/TX统计、VLAN模式等

## 模块 (modules.html)

### 流水线可视化

按执行顺序显示已加载的模块流水线：

```
入口: dispatcher → vlan → acl → route → l2learn → lastcall出口: egress_qos → egress_vlan → egress_final
```

### 模块表

显示每个模块的处理包数、转发包数、丢弃包数和处理字节数。

## VLAN管理 (vlans.html)

### VLAN操作

**创建VLAN**:
1. 点击 **添加VLAN**
2. 输入VLAN ID (1-4094)
3. 选择成员端口和模式（access/trunk）
4. 点击 **保存**

**删除VLAN**: 点击VLAN旁的删除图标并确认。

等效CLI：
```bash
sudo ./build/rsvlanctl add-port ens34 trunk 100,200
sudo ./build/rsvlanctl show
```

## ACL管理 (acls.html)

### ACL操作

**添加规则**:
1. 点击 **添加规则**
2. 填写匹配条件（源/目标IP、协议、端口）
3. 选择动作（允许/拒绝）
4. 设置优先级5. 点击 **保存**

规则使用稳定ID标识，删除规则不会改变其他规则的标识符。

等效CLI：
```bash
sudo ./build/rsaclctl add --src 10.0.0.0/8 --dst 192.168.1.0/24 --action deny --priority 100
```

## 路由管理 (routes.html)

**添加路由**:
1. 输入目标前缀（如 `10.0.0.0/8`）
2. 输入下一跳IP
3. 选择出口接口4. 点击 **保存**

等效CLI：
```bash
sudo ./build/rsroutectl add 10.0.0.0/8 via 192.168.1.1 dev ens34
```

## DHCP Snooping (dhcp.html)

显示DHCP snooping绑定表：MAC地址、IP地址、VLAN、端口、租期。此页面为只读 — 绑定由DHCP snooping模块自动填充。

## 网络 (network.html)

显示MAC地址表和ARP表。

## 实时日志 (logs.html)

通过WebSocket连接的实时事件流：

- 支持按事件类型、模块或严重性过滤
- 自动滚动，新事件显示在底部

## 配置文件 (profiles.html)

查看当前加载的配置文件：活动配置名称、模块列表、VOQd配置。

> **注意**: 配置变更需要重新加载rSwitch loader。门户显示当前状态，不支持运行时切换配置。

## REST API参考

除 `POST /api/auth/login` 外，所有API端点均需认证（会话cookie）。

### 认证

| 方法 | 路径 | 描述 |
|------|------|------|
| `POST` | `/api/auth/login` | 登录 |
| `POST` | `/api/auth/logout` | 注销 |

### 系统

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/api/system/info` | 主机名、版本、运行时间、端口数、管理IP |
| `GET` | `/api/system/health` | 健康检查 |
| `POST` | `/api/system/reboot` | 重启系统 |
| `POST` | `/api/system/shutdown` | 关机 |
| `GET/PUT` | `/api/system/network` | 管理网络配置 |

### 端口

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/api/ports` | 端口列表及统计 |
| `GET` | `/api/ports/:id/stats` | 单端口详细统计 |
| `PUT` | `/api/ports/:id/config` | 更新端口配置 |

### 模块

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/api/modules` | 已加载模块及流水线阶段 |
| `GET` | `/api/modules/:name/stats` | 模块处理统计 |
| `POST` | `/api/modules/:name/reload` | 热重载模块 |
| `PUT` | `/api/modules/:name/config` | 更新模块配置 |

### VLAN

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET/POST` | `/api/vlans` | 列表 / 创建VLAN |
| `PUT/DELETE` | `/api/vlans/:id` | 更新 / 删除VLAN |

### ACL

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET/POST` | `/api/acls` | 列表 / 创建ACL规则 |
| `PUT/DELETE` | `/api/acls/:id` | 更新 / 删除ACL规则 |

### 路由

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET/POST` | `/api/routes` | 列表 / 添加路由 |
| `DELETE` | `/api/routes/:name` | 按名称删除路由 |

### NAT

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET/POST` | `/api/nat/rules` | NAT规则 |
| `GET` | `/api/nat/conntrack` | 连接跟踪表 |

### Profile管理

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/api/profiles` | Profile列表 |
| `GET` | `/api/profiles/active` | 当前激活的profile |
| `POST` | `/api/profiles/apply` | 应用profile |
| `GET/PUT/DELETE` | `/api/profiles/:name` | Profile CRUD |

### 配置管理

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/api/config/snapshots` | 配置快照列表 |
| `POST` | `/api/config/save` | 保存当前配置 |
| `POST` | `/api/config/reset` | 恢复默认配置 |
| `POST` | `/api/config/export` | 导出配置 |
| `POST` | `/api/config/snapshot` | 创建命名快照 |
| `POST` | `/api/config/rollback/:id` | 回滚到指定快照 |
| `GET` | `/api/config/audit` | 配置审计日志 |

### 拓扑、事件与DHCP

| 方法 | 路径 | 描述 |
|------|------|------|
| `GET` | `/api/topology` | 网络拓扑 |
| `GET` | `/api/events` | 事件日志 |
| `GET` | `/api/dhcp-snooping` | DHCP Snooping绑定表 |
| `POST` | `/api/dhcp-snooping/config` | DHCP Snooping配置 |
| `POST` | `/api/dhcp-snooping/trusted-ports` | 设置信任端口 |

### WebSocket

| 路径 | 描述 |
|------|------|
| `/api/ws` | 实时事件流（日志页面使用） |

### curl示例

```bash
# 登录curl -c cookies.txt -X POST -H 'Content-Type: application/json' \
 -d '{"username":"admin","password":"rswitch"}' \
 http://<管理IP>:8080/api/auth/login

# 获取系统信息curl -b cookies.txt http://<管理IP>:8080/api/system/info

# 健康检查curl -b cookies.txt http://<管理IP>:8080/api/system/health

# 端口统计curl -b cookies.txt http://<管理IP>:8080/api/ports

# 模块列表curl -b cookies.txt http://<管理IP>:8080/api/modules

# 创建VLAN
curl -b cookies.txt -X POST -H 'Content-Type: application/json' \
 -d '{"vlan_id":100,"name":"Engineering"}' \
 http://<管理IP>:8080/api/vlans

# Profile列表curl -b cookies.txt http://<管理IP>:8080/api/profiles

# 保存配置快照curl -b cookies.txt -X POST http://<管理IP>:8080/api/config/snapshot
```

## 故障排除

### 门户无法访问1. 检查mgmtd运行状态: `sudo systemctl status rswitch-mgmtd`
2. 检查管理IP: `sudo ip netns exec rswitch-mgmt ip addr show mgmt0`
3. 检查端口: `sudo ip netns exec rswitch-mgmt ss -tlnp | grep 8080`
4. DHCP超时: 验证所有端口XDP模式一致

### 认证失败

- 验证凭据与配置YAML一致
- 查看日志: `sudo journalctl -u rswitch-mgmtd`
- 重启: `sudo systemctl restart rswitch-mgmtd`

## 另请参阅

- [管理门户](../deployment/Management_Portal.md) — 架构、命名空间设计、API详情
- [CLI参考](CLI_Reference.md) — 等效CLI命令
- [安全加固](../deployment/Security_Hardening.md) — 门户安全配置
- [故障排除](Troubleshooting.md) — 通用诊断流程
