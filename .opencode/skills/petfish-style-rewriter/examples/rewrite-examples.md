# Rewrite Examples

## Example 1: Chinese-English spacing normalization

### Input

接入层支持Webhook挂载。接入事件包括Git提交，Issue更新和PR合并。

### Output

接入层支持Webhook挂载。接入事件包括Git提交、Issue更新和PR合并。

## Example 2: remove AI-style expression

### Input

在当今高度复杂的网络对抗格局中，银弹式的单点防御理念早已失效。现代网络安全的核心挑战，已经从对单一威胁指标的被动响应，转变为对复杂攻击者战术、技术和程序的主动理解与体系化对抗。

### Output

随着网络环境和攻击路径的复杂化，单一防御手段已经难以覆盖全部风险。

一方面，攻击活动通常会跨越多个阶段，仅依赖单个告警或单项指标难以还原完整过程。另一方面，不同安全设备产生的数据存在视角差异，需要通过关联分析才能形成较稳定的判断。

因此，安全分析不能只关注单一指标，而需要围绕攻击过程建立跨数据源的分析方法。

## Example 3: formal Chinese technical writing

### Input

AI渗透测试智能体会让攻击门槛普惠化，也会极限拔高高级攻击能力。

### Output

AI渗透测试智能体会改变攻击能力的使用方式。

对于低能力攻击者而言，智能体可以将部分侦察、扫描和漏洞利用流程自动化，从而降低实施复杂攻击链的技术门槛。对于高能力攻击者而言，智能体可以承担重复性任务，使攻击者能够同时管理更多目标和更大的攻击面。

因此，防御方需要关注的不只是单个攻击工具的能力变化，而是攻击组织方式和执行效率的变化。

## Example 4: English technical email

### Input

The hotfix is not related. The capture shows packet loss. Network should check it.

### Output

Hi [Name],

Thanks for the update.

Based on the network trace, the hotfix does not appear to be related to this issue. The trace indicates that the missing data was not captured by the network adapter on the receiving server. This usually means the packets did not reach the server, rather than being modified by the operating system.

Therefore, the next step should be to review the network path between the two servers and identify whether any device is filtering or dropping the traffic.

Please feel free to let me know if you have any questions or concerns.
