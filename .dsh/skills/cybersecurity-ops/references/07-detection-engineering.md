# 检测工程与威胁狩猎

> 检测规则的价值不在“写了多少条”，而在**能否在真实数据上稳定区分恶意与良性**。这个手册用“假设 → 数据 → 规则 → 验证 → 调优 → 部署”的闭环，避免堆规则和拍脑袋阈值。

## 1. 适用场景

- 为 ATT&CK 技术/事件写 Sigma、KQL、SPL、Suricata、YARA-L 规则。
- 对现有告警做误报分析、调优、覆盖评估。
- 威胁狩猎：从假设出发找未知活动。
- 紫队：用 Atomic Red Team/Caldera 验证检测。

## 2. 先写假设，不先写规则

一个可测试的假设：

```text
在 [时间窗] 内，[资产群] 上，如果 [攻击者行为] 发生，
我们应该在 [数据源/字段] 看到 [可观测模式]，
并且它应与 [良性基线] 可区分。
```

示例：

> 在 7 天内，Windows 工作站上如果出现 Office 子进程启动 PowerShell 并带编码命令，我们应在 Sysmon Event 1/4104 中看到父子进程链与长 base64 参数；正常宏/管理脚本可能类似，需要用签名/路径/命令行白名单区分。

没有假设的“狩猎”容易变成随机翻日志。

## 3. 数据源与可见性

先确认数据是否存在、字段是否可用、保留多久：

| 行为 | 数据源 | 关键字段 |
|---|---|---|
| 进程执行 | Sysmon 1 / EDR / auditd | 父/子进程、命令行、用户、哈希、签名 |
| 网络连接 | Sysmon 3 / Zeek / EDR / VPC Flow | 五元组、进程、DNS、SNI、JA3 |
| 文件创建 | Sysmon 11 / EDR | 路径、哈希、签名、创建进程 |
| 注册表/服务 | Sysmon 12/13/14、7045 | 键、值、服务路径、账户 |
| 登录 | 4624/4625/4648、SSH、云 sign-in | 用户、源 IP、MFA、结果、会话 |
| PowerShell | 4104/4103、Script Block | 脚本块、编码、模块 |
| DNS | Zeek/Sysmon 22/ DNS logs | 查询名、响应、客户端、长度 |
| 云控制面 | CloudTrail/Activity/Audit | 主体、API、资源、源 IP、UA、结果 |
| 邮件 | M365/Google Workspace | 发件人、SPF/DKIM/DMARC、URL、附件 |

如果数据源缺失，先写“可见性缺口”，不要用低质量规则假装覆盖。

## 4. 规则结构（以 Sigma 为例）

```yaml
title: Certutil URL Cache Download
id: 8f3f7c2a-4b1e-4f0e-9d2a-1c6b5a7e9f10
status: experimental
description: Detects certutil used to download a file from a URL, a common ingress/download technique.
references:
  - https://attack.mitre.org/techniques/T1105/
author: cybersecurity-ops
date: "2026-10-22"
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains|all:
      - '-urlcache'
      - 'http'
  condition: selection_img and selection_cli
falsepositives:
  - Legitimate enterprise PKI/automation using certutil to fetch CRLs or packages
  - Admin scripts with allowlisted URLs
level: medium
tags:
  - attack.t1105
```

要点：

- `id` 用 UUID；`date` 用 ISO；`status` 标 `experimental/test/stable`。
- `falsepositives` 必须具体；不要写“unknown”。
- 条件优先用字段组合，不用大段正则。
- 对 `CommandLine` 做大小写/编码/参数顺序兼容；Sigma 后端会转换。
- 规则要能解释“为什么这代表恶意”，而不是“这个字符串很少见”。

### 4.1 规则类型

- **行为规则**：进程链、命令行、注册表、网络组合；抗改名的能力较强。
- **IOC 规则**：域名/IP/哈希；易过期，适合应急止血。
- **基线/异常规则**：频率、稀有度、时序；误报高，需要资产/角色上下文。
- **关联规则**：多个低置信信号组合（如“Office → PowerShell → 外联新域名”）。

## 5. 验证

### 5.1 正例

- 在隔离实验环境运行 Atomic Red Team/Caldera/自建模拟，确认规则触发。
- 记录：测试 ID、命令、时间、数据源、规则命中字段、原始事件。
- 不要在生产上跑攻击模拟；使用授权的测试网段/端点。

### 5.2 负例

- 用正常业务/管理脚本/软件安装/备份/监控流量测试。
- 至少覆盖：同工具合法用途、相似命令行、相似域名、不同用户/资产角色。
- 统计误报率；对高频规则做白名单/阈值/上下文过滤。

### 5.3 回测

- 用历史数据（7–30 天）跑规则，看来命中量、命中资产、时间分布。
- 抽样人工判定；不要只看“命中数为 0”就认为规则好——可能数据/字段不对。
- 对比现有规则，避免重复覆盖。

## 6. 调优

优先级：

1. **修字段/逻辑错误**（大小写、编码、字段不存在）。
2. **缩窄高误报条件**（父进程、签名、路径、用户、资产角色）。
3. **加关联**（同一主机 5 分钟内多个信号）。
4. **阈值/去重**（按主机/用户/小时聚合）。
5. **白名单**（具体路径/签名/变更单号；不要大面积排除）。

不要用“把 level 改成 low”解决误报；那只是掩盖。

## 7. 覆盖评估

用 ATT&CK 做**行为覆盖**，不是打卡：

```text
技术 -> 数据源 -> 规则 -> 最近验证时间 -> 已知盲区
T1059.001 PowerShell -> 4104/Sysmon 1 -> SIG-012 -> 2026-10-20 -> 编码/混淆变体
T1105 Ingress Tool Transfer -> Sysmon 3/11 -> SIG-031 -> 2026-10-18 -> 云存储/合法工具
```

覆盖评级：

- **有规则且有正/负例验证**：covered。
- **有规则但未验证/高误报**：partial。
- **有数据但无规则**：gap。
- **无数据**：blind。

向管理层汇报“gap/blind”，不要用规则数量冒充覆盖。

## 8. 威胁狩猎 loop

1. **假设**（基于 ATT&CK/CTI/事件复盘）。
2. **数据**（确认字段/保留/质量）。
3. **查询**（先宽后窄；保存查询）。
4. **分析**（基线对比、稀有度、时间/资产聚集）。
5. **验证**（主机/EDR/网络/身份多源）。
6. **产出**：新规则、调优、可见性需求、事件。
7. **复盘**：假设是否成立、查询是否可复用。

狩猎不是“找 IOC”；IOC 会过期，行为假设更持久。

## 9. 常见坑

- 规则依赖的字段在真实日志里不存在/为空。
- 只测正例，不测负例；上线后告警风暴。
- 用 `contains "powershell"` 覆盖所有 PowerShell，误报爆炸。
- 忽略编码/混淆：`-enc`、base64、大小写、参数拆分。
- 没有资产/身份上下文，无法判断“异常”。
- 规则复制粘贴，`id` 重复/缺 `falsepositives`。
- 把 ATT&CK 技术 ID 当规则 ID；一个技术需要多条规则/数据源。
- 只部署不监控：规则失效/数据断流无人发现。

## 10. 交付

```markdown
# 检测规则：Certutil URL Cache Download
- 假设/行为：...
- 数据源：Sysmon Event 1 / Windows Security 4688
- 规则：Sigma YAML（附文件）
- 正例：Atomic T1105 模拟，命中 1 条
- 负例：PKI 管理员脚本 12 次，命中 0（白名单 URL）
- 误报边界：企业 PKI/更新脚本；按 URL/签名/父进程过滤
- 部署：转换为 KQL/SPL；先在测试索引跑 7 天
- 监控：每日命中量、字段缺失率、数据源断流
```

## 11. 参考

- Sigma: <https://sigmahq.io/>
- MITRE ATT&CK: <https://attack.mitre.org/>
- Atomic Red Team: <https://github.com/redcanaryco/atomic-red-team>
- MITRE CALDERA: <https://caldera.mitre.org/>
- MITRE D3FEND: <https://d3fend.mitre.org/>
- Detection Engineering (Florian Roth): <https://github.com/Neo23x0/sigma>
