# 事件响应与 DFIR

> 事件响应的第一目标不是“找出 APT”，而是**控制影响、保留证据、恢复业务、说清事实**。NIST SP 800-61r3 把 IR 融入 CSF 2.0 的治理/识别/保护/检测/响应/恢复；本手册用可执行顺序表达。

## 1. 适用场景

- 安全告警升级：可疑登录、恶意软件、C2、数据外传、勒索。
- 主机/账号/云资源确认失陷。
- 需要取证、时间线、影响范围、监管/客户沟通。
- 桌面演练/复盘。

不适用：未经授权的“反黑”、攻击攻击者、清除第三方系统。

## 2. 最初 60 分钟

以下活动按影响并行推进；持续加密、外传或人身安全风险下，按既有响应授权立即遏制，不等待完整取证：

1. **确认事件与授权**：谁负责、谁决策、是否已通知法务/公关/管理层；记录时间。
2. **定级**：影响范围（主机/账号/数据/业务）、是否在持续、是否勒索/数据泄露、是否关键基础设施。
3. **保存证据**：不要立刻重装/删除；先采集易失数据（见第 4 节）。
4. **止血**：隔离主机/禁用账号/撤销会话/封禁 IOC/关闭入口；选择对业务影响最小的方案。
5. **范围**：从初始告警向上下游扩：进程树、登录、网络、云审计、邮件、身份提供商。
6. **沟通**：建立事件频道、时间线、状态更新节奏；对外口径由授权发言人统一。
7. **记录**：每个动作谁在何时做了什么、结果如何；不要只靠记忆。

### 定级参考

| 级别 | 例子 | 响应 |
|---|---|---|
| SEV-1 | 核心业务中断、勒索大面积、确认大规模数据泄露 | 立即战情室；高管/法务/公关；24×7 |
| SEV-2 | 单业务系统失陷、管理员账号被控、有限数据 | 立即响应；业务 owner；定期同步 |
| SEV-3 | 单终端恶意软件、可疑但未确认 | 标准工单；当班处理 |
| SEV-4 | 低风险策略告警、误报 | 记录/调优 |

定级会变化；每次升级记录理由。

## 3. 角色与沟通

最小角色：

- **事件指挥（IC）**：决策、优先级、对外接口。
- **取证/分析**：证据、时间线、技术结论。
- **遏制/恢复**：隔离、修复、验证。
- **沟通**：内部状态、客户/监管/媒体（按授权）。
- **记录员**：时间线、决策、证据链。

沟通规则：

- 事实与推测分开；未知就说未知。
- 不在非授权渠道分享受害者/样本/客户数据。
- 勒索/数据泄露不要自行联系攻击者；由授权方/执法决定。
- 保留所有对外声明草稿和批准记录。

## 4. 证据：易失性顺序

从最易失到最持久：

1. CPU/寄存器/内存中的进程、网络连接、登录会话。
2. 运行中的进程、服务、计划任务、内核模块。
3. 网络连接/路由/ARP/DNS 缓存。
4. 临时文件、日志缓冲区、剪贴板。
5. 磁盘文件、注册表、配置。
6. 备份、归档、离线介质。

### 4.1 Windows

```powershell
# 仅示例；在授权/取证流程下运行，输出到证据目录
New-Item -ItemType Directory -Force .\evidence | Out-Null
Get-Date -Format o
Get-Process | Export-Csv .\evidence\processes.csv -NoTypeInformation
Get-NetTCPConnection | Export-Csv .\evidence\net-tcp.csv -NoTypeInformation
Get-Service | Export-Csv .\evidence\services.csv -NoTypeInformation
Get-ScheduledTask | Export-Csv .\evidence\scheduled-tasks.csv -NoTypeInformation
```

优先采集：

- 内存镜像（WinPmem/AVML 等，按批准工具）。
- `$MFT`、`$UsnJrnl`、Event Logs（Security/System/Application/Sysmon/PowerShell）。
- 注册表 hive（SAM/SECURITY/SYSTEM/SOFTWARE/NTUSER）。
- 浏览器/邮件/下载目录、Prefetch/Amcache/ShimCache/UserAssist。
- EDR 进程树/网络事件。

关键事件 ID（需结合环境）：

- 4624/4625 登录成功/失败；4648 显式凭据；4672 特殊权限。
- 4688 进程创建（需审核策略）；Sysmon 1/3/7/8/10/11/22。
- 4103/4104 PowerShell 模块/脚本块日志。
- 7045 服务安装；4697 服务创建。
- 1102 日志清除；104 日志清空。

### 4.2 Linux/macOS

```bash
date -u
ps auxww > evidence/ps.txt
ss -tulpan > evidence/sockets.txt
last -Fai > evidence/logins.txt
journalctl --since "2026-10-20 00:00:00" > evidence/journal.txt
```

采集：`/var/log/auth.log`/`secure`、`auditd`、`syslog`、`~/.bash_history`、cron/systemd、`/etc/passwd|shadow`（受控）、SSH authorized_keys、容器日志。

### 4.3 云

- AWS CloudTrail、GuardDuty、VPC Flow Logs、S3 access logs、IAM credential report。
- Azure Activity/Sign-in/Entra ID audit、NSG flow logs、Defender alerts。
- GCP Cloud Audit Logs、VPC Flow Logs、Security Command Center。
- Kubernetes audit logs、容器运行时/ Falco、镜像 digest。

云取证注意：API 调用本身会写日志；记录调查者身份/时间；使用只读角色；快照磁盘/导出日志前确认授权与数据边界。

## 5. 分析：建立时间线

- 统一 UTC；保留原始时区/时钟偏移。
- 每个事件带来源（主机/日志/EDR/云/网络）、主体（用户/进程/IP）、动作、对象、结果。
- 先画“初始访问 → 执行 → 持久化 → 提权 → 横向 → 外联/外传 → 影响”。
- 用 ATT&CK 标注行为，但不要强行填满所有战术。
- 对每个关键节点找**独立第二来源**（EDR + 网络 + 日志）；单源结论标 `suspected`。

```bash
# 简单合并示例（按时间排序；实际用 Plaso/Timesketch/Excel）
# 不直接 cat/sort 异构 CSV：先用 CSV 解析器分别加载、统一时间字段与时区，
# 保留每行的来源文件/原始时间/证据 ID，再排序导出；保留原始文件。
```

工具：Plaso/log2timeline、Timesketch、Hayabusa、Chainsaw、KAPE、Velociraptor、Volatility 3、Zeek。

## 6. Containment（止血）

选项与代价：

| 动作 | 作用 | 风险 |
|---|---|---|
| 网络隔离主机 | 阻断 C2/横向 | 影响业务/远程运维 |
| 禁用账号/撤销会话 | 阻断访问 | 影响用户；需保留证据 |
| 轮换凭据/密钥 | 切断持久访问 | 可能触发攻击者警觉 |
| 封禁 IP/域名 | 快速止血 | 可能误封/CDN 共享 |
| 关闭入口/下线服务 | 阻断初始访问 | 业务中断 |
| 加 WAF/EDR 规则 | 精准阻断 | 规则误报/绕过 |

原则：

- 先止血再根因；但不要破坏证据。
- 在不延误必要遏制的前提下采集内存/连接/进程；记录隔离对易失证据的影响。
- 对攻击者可见的动作（禁用账号、封 IP）可能促使其破坏/加速；与 IC 权衡。
- 记录每个动作的时间、执行人、影响、回滚方法。

## 7. 勒索软件专项

- 立即隔离受感染网段/主机；优先保护备份（离线/不可变）。
- 不要支付赎金（除非经法律/管理层授权，且理解制裁/合规风险）。
- 确认加密范围、窃取数据（双重勒索）、泄露站点。
- 保留勒索信、样本、加密文件样本、日志。
- 恢复：从已知干净备份、验证完整性、分段恢复、监控再感染。
- 检查初始访问：VPN/暴露的 RDP/钓鱼/供应链/漏洞。
- 通知：法务、保险、监管、客户（按适用法律）。

## 8. Eradication/Recovery

- 根因修复：补丁、配置、账号、供应链、边界。
- 清除持久化：服务、计划任务、注册表、WebShell、恶意账号、SSH key、OAuth 应用。
- 重建 vs 清理：被提权/内核级/不确定时优先重建。
- 恢复顺序：身份/网络/核心数据/业务；先小范围验证。
- 监控：恢复后 1–2 周提高日志/EDR 关注；设置再感染告警。
- 复测：原 IOC 不再出现、漏洞已修、凭据已轮换。

## 9. 事后复盘

- 时间线复盘：哪些发现早/晚、哪些工具/流程缺失。
- 根因与贡献因素：技术、流程、人员、供应商。
- 改进项：owner、截止日、验证方式；不要只写“加强安全意识”。
- 指标：MTTD、MTTA、MTTC、MTTR；误报/升级准确率。
- 更新检测/ playbook / 资产台账 / 备份恢复演练。

## 10. 常见坑

- 先重装再取证，证据全丢。
- 只查单主机，忽略身份提供商/云控制面/横向。
- 把“杀毒软件隔离”当“事件结束”。
- 时间线混用本地时间/UTC，顺序错乱。
- 过早对外下结论（“没有数据泄露”）后被打脸。
- 不记录调查者自己的 API 调用，污染云日志。
- 不验证备份可恢复，恢复时才发现损坏。
- 忽略攻击者留下的 OAuth token/API key/SSH key，清除了主机但仍可访问。

## 11. 参考

- NIST SP 800-61r3: <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- CISA Incident Response: <https://www.cisa.gov/incident-response>
- MITRE ATT&CK: <https://attack.mitre.org/>
- Volatility 3: <https://github.com/volatilityfoundation/volatility3>
- Velociraptor: <https://docs.velociraptor.app/>
- Timesketch: <https://timesketch.org/>
- Hayabusa: <https://github.com/Yamato-Security/hayabusa>
