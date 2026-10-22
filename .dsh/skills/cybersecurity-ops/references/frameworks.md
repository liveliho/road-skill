# 框架、评分与冲突裁决

> 框架是“共同语言”，不是“必须填满的表格”。一个 finding 通常只需要 1 个主框架 + 1 个技术分类；强行映射到 6 个框架会产生虚假精确。

## 1. 框架速查

| 框架 | 回答什么问题 | 用在哪里 | 不要用来 |
|---|---|---|---|
| **MITRE ATT&CK** | 攻击者做了什么行为？ | 检测、狩猎、事件时间线、紫队 | 给漏洞打分/替代 CVE |
| **MITRE D3FEND** | 有哪些防御对策？ | 修复/检测设计、防御覆盖 | 描述攻击行为 |
| **NIST CSF 2.0** | 组织安全能力/治理如何？ | 管理层、项目、合规、差距评估 | 单个漏洞的技术定级 |
| **MITRE ATLAS** | AI/ML 系统面临什么对抗技术？ | AI 红队、模型/agent 安全 | 传统 Web 漏洞 |
| **NIST AI RMF** | AI 风险如何治理？ | AI 系统全生命周期风险 | 具体 payload/利用 |
| **MITRE F3** | 网络欺诈如何发生/变现？ | BEC、账户接管、支付欺诈 | 普通漏洞管理 |
| **OWASP Top 10 / API Top 10** | Web/API 的主要风险类别 | 应用测试、开发培训 | 精确的严重性评分 |
| **OWASP ASVS** | 应用安全要求是否满足？ | 需求、验收、审计 | 替代渗透测试 |
| **CIS Benchmarks** | 系统/云配置基线 | 加固、合规、配置审计 | 应用逻辑漏洞 |
| **CVSS** | 技术严重性（base/environmental） | 漏洞 severity | 业务优先级/在野利用 |
| **EPSS** | 未来 30 天被利用概率 | 优先级输入 | 证明漏洞存在/可达 |
| **CISA KEV** | 是否已知在野利用 | 优先级/应急 | 证明所有版本都受影响 |
| **SSVC** | 处置决策（Track/Track*/Attend/Act） | 漏洞管理决策树 | 替代技术分析 |

## 2. 映射规则

### 2.1 一个 finding 一个主分类

```text
技术类型：CWE / OWASP 类别
技术严重性：CVSS
利用可能性：EPSS / KEV / 在野证据
攻击行为：ATT&CK（可选，事件/检测用）
防御对策：D3FEND（可选，修复/检测用）
治理：CSF 2.0 / 合规映射（可选，项目级）
```

例子：

- “SQL 注入” → CWE-89 / OWASP A03；CVSS；ATT&CK 不直接描述 SQLi（可能 T1190 Exploit Public-Facing Application）；D3FEND 可选。
- “Office → PowerShell 下载” → ATT&CK T1059.001/T1105；CWE 不适用；CVSS 不适用（这是行为，不是漏洞）。
- “S3 公共桶” → CWE-284/配置；CIS AWS 2.x；ATT&CK T1530（Data from Cloud Storage）；D3FEND 可选。

### 2.2 不要强行映射

- 没有证据的行为不要标 ATT&CK。
- 一个漏洞可能对应多个 CWE；选最具体的，不要列 10 个。
- CSF 是组织级功能，不是 finding 级标签；项目报告可映射，单条漏洞不必。
- ATLAS 只用于 AI/ML 相关；不要给普通 API 硬套。
- F3 只用于欺诈/变现链；普通勒索软件不一定用 F3。

## 3. 严重性 vs 优先级

| 维度 | 问题 | 输入 | 输出 |
|---|---|---|---|
| Severity | 技术影响多大？ | CVSS base/environmental、定性影响 | Critical/High/Medium/Low/Info |
| Priority | 现在先处理哪个？ | KEV、EPSS、暴露、数据、可达性、补偿控制、置信度 | P0/P1/P2/P3 + SLA |
| Risk | 对业务意味着什么？ | 资产关键性、财务/合规/声誉 | 风险陈述/接受决策 |

规则：

- Severity 不因“业务不重要”而降低；Priority 可以。
- CVSS 不因 KEV 而修改；Priority 可以提升。
- EPSS 高不代表可利用；需要可达性/配置/版本证据。
- KEV 是“已知在野利用”的强信号，但仍需确认资产受影响。
- 自定义评分必须公开公式、输入、缺失值和局限；不要伪装成 CVSS/EPSS。

## 4. 常见冲突与裁决

| 冲突 | 错误做法 | 正确做法 |
|---|---|---|
| 扫描器说 Critical，手工验证不可达 | 直接报 P0 | 保留 severity，降低 priority，写清不可达证据 |
| CVSS 9.8 但需要管理员 | 忽略 | severity 仍高；priority 按前提/暴露调整 |
| EPSS 0.9 但组件未使用 | 直接 P0 | 先确认可达/运行；priority 降级 |
| KEV 漏洞但已打补丁 | 继续报 | 验证版本/补丁；finding 状态改 `fixed`；资产可在清单标 `excluded`，但不要混用为 finding 状态 |
| 两个框架映射不同 | 都写，互相矛盾 | 选主框架；另一个作为补充并解释 |
| 工具 A 说存在，工具 B 说没有 | 取更吓人的 | 回到原始证据；解释差异（认证/版本/配置） |
| 用户要求“写成高危” | 迎合 | 用证据/影响解释；不伪造 |
| 授权范围与测试需要冲突 | 扩大范围 | 停止，申请范围变更 |
| 生产修复会中断业务 | 直接改 | 先缓解/变更窗口/回滚；owner 批准 |

## 5. NIST CSF 2.0 速查

| 功能 | 关注 | 安全运营例子 |
|---|---|---|
| Govern (GV) | 策略、角色、风险、供应链 | 授权/RoE、风险接受、供应商管理 |
| Identify (ID) | 资产、风险、改进 | 资产台账、攻击面、漏洞清单 |
| Protect (PR) | 身份、访问、数据、平台 | MFA、最小权限、加固、备份 |
| Detect (DE) | 持续监控、异常、验证 | 日志、EDR、检测规则、狩猎 |
| Respond (RS) | 事件管理、分析、缓解、沟通 | IR playbook、遏制、取证 |
| Recover (RC) | 恢复计划、改进 | 备份恢复、复盘、复测 |

不要把 CSF 当“检查表打分”；它是治理/能力框架，适合项目级 mapping。

## 6. ATT&CK 使用要点

- 用 tactic/technique 描述**行为**，不要描述漏洞。
- 一个事件通常映射 3–8 个关键技术，不必覆盖全部。
- 检测规则映射到 technique 时，注明数据源和子技术。
- 覆盖评估用 “technique → 数据源 → 规则 → 验证”，不要只数规则。
- 版本会更新（如 Defense Evasion 拆分）；引用时写版本/日期。

## 7. D3FEND 使用要点

- D3FEND 是防御技术本体，适合“针对 T1059 的检测/阻断/隔离有哪些”。
- 不要用 D3FEND ID 替代修复建议；它给你类别，具体配置仍需落地。
- 与 ATT&CK 双向映射时，注明版本。

## 8. AI 安全框架

- **ATLAS**：AI 系统的对抗技术（数据投毒、模型提取、prompt injection、agent 工具滥用等）。用于 AI 红队/威胁建模。
- **NIST AI RMF**：Govern/Map/Measure/Manage；适合 AI 项目治理、风险评估、上线门禁。
- **OWASP LLM Top 10**：LLM 应用风险清单；适合应用测试。
- 不要把传统 Web 漏洞都标成 ATLAS；只有 AI 特有/AI 相关链路才用。

## 9. 评分口径模板

在报告附录写：

```text
Severity: CVSS v3.1 base; 无向量时用定性等级（说明依据）。
Priority: 本 skill 示例公式（见 03），输入缺失标记 unknown；组织 SLA 可覆盖。
KEV: CISA KEV，查询日期 2026-10-22。
EPSS: FIRST EPSS，查询日期 2026-10-22；缺失标记 unknown，示例公式为可计算按 0 参与加权，报告必须显示该缺口。
CVSS/EPSS/KEV 都可能随时间变化；报告记录查询日期。
```

## 10. 参考

- MITRE ATT&CK: <https://attack.mitre.org/>
- MITRE D3FEND: <https://d3fend.mitre.org/>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- MITRE ATLAS: <https://atlas.mitre.org/>
- NIST AI RMF: <https://www.nist.gov/itl/ai-risk-management-framework>
- MITRE F3: <https://ctid.mitre.org/fraud/>
- OWASP Top 10: <https://owasp.org/Top10/>
- OWASP API Top 10: <https://owasp.org/API-Security/>
- CIS Benchmarks: <https://www.cisecurity.org/cis-benchmarks>
- FIRST CVSS: <https://www.first.org/cvss/>
- FIRST EPSS: <https://www.first.org/epss/>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA SSVC: <https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc>
