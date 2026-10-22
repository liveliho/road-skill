# 漏洞定级、去重与修复排序

> 扫描器输出不是风险清单。这个手册把“技术严重性”和“业务处置优先级”分开，避免三个常见错误：把 CVSS 当唯一标准、把 EPSS 当漏洞存在证明、把 KEV 当“一定被利用”。

## 1. 输入

- 扫描器导出：Nessus、Qualys、Nuclei、Trivy、Semgrep、CodeQL、云 CSPM、人工发现。
- 资产上下文：互联网暴露、数据分级、业务关键性、补偿控制、可达性。
- 漏洞情报：CVE/NVD、厂商公告、CISA KEV、FIRST EPSS、利用代码/在野报告。
- 修复上下文：补丁可用性、变更窗口、依赖链、回滚成本。

最少字段：

```text
id, title, asset, severity, cvss, cve, evidence, source, confidence,
internet_exposed, data_sensitive, kev, epss
```

缺失字段要标记 `unknown`，不要默认“安全”。

## 2. 规范化与去重

### 2.1 统一字段

- **标题**：`组件 + 版本 + 问题`，例如 “nginx 1.18.0 存在 CVE-2021-23017 可导致 DNS resolver 越界写”。
- **资产**：规范化主机名/URL/云资源 ID；保留端口和路径。
- **CVE/CWE**：CVE 用大写；CWE 用于类型；不要用 ATT&CK ID 代替。
- **CVSS**：记录版本和向量；只有分数没有向量时标注“score only”。
- **状态**：`observed/suspected/confirmed/exploited/fixed/false_positive/accepted/unknown`（见 SKILL.md）。

### 2.2 去重指纹

推荐：

```text
if cve:
    dedupe_key = canonical_asset(asset) + "|" + upper(cve)
else:
    dedupe_key = canonical_asset(asset) + "|" + unicode_casefold(title)
fingerprint = sha256(dedupe_key)
```

只规范化主机名大小写，保留 URL 路径、查询和云资源标识的大小写；标题保留中文和标点。状态矛盾（例如 `confirmed` 与 `fixed`）合并后标 `unknown`，在 `status_conflicts`/理由中列出原值，交由证据复核。不同端口/组件实例仍须在 asset 中明确区分。

同一 CVE 在同一资产的不同端点可能是多个 finding；不要粗暴按 CVE 全局合并。**如果 finding 是端点级的，把完整 URL/端点写进 `asset`**；这样同一 host 的不同端点不会误合并。反过来，同一端点被三个扫描器报同一问题，应合并并保留 `sources: [nessus, nuclei, manual]`。本 skill 的 `triage` 对“相同 asset + CVE”合并；没有 CVE 时按 asset + 规范化标题指纹合并。

### 2.3 规范化示例

```bash
# 本 skill 的 triage 会做列名别名、CVSS/EPSS 归一、布尔解析、去重和排序
python scripts/secops.py triage findings.csv --format md --as-of 2026-10-22
```

输入 CSV 示例见 `assets/triage-example.csv`。输出会明确写出公式和“自定义评分，不是行业标准”。

## 3. 先验证“是不是真的”

在评分前，至少排除：

- **版本误判**：banner/字符串命中但实际已 backport 补丁；查厂商公告、包版本、构建号。
- **配置缓解**：功能未启用、需要认证、仅内网、WAF/网关阻断、编译选项关闭。
- **扫描器未认证**：把“未登录看不到”误报为“不存在”；反之也可能漏报。
- **软 404/默认页**：所有路径都 200；用随机路径对照。
- **重复/旧资产**：已下线、已迁移、测试环境；确认 DNS/资产归属。
- **PoC 不可复现**：环境差异、依赖缺失、权限不足；记录失败原因，不强行标 confirmed。
- **误读 CVSS**：向量版本不同、`AV`/`PR` 与实际不符、`S` 范围判断错误。

验证深度：

| 级别 | 证据 | 适用 |
|---|---|---|
| L1 版本/配置匹配 | 版本、构建号、配置项 | 大批量初筛，标 `suspected` |
| L2 非破坏验证 | 只读请求、错误差异、受控回调 | 大多数 Web/API |
| L3 直接证据 | 受控复现，或代码/配置可达路径与回归测试 | confirmed；不要求生产利用 |
| L4 实际利用 | 授权范围内达成影响 | exploited；高门槛 |

## 4. 严重性（severity）

优先使用 **CVSS v4.0 或 v3.1 base**，记录向量。没有向量时用定性等级，并说明依据：

| 等级 | 典型影响 | 例子 |
|---|---|---|
| Critical | 未认证 RCE、大规模数据泄露、核心身份系统完全失陷 | 互联网可达的未认证 RCE |
| High | 认证后 RCE、大量敏感数据读取、权限提升到管理员 | SQLi 可读全库、IDOR 批量数据 |
| Medium | 有限数据/权限、需要交互、局部绕过 | 存储型 XSS 影响单用户、有限 SSRF |
| Low | 信息泄露、低影响配置、需要高权限 | 版本 banner、缺少安全 header |
| Info | 观察/最佳实践 | 建议启用日志、CSP report-only |

注意：

- CVSS base 不包含“是否在野利用”“业务重要性”“补偿控制”；这些属于 priority。
- 环境评分（CVSS environmental）可以调整，但必须写明改了哪些 metric。
- 不要为了“让老板重视”手动抬高 CVSS；用 priority 和业务影响表达。

## 5. 优先级（priority）

优先级是处置顺序，不是漏洞严重性。推荐输入：

- **KEV**：CISA 已知被利用漏洞目录（有日期）。
- **EPSS**：未来 30 天被利用概率（0–1）；没有数据时标 `unknown`，不要当 0。
- **暴露**：互联网可达、面向客户、可从低权限网络到达。
- **数据敏感性**：PII/支付/医疗/凭据/源代码。
- **可达性/前置条件**：未认证 vs 需管理员；需要用户交互。
- **补偿控制**：WAF、网络隔离、EDR、强 MFA。
- **置信度**：confirmed vs suspected。

### 5.1 本 skill 的可审计公式

`scripts/secops.py triage` 使用以下**示例公式**（不是 CVSS 标准，也不是 SSVC 官方实现）：

```text
impact      = cvss / 10           # 无 CVSS 时用 severity 映射: critical .95, high .80, medium .55, low .25, info 0；未知标 unknown，计算暂用 0
epss_norm   = epss (0..1)         # 缺失标记 unknown；示例公式按 0 参与加权，报告必须显示缺口
kev_flag    = 1 if KEV else 0
exposed     = 1 if internet_exposed else 0
sensitive   = 1 if data_sensitive else 0
confidence  = 0..1                # 默认 0.8；低置信度降低分数

score = 100 × (0.50×impact + 0.20×epss_norm + 0.15×kev_flag
               + 0.10×exposed + 0.05×sensitive) × confidence
```

`missing` 显示 CVSS、EPSS、severity、KEV、暴露、敏感性和置信度的未知输入。未知标志仅为公式运算暂用 false，置信度暂用 0.8，不代表已核实；输入不完整时必须人工复核，不能凭低分关闭。`fixed/false_positive/accepted` 状态仍保留用于复核，分数不会重新打开或关闭发现。百分号明确换算（`0.5% = 0.005`），拒绝 NaN/Infinity 和夹杂说明的分数字符串；不计算 CVSS 向量，只有向量时分数保持未知。

优先级：

- **P0**：`score ≥ 85`，或 `KEV + 互联网暴露 + (CVSS ≥ 9.0 或 Critical)` 且 confidence ≥ 0.8。
- **P1**：`score ≥ 70`，或 KEV，或 CVSS ≥ 9.0 / Critical（confidence ≥ 0.7）。
- **P2**：`score ≥ 40`，或 CVSS ≥ 7.0 / High。
- **P3**：其余。

SLA 示例（按 `--as-of` 起算）：P0 24 小时、P1 7 天、P2 30 天、P3 90 天。组织应按自身风险偏好调整。

**为什么这样设计**：CVSS 占 50% 保证技术影响主导；EPSS/KEV 占 35% 引入现实利用；暴露/敏感性占 15% 引入业务上下文；confidence 防止“扫描器说高危”直接变 P0。它不是学术模型，但每一项都可解释、可复算。

### 5.2 什么时候不用公式

- 有正式漏洞管理流程/SSVC 决策树时，优先使用组织标准。
- 涉及安全事件（正在被利用）时，直接按事件响应处理，不等待评分。
- 涉及合规强制项（如 PCI DSS）时，合规要求可能高于风险评分。
- 评分输入大量缺失时，先补数据，不要用公式制造精确假象。

## 6. 修复排序

排序不是“分数高就先修”，还要看：

1. **止血**：KEV/在野利用/互联网暴露 → 先缓解（WAF 规则、关闭入口、轮换密钥）。
2. **低成本高收益**：关闭调试端点、移除默认账号、限制管理面。
3. **补丁批次**：同一维护窗口内合并；避免频繁重启核心系统。
4. **依赖链**：升级基础镜像/框架可能影响多个应用；先测试。
5. **补偿控制**：暂时无法修时，记录 compensating control、owner、到期日。

修复建议必须具体：

- 版本：`升级到 nginx 1.24.0+`（确认厂商修复版本）。
- 配置：给出指令/字段，不只写“加固”。
- 代码：给出安全写法/API，不只写“过滤输入”。
- 云：给出资源 ID、策略、最小权限示例。
- 检测：给出日志字段和规则思路。

## 7. 常见坑

- **把 EPSS 当“会不会被利用”的确定答案**：它是概率，不是保证；高 EPSS 低影响不一定 P0。
- **把 KEV 当“所有版本都受影响”**：KEV 是漏洞级别的在野利用证据，仍需确认资产/版本/配置。
- **忽略“未授权不可达”**：内网漏洞可能通过钓鱼/横向到达；用攻击路径评估，不要简单忽略。
- **只看 CVSS 不看数据**：一个 Medium 的 IDOR 可能泄露全部客户数据，优先级应提升。
- **重复计数**：同一根因的 50 个端点不要报 50 个 P0；合并为一个 finding + 影响范围。
- **修复建议不可执行**：没有版本/配置/测试步骤，owner 无法行动。
- **没有复测**：修复后必须用原 PoC/原扫描器复测，记录版本和结果。

## 8. 交付格式

```markdown
# 漏洞风险清单（示例）
范围：example.com 外部资产；扫描时间 2026-10-20~22 UTC
输入：Nessus 312 条、Nuclei 88 条、人工 7 条；去重后 96 条
公式：见 5.1；缺失 EPSS 14 条、缺失 CVSS 3 条

| ID | 优先级 | 分数 | 资产 | 问题 | CVE | CVSS | EPSS | KEV | 状态 | 截止 | 修复 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| V-001 | P0 | 91.2 | vpn.example.com | 未认证 RCE | CVE-... | 9.8 | 0.73 | yes | confirmed | 10-23 | 升级/临时禁用 |
...

## 建议
1. 24h：...
2. 7d：...
3. 30d：...
```

## 9. 参考

- FIRST CVSS: <https://www.first.org/cvss/>
- FIRST EPSS: <https://www.first.org/epss/>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- NIST NVD: <https://nvd.nist.gov/>
- CISA SSVC: <https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc>
- OWASP Risk Rating: <https://owasp.org/www-community/OWASP_Risk_Rating_Methodology>
