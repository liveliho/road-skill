# Finding 模板

> 一个 finding 只写一个可验证的问题。复制本模板，按需删减；不要用扫描器原始描述代替“影响/证据/修复”。

## 元数据

```yaml
id: V-001
title: "普通用户可读取其他租户发票 PDF"
asset: "https://staging.example.com/api/v1/invoices/{id}"
status: confirmed          # observed | suspected | confirmed | exploited | fixed | false_positive | accepted | unknown
severity: medium           # critical | high | medium | low | info | unknown
cvss:
  version: "3.1"
  vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
  score: 6.5
priority: P2               # 示例公式约 P3；因跨租户 PII 业务影响上调，需在报告记录例外
cwe: [CWE-639]
owasp: ["API1:2023 Broken Object Level Authorization"]
attck: []                  # 行为类 finding 才填，如 T1190
confidence: high
owner: "API team"
due: "2026-10-29"
```

## 摘要

一段话：谁、在什么前提下、能做什么、影响什么。不要只写漏洞类型。

## 影响

- **能**：...
- **不能**：...
- **前置条件**：...
- **受影响数据/用户/业务**：...

## 证据

| 证据 ID | 内容 | 位置/哈希 |
|---|---|---|
| E-001 | 请求/响应 | `evidence/E-001.txt` |
| E-002 | 对照请求 | `evidence/E-002.txt` |
| E-003 | 测试账号/租户 | `evidence/E-003.txt` |

## 复现（最小步骤）

1. ...
2. ...
3. ...

**对照/负例**：

- 无权限账号请求 -> 401/403
- 同租户账号请求 -> 200

## 根因

代码/配置/架构层面的原因；引用文件行号或配置项。

## 修复

- **根治**：...
- **短期缓解**：...（不能替代根治）
- **兼容/回滚**：...
- **测试**：...

## 检测

- 日志/字段：...
- 规则思路：...
- 误报边界：...

## 复测

- 步骤：...
- 通过标准：...
- 复测人/日期：...

## 参考

- CWE/OWASP/CVE/厂商公告：...
