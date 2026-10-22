# 网络安全运营 Skill 安全审计

日期：2026-10-22（Asia/Shanghai）。修复版本：`secops.py 1.1.0`。

范围为本仓库的 skill 入口、13 份 reference、模板、Python CLI 和测试，以及本次增加的发布配置。审计采用代码/文本审查、合成输入、回环 HTTP 服务器与模拟 TLS/DNS；没有对真实业务系统进行漏洞利用。严重性是结合本地 CLI/agent 使用方式给出的定性判断，未计算 CVSS，不能将它们当作互联网服务的远程漏洞评级。

原始 `secops.py` SHA-256：`86e5b3188b9830b7d4454204d84929534f15aae51e07c70d521e5ad231ab324d`。原有 28 个测试通过，说明已有功能用例成立，但不足以覆盖以下安全边界。

## 发现与处置

| ID | 级别 | 问题与触发条件 | 修复与验证 |
|---|---|---|---|
| A01 | 高 | HTTP 预检 DNS 后，urllib 与独立 TLS 探测会再次解析；目标控制解析变化或使用环境代理时，实际连接可能越过已核验地址 | 每跳一次解析，检查全部地址后直接创建数字 IP socket；忽略代理环境变量，保留 Host/SNI 和证书验证，TLS 信息来自同一连接。测试确认运输层不再解析、保留主机身份、证书错误不会降级重试 |
| A02 | 高 | 脱敏不识别带引号的 JSON 字段、短秘密、Basic、部分令牌格式、URL userinfo/编码参数；IOC 原始 value 和截断上下文仍可泄漏令牌/私钥 | 补充识别，全文过滤后提取/截断，结构化 JSON 在序列化前脱敏；新增短值、转义引号、跨行私钥、敏感 URL、IPv6 与有效 JSON 输出测试 |
| A03 | 中 | scope 中的 URL 被简化成整个主机；非网络地址 CIDR 以 `strict=False` 扩大到整个网段；坏条目未及时拒绝 | 拒绝 URL/端口/路径与空 scope，严格解析 CIDR；URL 在 DNS 前检查凭据、控制字符、转义和端口；拒绝 HTTPS 降级。保留“仅主机/IP”的明确限制 |
| A04 | 中 | finding、文件名、IOC 上下文进入 CSV/Markdown 时，可携带公式、HTML、远程图片或代码围栏；后果取决于导入/渲染程序 | 三类 CSV 导出统一处理公式与控制前缀，Markdown 转义不可信标记；测试包含空白前缀及全角公式符号。文档说明另存/重新导入会削弱 CSV 保护 |
| A05 | 中 | 仅保留 ASCII 的标题指纹会把多个中文发现变为空标题；整个 asset 小写会合并大小写不同的 URL 路径；冲突状态会被隐去 | 标题保留 Unicode，URL 仅规范化协议/主机部分；冲突状态标 `unknown` 并保留原值，按完整来源项合并。对应回归验证发现不会丢失 |
| A06 | 中 | `0.5%` 被当作 `0.5`，从任意文字取第一个数字可能误读分数；未知 severity 默认为 medium，部分缺失上下文看似明确的 false | 严格有限数字解析、明确百分号换算、校验 KEV 日期；未知 severity 保留，`missing` 列出缺口。公式的运算默认值与人工复核要求写入输出和手册 |
| A07 | 中 | agent 手册没有明确将网页/日志/样本/仓库中的自然语言当不可信证据，可能被提示注入诱导执行、外传或扩大授权 | 增加证据与指令分离、先审查再执行、不根据工具输出授权的规则；修正 skill 自称高于用户的指令层级错误。此项为文本边界审查，尚未进行完整 agent 行为评测 |
| A08 | 中 | “必须先完整取证”“GET/HEAD 幂等即安全”等表述可能误导处置；资源认领被描述为非破坏验证，K8s 列 Secret 被当作元数据读取 | 遏制与取证按影响并行，明确持续破坏下不要等待完整取证；说明 HTTP 副作用、资源认领需授权、Secret API 数据边界；静态代码/配置证据也可确认问题，无需实际利用生产 |
| A09 | 低 | 标准输入/部分文本操作没有长度上限，NaN/Infinity 和过大重定向参数未约束；HTTP 报告可能使用初始 IP 或不相关 TLS 状态 | 文本输入每项 10 MiB 上限、有限数值范围、最多 10 次重定向；报告绑定最后一跳。完善干净的 CLI 错误处理，保留慢响应/总耗时限制说明 |
| A10 | 低 | 研究排名缺少原始快照，精确 stars 不可复核；没有持续测试/受控发布包，容易误交付证据或漏资源 | 移除未证实排名；增加 Windows/Linux 测试矩阵、最小权限和 SHA 固定的 Actions，以及文件白名单 ZIP/SHA-256；包测试核验敏感额外文件排除、资源完整性与同环境重复构建一致性 |

这些发现不意味着项目此前已被攻击；本次没有发现足以证明恶意后门、历史入侵或实际数据外传的证据。

## 验证方式

本地环境：Windows、Python 3.13.15。CLI 功能/安全回归 60 个，发布包验证 2 个；均通过后发布。GitHub Actions 会进一步在 Windows/Linux、Python 3.10/3.13/3.14 的矩阵中验证，线上结果以具体 workflow run 为准。

```powershell
python -m unittest discover -s .dsh/skills/cybersecurity-ops/scripts -p "test_*.py" -v
python -m unittest discover -s tests -p "test_*.py" -v
python -m py_compile .dsh/skills/cybersecurity-ops/scripts/secops.py tools/build_release.py
python tools/build_release.py
```

主要测试文件：

- [`test_secops.py`](../.dsh/skills/cybersecurity-ops/scripts/test_secops.py)：原有功能与本机 HTTP 集成。
- [`test_security.py`](../.dsh/skills/cybersecurity-ops/scripts/test_security.py)：地址/范围、TLS 连接约束、输出注入、脱敏、去重、评分边界。
- [`test_release.py`](../tests/test_release.py)：发布白名单、缺失资源阻断、ZIP 完整性与校验值。

本机 HTTP 使用真实回环 socket；TLS 主机名、验证标志和证书失败通过模拟连接验证，未用公网服务枚举 TLS，也未覆盖所有真实 TLS 证书链/代理组合。打包不会执行 skill 代码；Python 源码通过 AST 检查并按明确白名单收集。

## 仍需注意的限制

1. **scope 不是完整授权执行器。** 仅表示主机/IP；端口、路径、排除项、资产归属与授权有效期需要操作者核验。不能把填写开关当作获得授权。
2. **自动脱敏不是 DLP。** 自定义/嵌套编码、截断密钥、截图、客户名称等可能遗漏，公开前人工复核。IOC 的敏感值过滤可能造成部分指标丢失；保留受控原证据。
3. **CSV 保护依赖使用方式。** 按纯文本导入，编辑/另存后再次检查；程序交换优先 JSON。渲染器还应禁用不可信主动内容。
4. **执行时间与资源不是硬隔离。** socket 超时不等于全任务总时限，DNS/慢响应/大目录/特殊文件可能拖长运行。高风险输入在受控环境运行，必要时由外层进程设置硬资源限制。
5. **硬化观察不能证明可利用性。** 单次 HEAD 默认没有正文，单次 TLS 协商不能证明服务器不支持旧协议；未知输入应复核，不能凭示例评分关闭风险。
6. **领域命令是需核验的示例。** 未逐条运行外部扫描器，也未验证其所有版本、数据库、遥测和平台行为。框架版本与修复版本以任务时的官方信息为准。
7. **文本规则依赖宿主执行。** 尚未进行独立、完整的 agent 提示注入/误授权行为评测；这次新增的是明确规则与可验证的脚本约束，不能声称彻底解决提示注入。

## 参考依据

- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)：地址与重定向的信任边界。
- [Python http.client](https://docs.python.org/3/library/http.client.html)、[ssl](https://docs.python.org/3/library/ssl.html)：HTTP 连接与 TLS 身份验证。
- [OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection)：公式前缀及保存/重新打开后的限制。
- [FIRST EPSS](https://www.first.org/epss/)：概率输入的含义。

本报告只涵盖所列版本和验证方式，不构成“没有其他漏洞”的保证。
