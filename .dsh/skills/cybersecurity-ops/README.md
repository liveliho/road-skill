# cybersecurity-ops

通过 `SKILL.md` 路由到授权、侦察、Web/API、漏洞定级、PCAP、样本、事件响应、检测、云/容器、供应链和报告手册。每次只加载当前任务需要的手册。

## 安装与目录

复制完整 `cybersecurity-ops/` 文件夹到宿主的 skill 目录。DSH 可使用项目中的 `.dsh/skills/`；具体发现、刷新与手动调用方式以宿主版本为准。本包不安装外部扫描器，也不包含远程服务。

- `SKILL.md`：入口、授权和证据信任边界、路由、状态与交付。
- `references/`：按领域加载的操作手册；命令示例执行前检查版本和范围。
- `scripts/secops.py`：Python 3.10+ 标准库 CLI，版本 1.1.0。
- `scripts/test_*.py`：功能与安全回归；网络测试使用本机服务器或模拟连接。
- `assets/`：范围、报告、finding 模板和合成示例。

## CLI

在本文件所在目录运行：

```bash
python scripts/secops.py --help
python scripts/secops.py ioc evidence.txt --format md
python scripts/secops.py hash sample.bin --format json
python scripts/secops.py triage assets/triage-example.csv --format md
python scripts/secops.py redact report.md --pii --output report-share.md
python -m unittest discover -s scripts -p "test_*.py" -v
```

`ioc/hash/triage/redact` 不主动联网；本地路径仍受操作系统权限、网络挂载等环境因素影响。

### HTTP 检查

```bash
python scripts/secops.py http https://staging.example.com/ --scope-file scope.txt --i-have-authorization --format json
# 如明确需要读取正文，增加 --method GET；默认 HEAD 不提取页面标题。
```

`scope.txt` 每行一个主机、一级通配符、IP 或严格对齐的 CIDR，例如：

```text
staging.example.com
*.example.com
203.0.113.0/24
```

- `*.example.com` 不包含根域或多级子域。URL、端口/路径条目、空 scope 和无效 CIDR 会报错；`203.0.113.7/24` 不会被自动扩大成整个网段。
- scope 文件不表达端口、路径、排除项、归属或时间窗。只有这些条件已由操作者核验时才能运行；路径受限任务建议 `--max-redirects 0` 或采用能完整表达限制的工具。
- 每跳检查所有 A/AAAA 结果，非全局地址必须显式列出 IP/CIDR；包含 IPv4 映射 IPv6。连接固定到已验证 IP；环境代理被忽略。通过连接的 Host/SNI 验证目标身份，从同一连接读取 TLS 信息。
- 拒绝 URL 凭据、控制字符、非法转义、端口 0，以及 HTTPS 到 HTTP 的重定向。默认最多 5 次重定向，上限 10；超时范围 `(0,120]` 秒、重定向间隔 `[0,60]` 秒，只接受有限数值。
- 默认验证证书；`--insecure` 仅用于明确批准的隔离实验，报告标 `verified: false`。单次协商无法枚举服务器支持的全部协议/密码套件。
- HEAD/GET 仍可能产生服务端副作用。脚本不爬取、注入或爆破；socket 超时是 I/O 超时，并非严格的总执行时限。DNS、慢速响应和多地址连接仍可能延长运行时间。
- 最多读取 256 KiB 正文；报告不保存 Cookie 值或完整正文。安全头检查属于加固观察，不能证明漏洞可利用；JSON API 不套用 HTML 页面专用检查。

### 脱敏与输出

`redact` 识别常见令牌、Basic/Bearer、Cookie、JSON/配置秘密字段、URL 凭据和敏感查询参数；`--pii` 增加邮箱、电话、支付卡号与私有 IPv4/IPv6。有效 JSON 逐字段脱敏后重新序列化。自定义格式、编码/加密内容、截图、姓名、内部主机名等可能遗漏，分享前必须人工复核。

IOC 提取先对全文过滤已识别的秘密，再提取指标、截取上下文，避免私钥跨行或长令牌变成 IOC。可能因此丢失一些真实指标。`--no-redact-context` 会保留原始上下文，属于敏感输出；邮箱仅在 `--include-emails` 时提取，其他个人数据不保证自动移除。域名/TLD 和二进制识别都是启发式。

CSV 使用标准库转义字段，并对疑似公式前缀加单引号。表格软件编辑/另存/重新打开可能丢失保护，按纯文本导入；JSON 保留原始字段值，更适合程序交换。Markdown 对不可信标记转义；第三方渲染器仍应禁用原始 HTML 和主动内容。

文本输入每个文件/标准输入上限 10 MiB；IOC 目录扫描跳过过大/二进制文件和遇到的文件符号链接，stderr 会提示部分跳过情况。不要对来源不明的无限目录或特殊文件运行；未知解析器/样本使用隔离环境。

### 定级与去重

自定义公式见 `references/03-vuln-triage.md`，不等于 CVSS 或 SSVC。未知输入在 `missing` 中列出；运算时未知 EPSS/标志/影响暂用 0，缺失置信度暂用 0.8，不能据此判断低风险。百分号明确换算（`0.5% = 0.005`），CVSS 向量不会自动变成分数。

去重保留中文标题、URL 路径和资源标识大小写，合并来源与证据。状态矛盾时标 `unknown` 并保留 `status_conflicts`；不得选择一个更方便的状态代替复核。端口/组件实例需在资产字段中明确区分。

## 来源与维护

来源记录见 `references/sources.md`。原包的“热门前十/精确 stars”断言缺少随包保存的原始快照，已移除，不能作为质量证明。框架版本、工具参数、漏洞情报与修复版本均应在具体任务中核对官方来源。
