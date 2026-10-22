# 资产发现、OSINT 与攻击面

> 目标不是“收集尽可能多的数据”，而是建立**可验证、可去重、可解释的资产图**。SpiderFoot 的模块化 pivot、Sherlock/Maigret 的用户名枚举、Shodan/Censys 的暴露面数据，都只是图的输入，不是结论。

## 1. 适用场景

- 授权渗透测试的前期侦察。
- 企业外部攻击面梳理（域名、子域、IP、证书、云存储、代码泄露）。
- 钓鱼/欺诈/冒充域名的调查（防御侧）。
- 事件响应中确认“这个域名/账号是不是我们的”。

不适用：对未授权目标做画像、人肉、骚扰、绕过隐私设置。

## 2. 输入与输出

**输入种子**（至少一个）：

- 根域名（`example.com`）、已知子域、IP/CIDR、ASN。
- 组织名、品牌名、产品名。
- 公开邮箱、用户名、代码仓库、移动应用包名。
- 证书、WHOIS/RDAP 记录、公开云存储桶名。

**输出资产图**，每个实体至少包含：

```yaml
entity: api.example.com
type: hostname            # domain | hostname | ip | cidr | asn | cert | cloud_bucket | repo | identity
source: [crt.sh, dns, http]
first_seen: 2026-10-01T00:00:00Z
last_seen: 2026-10-22T08:00:00Z
confidence: high          # high | medium | low
state: resolved           # candidate | resolved | verified | owned | excluded
evidence: E-012
notes: "CNAME to CDN; origin unknown"
```

不要把“解析成功”当成“属于客户”：CDN、停车场、失效域名、通配符 DNS 都会制造假资产。

## 3. 被动优先

### 3.1 域名与证书

```bash
# RDAP（比传统 whois 更结构化；注意隐私 redaction）
curl -sS "https://rdap.org/domain/example.com" | jq .

# 证书透明日志：找历史/当前子域
curl -sS "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sort -u

# DNS 记录（被动查询）
dig +short example.com A
dig +short example.com MX
dig +short example.com TXT
dig +short _dmarc.example.com TXT
```

`crt.sh` 可能很慢或返回重复/通配符；用 `*.example.com` 过滤并去重。证书里的名字不等于当前仍在服务。

### 3.2 子域枚举（先被动）

```bash
# subfinder：聚合被动源；-all 会增加来源和噪声
subfinder -d example.com -all -silent -o subs.txt

# amass：被动模式，避免主动爆破
amass enum -passive -d example.com -o amass.txt

# theHarvester：公开源；限制来源，避免触发第三方限制
theHarvester -d example.com -b duckduckgo,bing -l 100 -f harvester
```

合并后：

```bash
# 只保留授权根域及其子域，防止把范围外主机带进后续主动测试
sort -u subs.txt amass.txt | grep -E '(^|\.)example\.com$' > candidates.txt
```

**主动爆破**（`dnsx`、`massdns`、`amass active`）必须获得授权，并限制速率；不要对根域做大规模字典轰炸。

### 3.3 互联网暴露面

```bash
# Shodan/Censys 查询是第三方已扫描数据，通常算被动；
# 但不要把 API key 写进 shell history。
shodan search 'ssl:"example.com"'
shodan host 203.0.113.10

# Censys CLI（如已安装并配置）
censys search 'services.tls.certificates.leaf_data.subject.common_name: example.com'
```

查询语法随平台版本变化；以平台文档为准。把结果当作“某时间点的观察”，不要当作实时资产。

### 3.4 代码与云存储泄露

```bash
# GitHub 代码搜索 API 需要认证；token 从环境变量读取，不要写进命令历史。
# 只查公开仓库，遵守平台条款。关键词示例：org name + internal / password / token / example.com
curl -sS -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=%22example.com%22+org:example" | jq .

# 公开 S3 桶检查：只做 GET/List，不写入、不枚举他人私有对象
curl -sS -o /dev/null -w '%{http_code}\n' "https://example-assets.s3.amazonaws.com/"
```

发现凭据时：停止扩散、记录位置、通知 owner、立即轮换；不要在报告中贴出完整凭据。

### 3.5 用户名与身份（谨慎）

Sherlock/Maigret 通过用户名在大量站点上查找公开资料。它们适合**授权调查**（例如确认冒充账号），不适合对人做全面画像。

```bash
sherlock user_name --timeout 10 --print-found
maigret user_name --timeout 10 --no-recursion --top-sites 100
```

规则：

- 只查与授权事件相关的公开账号；不绕过登录、不抓取私密内容。
- 结果必须人工打开确认；不同站点可能返回 200 的“未找到”页面。
- 记录 URL、截图、时间；不要把“同名”当“同一人”。
- 不在报告中暴露无关的个人信息。

## 4. 解析与验证

对每个候选资产：

1. **解析**：A/AAAA/CNAME；记录解析链和 TTL。
2. **证书**：SAN、CN、签发者、有效期；是否与已知资产共享证书。
3. **HTTP 指纹**：标题、favicon 哈希、`Server`、`X-Powered-By`、登录页、错误页。
4. **归属**：WHOIS/RDAP、云资源标签、证书组织、页面版权/备案、客户确认。
5. **状态**：`candidate → resolved → verified → owned/excluded`。

```bash
# 批量解析，保留失败原因
dnsx -l candidates.txt -a -resp -o resolved.txt

# HTTP 指纹（授权范围内，限速）
httpx -l resolved.txt -title -tech-detect -status-code -tls-grab -rate-limit 5 -o http.txt

# TLS 证书信息
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

`httpx`/`nuclei` 等工具会主动请求目标；确认授权和速率后再跑。

## 5. 去重与实体图

常见重复：

- `www.example.com`、`example.com`、`https://example.com/` 指向同一站点。
- 同一 IP 上的多个 vhost；同一 CDN 边缘 IP 上的大量域名。
- 证书 SAN 里的通配符和具体子域。
- 大小写、末尾点、IDN/punycode、默认端口。

规范化建议：

- 主机名小写、去掉末尾点；URL 去掉默认端口和 fragment；保留 path 用于指纹但不要用于资产去重。
- IP 用标准压缩形式；IPv6 小写。
- 证书用 SHA-256 指纹；文件用 SHA-256；页面用标题 + favicon 哈希 + 关键 header 组合。
- 每个实体保留 `source` 和 `first_seen/last_seen`，不要覆盖历史。

可以用 `scripts/secops.py ioc` 从扫描输出/笔记中抽取域名、IP、URL、哈希，再导入表格：

```bash
python scripts/secops.py ioc recon-notes.txt --format csv --output iocs.csv
```

## 6. 攻击面优先级

不要按“资产数量”汇报，按**可达性 × 敏感性 × 暴露类型**排序：

| 信号 | 为什么重要 | 下一步 |
|---|---|---|
| 互联网可达的管理后台/VPN/CI | 直接入口 | 授权验证认证/补丁/暴露 |
| 过期证书/域名 | 劫持、冒充 | 确认归属、续期/赎回 |
| 云存储可列目录 | 数据泄露 | 只读确认、通知 owner、修复 ACL |
| 源代码/密钥泄露 | 供应链/横向 | 轮换、撤稿、排查使用 |
| 子域接管（dangling CNAME） | 可信域名被控 | 验证 CNAME 目标、移除记录 |
| 旧版本/已知漏洞 | 可利用性 | 版本确认、补丁/缓解、KEV/EPSS |
| 影子资产（未知部门） | 无监控 | 找到 owner、纳管 |

对“子域接管”先做被动证据核验：CNAME、厂商响应、资源归属和客户确认。注册/认领资源会改变状态；只有现有授权明确覆盖且厂商允许时，才使用受控标识并准备清理。没有这类授权时保留 `suspected`，不通过抢注来追求 `confirmed`。

## 7. 常见误报

- **通配符 DNS**：随机子域也解析；用随机标签做对照。
- **CDN/WAF**：所有子域解析到同一组边缘 IP；不能据此判断同源。
- **停车场/抢注域名**：页面相似但归属不同；查 RDAP/证书/备案。
- **软 404**：所有路径返回 200；比较状态、长度、标题、内容哈希。
- **证书共享**：共享证书不等于同一组织；看 SAN 范围和组织验证。
- **用户名同名**：不同平台、不同人；必须看头像、简介、活动、交叉链接。
- **旧扫描数据**：Shodan/Censys 结果可能过期；关键结论要实时复核（授权后）。

## 8. 交付格式

```markdown
## 攻击面摘要
- 根域：example.com
- 已验证资产：42 个主机名 / 7 个 IP / 3 个云存储
- 高优先暴露：5 个（管理入口 2、过期证书 1、可列目录 1、疑似接管 1）
- 未确认/排除：18 个（CDN 共享、停车场、重复）

## 资产表
| 资产 | 类型 | 状态 | 归属置信度 | 暴露 | 证据 | 下一步 |
...

## 方法
- 被动源：crt.sh、RDAP、subfinder、Shodan
- 主动验证：dnsx/httpx（授权号、速率、时间窗）
- 限制：未做端口扫描；CDN 后源站未知
```

## 9. 设计依据

- **SpiderFoot**：模块化、publisher/subscriber 式实体 pivot；本手册把“实体图 + 来源 + 时间”作为核心数据结构。
- **Sherlock/Maigret**：用户名跨站点发现；本手册强调人工确认、同名不等于同一人、隐私边界。
- **Shodan/Censys**：外部暴露面；本手册要求把第三方扫描数据当作有时间戳的观察。
- **Anthropic-Cybersecurity-Skills**：progressive disclosure；本手册只保留侦察阶段需要的实体、验证和误报规则。

## 10. 参考

- OWASP Amass: <https://github.com/owasp-amass/amass>
- ProjectDiscovery subfinder: <https://github.com/projectdiscovery/subfinder>
- theHarvester: <https://github.com/laramies/theHarvester>
- SpiderFoot: <https://github.com/smicallef/spiderfoot>
- Sherlock: <https://github.com/sherlock-project/sherlock>
- Maigret: <https://github.com/soxoj/maigret>
- crt.sh: <https://crt.sh/>
- RDAP: <https://rdap.org/>
