# Web 与 API 安全测试

> 以证据区分 `confirmed`、`suspected` 和 `exploited`。可定位的代码/配置路径与受控测试可以确认问题，无需在生产上实际利用；证据不足时保留待验证项，不为了进入报告而扩大测试。

## 1. 适用场景

- 授权 Web 应用/API 渗透测试、上线前安全评估。
- 漏洞赏金（严格按项目 scope 和规则）。
- 代码 + 运行时结合的灰盒测试。
- 对扫描器结果做人工验证，降低误报。

不适用：未授权测试、DoS、真实用户数据获取、绕过第三方访问控制。

## 2. 测试前准备

- **授权与范围**：域名/API base URL、环境（dev/staging/prod）、账号、时间窗、禁止动作、速率。
- **账号矩阵**：匿名、普通用户 A、普通用户 B、管理员、只读/受限角色；每类至少一个测试账号。
- **数据**：合成数据；不要用真实客户数据；记录测试数据的创建/清理。
- **工具**：代理（Burp Suite / Caido / ZAP）、`curl`、浏览器、OpenAPI/Swagger、源码访问（如获授权）。
- **基线**：正常请求的状态码、长度、时间、关键 header；记录 WAF/CDN 行为。

```bash
# 只读基线：确认可达、TLS、重定向、header
curl -sS -D - -o /dev/null "https://staging.example.com/" \
  -H 'User-Agent: authorized-security-review/1.0'

# 带测试账号的请求：用环境变量，避免把 token 写进历史
curl -sS -D - "https://staging.example.com/api/v1/me" \
  -H "Authorization: Bearer $TEST_TOKEN"
```

## 3. 先建图，再测试

### 3.1 应用地图

- 入口：页面、API 端点、GraphQL、WebSocket、移动端 API、第三方回调。
- 身份：登录、注册、找回密码、MFA、OAuth/OIDC、SSO、API key、JWT。
- 角色与权限：匿名/用户/管理员/租户；前端隐藏不等于后端拒绝。
- 数据流：上传、导出、搜索、分享、邀请、支付、通知、集成。
- 信任边界：浏览器→API、API→数据库、API→内部服务、webhook、文件处理、模板渲染。

### 3.2 API 契约

有 OpenAPI/Swagger/Postman 时，先枚举所有方法和参数，再抽样验证：

```bash
# 例：从 OpenAPI 提取端点（jq 可用时）
curl -sS https://staging.example.com/openapi.json \
  | jq -r '.paths | keys[]'
```

没有契约时，用代理录制正常流程，按资源/动作归类；不要盲目目录爆破。

## 4. 检查清单

按 OWASP Top 10 (2021) 与 OWASP API Security Top 10 (2023) 组织，但**一个发现只归一个主类**。

### 4.1 访问控制（最高优先）

- 水平越权（IDOR）：A 的 ID 换成 B 的 ID，后端是否校验归属？
- 垂直越权：普通用户调用管理员端点/字段。
- 租户隔离：跨 tenant/org 读写。
- 方法/路径绕过：`GET` vs `POST`、大小写、尾斜杠、`X-HTTP-Method-Override`、版本降级。
- 批量赋值：`role`、`is_admin`、`tenant_id`、`owner_id` 是否被接受。
- GraphQL：字段级授权、嵌套对象、 introspection 暴露（本身是信息泄露，不一定是漏洞）。

**安全验证**：用两个测试账号、同一资源、最小请求；只读取测试数据。不要遍历真实用户 ID。

### 4.2 认证与会话

- 登录枚举（响应差异、时间差）；限速，避免口令爆破。
- 会话固定、Cookie 属性（Secure/HttpOnly/SameSite）、退出后失效。
- JWT：算法混淆、`none`、弱密钥、`kid` 注入、过期/受众/签发者校验。只在自己的测试 token 上验证。
- OAuth/OIDC：`state`、PKCE、redirect_uri 白名单、token 泄露、账号绑定。
- 密码重置：token 可预测、Host header 投毒、邮件链接泄露。不要重置真实用户。

### 4.3 注入与输入处理

- SQL/NoSQL/LDAP/命令/模板注入：用**无害 canary**（如 `'`、时间延迟 1 秒、算术表达式）证明解析差异，不执行系统命令、不导数据。
- XSS：用 `alert(1)` 或唯一字符串证明执行；存储型测试用测试账号，避免影响他人。
- SSRF：让服务请求你控制的**授权回调域名**，记录 DNS/HTTP 命中；不要扫内网、不要读云元数据。
- XXE/反序列化：优先在本地复现或测试环境；不加载真实利用链。
- 文件上传：测试类型/大小/路径/内容校验；上传无害文件（如唯一文本），不传 webshell。
- 路径遍历：只读测试文件（如应用自己的公开文件），不读 `/etc/shadow` 等敏感文件。

### 4.4 业务逻辑

- 价格/数量/优惠券/退款/积分：用测试商品和测试账户；不触发真实支付。
- 竞态：先审查代码/事务边界，需动态验证时按 RoE 在测试环境逐步增加并发；固定 5–10 次并不保证安全。
- 工作流绕过：跳过步骤、重放请求、修改状态机；记录前后状态。
- 邀请/分享：确认 token 作用域、过期、撤销。

### 4.5 其它

- 安全 header/CSP/CORS：单独作为 hardening observation，不夸大为“高危漏洞”。
- 错误处理：堆栈、SQL 错误、内部主机名、调试端点。
- 缓存：敏感响应是否被 CDN/代理缓存；用测试账号验证，避免污染真实缓存。
- 速率限制：低量验证是否存在；不做压力测试。
- 组件漏洞：版本确认 + 可达性 + 已知漏洞；不要只凭 banner。

## 5. 证据与复现

每个 finding 记录：

```text
ID: WEB-003
Title: 普通用户可读取其他租户的发票 PDF
Asset: https://staging.example.com/api/v1/invoices/{id}
Status: confirmed
Severity: medium (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N, 6.5)
Account: userA@test / tenant A; userB@test / tenant B
Request: GET /api/v1/invoices/INV-B-1001 (userA token)
Response: 200, application/pdf, 12 KB, invoice for tenant B
Control: same request with userB token -> 200; with anonymous -> 401
Impact: 可枚举/读取其他租户发票，含地址与金额
Evidence: E-021 (request/response), E-022 (tenant IDs)
Remediation: 在查询层强制 tenant_id = current_tenant；增加回归测试
Retest: 修复后 userA 请求返回 404/403；userB 正常
```

证据要求：

- 原始请求/响应（脱敏 token/Cookie）。
- 时间、账号/角色、目标环境。
- 对照请求（负例）和最小化步骤。
- 不把“扫描器 report”当复现步骤。
- 截图只作辅助，保留文本。

## 6. 误报与干扰因素

- WAF 拦截返回 403，不代表漏洞不存在；换授权测试路径/环境验证，不要绕过 WAF。
- CDN 缓存返回旧页面；加唯一 query/使用测试环境。
- 前端隐藏按钮不等于后端无权限；直接测 API。
- 401/403 的差异可能来自路由不存在、认证失败、权限拒绝；看响应体和日志（如可用）。
- 200 但内容为空/软 404；比较基线长度和业务字段。
- 时间延迟可能来自网络/GC；多次测量，使用统计而非单次。
- 扫描器把“缺少 header”报成“高危”；按实际影响降级。

## 7. 修复建议的写法

不要只写“加强输入校验”。给出可执行改法：

- 访问控制：在数据访问层加 `tenant_id`/`owner_id` 约束；默认拒绝；为每个端点写授权测试。
- 注入：参数化查询/预编译；允许列表；输出编码；禁用危险反序列化。
- SSRF：目标允许列表、禁用内网/元数据、DNS 解析后校验、独立出口代理。
- 上传：类型/内容/大小校验、随机文件名、存储与执行分离、病毒扫描。
- JWT：固定算法、校验 `iss/aud/exp`、强密钥/轮换、撤销列表。
- 业务逻辑：服务端状态机、幂等键、事务/锁、限额。

## 8. 工具与命令

```bash
# 代理/重放：Burp Suite / Caido / ZAP（GUI）
# 轻量请求：curl/httpie
# 浏览器自动化：Playwright（授权登录流程）
# 代码侧：Semgrep / CodeQL（见 09）
#  API 契约：OpenAPI/Swagger/Postman

# 安全 header 快速检查（本 skill 自带，需授权 + scope）
python scripts/secops.py http https://staging.example.com \
  --scope-file scope.txt --i-have-authorization --format md
```

不要把 `nuclei -tags cve` 之类的大范围模板直接打生产；先确认模板影响、速率和 scope。

## 9. 交付

- 发现表：ID、标题、资产、状态、severity、priority、CWE/OWASP、证据、修复。
- 每个 confirmed 发现：最小复现、影响、前置条件、对照、证据。
- 未确认项：为什么没确认、还缺什么、是否建议人工复核。
- 覆盖说明：测了哪些角色/端点/漏洞类；没测什么（如未授权无法测的管理后台）。
- 修复优先级：先访问控制/认证/注入，再 hardening。

## 10. 设计依据

- **Shannon**：源码分析 + 运行时验证 + “只有可复现 PoC 才进报告”；本手册采用 `confirmed/exploited` 分级和最小 PoC。
- **Strix**：OWASP Top 10 覆盖、浏览器/代理/代码分析组合；本手册把“多工具”收敛为“一个证据链”。
- **Anthropic-Cybersecurity-Skills**：API/Web 原子技能拆分；本手册用检查清单路由，不堆砌 payload。

## 11. 参考

- OWASP Top 10: <https://owasp.org/Top10/>
- OWASP API Security Top 10: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP WSTG: <https://owasp.org/www-project-web-security-testing-guide/>
- PortSwigger Web Security Academy: <https://portswigger.net/web-security>
