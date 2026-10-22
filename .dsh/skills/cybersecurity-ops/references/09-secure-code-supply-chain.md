# 安全代码审查与软件供应链

> 代码审计的目标不是“找出所有危险函数”，而是证明**一条从输入到影响的真实路径**。供应链安全的目标不是“零依赖”，而是让依赖、构建产物和发布过程可验证、可追溯。

## 1. 适用场景

- 代码审计/PR 安全 review。
- SAST/SCA/密钥扫描结果验证与去重。
- SBOM、依赖升级、CI/CD 供应链加固。
- 开源组件漏洞/恶意包 triage。

## 2. 先画信任边界

- 入口：HTTP 参数/header/cookie、文件上传、消息队列、webhook、CLI、导入文件。
- 身份：认证中间件、会话、JWT、OAuth、服务间 mTLS。
- 数据：数据库、对象存储、缓存、日志、第三方 API。
- 执行：模板、命令、反序列化、表达式、SQL、文件系统。
- 边界：浏览器→服务、服务→服务、服务→数据、CI→云、依赖→构建。

数据流问题：

```text
source（用户可控） -> transform（校验/编码/拼接） -> sink（危险操作）
```

只有 source 到 sink 可达，且中间校验不足，才是可确认漏洞。

## 3. 审查清单

### 3.1 授权与身份

- 每个端点是否默认拒绝？是否有集中式授权？
- 对象级权限（owner/tenant）是否在查询层强制？
- 管理员端点是否单独鉴权？前端隐藏不是控制。
- JWT：算法固定、`iss/aud/exp` 校验、密钥强度、撤销。
- 服务间：mTLS/短期 token；不要共享长期密钥。

### 3.2 输入与输出

- SQL：参数化；ORM 的 raw/拼接；`ORDER BY`/列名白名单。
- 命令：避免 shell；参数数组；允许列表。
- 模板：用户输入不进模板源码；沙箱/上下文转义。
- 反序列化：避免原生/PHP/Python pickle/Java 原生；允许列表/签名。
- 文件：路径规范化、根目录限制、类型/内容校验、随机名、存储与执行分离。
- SSRF：目标允许列表、禁内网/元数据、DNS 解析后校验、独立出口。
- XSS：按上下文输出编码；CSP 作为纵深。
- 开放重定向/URL 拼接：允许列表。

### 3.3 加密与密钥

- 不要自创加密；用成熟库/AEAD。
- 密钥不在代码/镜像/日志；用 KMS/Vault/secret manager。
- 随机数用 CSPRNG；不要 `Math.random()`/时间戳做 token。
- 密码哈希用 Argon2id/bcrypt/scrypt + 盐；不要 MD5/SHA-1。
- TLS 校验开启；不要 `verify=False`/`InsecureSkipVerify`。
- 密钥轮换/撤销方案。

### 3.4 业务逻辑

- 价格/数量/折扣/退款由服务端计算。
- 状态机服务端强制；幂等键；防重放。
- 竞态：事务/锁/唯一约束；不要只靠前端按钮禁用。
- 多租户：所有查询带 tenant 条件；测试跨租户。

### 3.5 日志与隐私

- 不记录密码/token/完整卡号/敏感 PII。
- 日志注入：换行/控制字符转义。
- 审计日志：谁、何时、对什么、结果；防篡改。
- 错误信息不泄露堆栈/内部路径。

## 4. 工具链

这些命令是版本相关的示例，执行前核对工具官方文档、目标范围、遥测和出网设置。`--config auto`、规则下载、漏洞数据库更新可能联网；不要把“本地扫描”理解为不会向外发送数据。先检查构建/安装钩子，未受信任仓库不要直接安装依赖或运行测试。

```bash
# SAST（规则需按语言/框架调整）
semgrep --config auto --sarif --output semgrep.sarif .

# CodeQL（需数据库；以官方 CLI 为准）
codeql database create db --language=javascript
codeql database analyze db codeql/javascript-queries:codeql-suites/javascript-security-extended.qls \
  --format=sarif-latest --output=codeql.sarif

# 密钥扫描（工作区/历史）
gitleaks detect --source . --report-format sarif --report-path gitleaks.sarif

# 依赖/镜像/IaC
trivy fs --scanners vuln,secret,misconfig .
osv-scanner --lockfile=package-lock.json
npm audit --json
pip-audit -r requirements.txt

# SBOM
syft dir:. -o spdx-json > sbom.spdx.json
grype sbom:sbom.spdx.json
```

原则：

- 工具输出是候选；先看数据流/可达性，再定级。
- 不要为了“清零”而关闭规则；记录 risk acceptance。
- 扫描器要固定版本/规则集，保证可复现。
- CI 中 SARIF 上传到代码扫描；不要把 token 打到日志。

## 5. 依赖与供应链

### 5.1 依赖风险

- 已知漏洞（CVE）、EOL、无人维护、恶意包、typosquatting、依赖混淆。
- 传递依赖、锁文件漂移、浮动版本、私有 registry 配置。
- 安装脚本（`postinstall`）、二进制下载、git 依赖。

### 5.2 验证

- 锁文件 + 完整性哈希；CI 使用 `npm ci`/`pip install --require-hashes` 等。
- 依赖来源固定 registry；私有包 scope 配置；防止 dependency confusion。
- 新依赖审查：维护者、下载量、最近提交、许可证、安装脚本。
- 漏洞 triage：可达性、是否运行、是否有补丁；不要只看 CVSS。

### 5.3 构建与发布

- **SLSA**：构建平台生成 provenance；消费者验证。
- **Sigstore/cosign**：签名镜像/制品；准入验证。
- **SBOM**：SPDX/CycloneDX；随制品保存；能定位组件。
- **可复现构建**：固定工具链/依赖/时间；至少可追溯。
- **制品仓库**：不可变 tag/digest；保留审计。

```bash
# 签名/验证示例（cosign）
cosign sign --key cosign.key registry.example.com/app@sha256:...
cosign verify --key cosign.pub registry.example.com/app@sha256:...
```

## 6. CI/CD 加固

- 最小权限 `GITHUB_TOKEN`/CI token；按 job 授权。
- 优先 OIDC 联合云角色，替代长期 AK/SK。
- 第三方 Action 固定到 commit SHA；不要用浮动 tag。
- 避免 `pull_request_target` 直接 checkout/执行不可信 PR 代码并携带 secrets。
- secrets 只在需要的 job/环境；mask；不打印。
- 构建与部署分离；生产部署需审批/环境门禁。
- 保护分支、required review、签名提交（按组织要求）。
- 缓存/制品完整性；不要从不可信源恢复缓存。

## 7. 发现验证

一个代码 finding 至少包含：

```text
ID: CODE-007
Title: 订单导出接口存在租户越权
File: app/api/orders.py:142
Source: GET /api/orders/export?tenant_id=...
Sink: db.session.query(Order).filter(Order.tenant_id == tenant_id)
Missing control: tenant_id 来自请求参数，未与当前用户 tenant 比对
Reachability: 任意登录用户可调用；无需管理员
Proof: 测试账号 A 请求 tenant B 的导出，返回 B 的 CSV（E-031）
Fix: 从会话取 tenant_id；查询强制过滤；加回归测试
```

不要只写“使用了 `eval`”或“字符串拼接 SQL”；要证明可控输入和影响。

## 8. 常见坑

- 把 SAST 命中当 confirmed；没有数据流/可达性。
- 忽略框架的自动转义/参数化；误报。
- 只看直接依赖，忽略传递依赖/基础镜像。
- 锁文件存在但 CI 用 `npm install` 而不是 `npm ci`。
- 签名了镜像但准入不验证；等于没签。
- SBOM 生成了但从不使用；无法定位受影响制品。
- CI 日志打印 env/secrets；缓存污染。
- 为了通过扫描而加 `# nosec`/忽略规则，没有记录理由。
- 依赖升级只看版本号，不跑测试/不验证行为。

## 9. 交付

- 代码 finding：文件/行、source→sink、可达性、证据、修复 patch/建议、测试。
- 依赖 finding：组件/版本、CVE、可达性、修复版本、是否 breaking。
- 供应链：SBOM 位置、签名/验证状态、CI 风险、改进项。
- 优先级：按 03 的 severity/priority 规则，不单独造一套。

## 10. 参考

- OWASP Top 10: <https://owasp.org/Top10/>
- OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Dependency-Check: <https://owasp.org/www-project-dependency-check/>
- Semgrep: <https://semgrep.dev/docs/>
- CodeQL: <https://codeql.github.com/docs/>
- Gitleaks: <https://github.com/gitleaks/gitleaks>
- SLSA: <https://slsa.dev/>
- Sigstore: <https://www.sigstore.dev/>
- OpenSSF Scorecard: <https://github.com/ossf/scorecard>
