# road-skill：网络安全运营 Skill

面向 AI agent 的授权安全审计、漏洞定级、流量/样本分析、事件响应与加固工作流，附带零依赖 Python 工具。入口：[SKILL.md](.dsh/skills/cybersecurity-ops/SKILL.md)。

本项目包含可安装的 Skill 包与纯静态网站。GitHub Actions 在 Windows/Linux 上运行测试，通过后构建安装包；版本包见 [Releases](https://github.com/liveliho/road-skill/releases)。

## 网站工作台

网站提供 11 类工作流、18 份仓库文档的全文搜索、收藏与阅读记录、3 份 Markdown 模板下载，以及浏览器本地 IOC 提取、SHA-256 校验、脱敏和优先级试算。日间 Linux 工作空间搭配 iOS 风格的浮动玻璃工具栏，支持手机、平板和夜间主题；不需要后台或付费 API。

网站入口与部署状态见 [GitHub Pages 发布工作流](https://github.com/liveliho/road-skill/actions/workflows/pages.yml)。网站源码位于 [`website/`](website/README.md)，文档直接从 Skill 的 Markdown 源文件构建。

```bash
python tools/build_site.py
python -m http.server 8000 --directory dist/site
```

访问 `http://localhost:8000`。Pages 配置为 GitHub Actions 后，提交到 `main` 会自动构建发布。网页本地工具是独立轻量实现，不在浏览器中运行 Python CLI，不做主动扫描。

## 审计与修复

2026-10-22 审计修复了 HTTP 地址校验与连接不一致、scope 静默扩大、秘密脱敏遗漏、CSV/Markdown 输出注入、去重丢失发现及评分输入错误，并补充不可信证据的指令边界。

详见 [安全审计报告](docs/SECURITY-AUDIT-2026-10-22.md)，其中列出触发条件、证据、修复与剩余限制。测试结果以 [GitHub Actions](https://github.com/liveliho/road-skill/actions) 为准。

## 安装

下载 Release 中的 ZIP，解压后得到完整 `cybersecurity-ops/` 文件夹，放到所用 agent 的技能目录。例如 DSH 项目目录 `.dsh/skills/`；其他宿主按其技能目录配置安装。是否成功加载以客户端实际发现结果为准，不会自动授予工具权限。

也可以从源码复制：

```powershell
git clone https://github.com/liveliho/road-skill.git
# 在克隆目录中，将完整 skill 文件夹复制到你的目标项目
Copy-Item -Recurse .dsh/skills/cybersecurity-ops <目标项目>/.dsh/skills/
```

ZIP 附有 SHA-256 文件。Windows 可用 `Get-FileHash <文件.zip> -Algorithm SHA256` 核对；校验值用于完整性检查，不等于数字签名。

## 本地使用

需要 Python 3.10+，运行工具与测试均不需要安装第三方 Python 包。

```powershell
python -m unittest discover -s .dsh/skills/cybersecurity-ops/scripts -p "test_*.py" -v
python -m unittest discover -s tests -p "test_*.py" -v
python tools/build_release.py

cd .dsh/skills/cybersecurity-ops
python scripts/secops.py triage assets/triage-example.csv --format md
python scripts/secops.py ioc evidence.txt --format json
python scripts/secops.py redact report.md --pii --output report-share.md
```

仅 `http` 子命令联网。它需要明确授权和 scope，默认 HEAD，保留 Host/SNI 与证书验证，每跳直接连接校验后的数字 IP，不使用环境代理。详见 [工具说明](.dsh/skills/cybersecurity-ops/README.md)。

## 使用边界

- 只在授权范围内开展安全工作；脚本开关不能证明授权、资产归属或时间窗有效。
- scope 文件仅约束主机/IP，不能表达端口、路径或排除规则；操作者必须核对具体请求。
- 脱敏、IOC 识别和评分是辅助工具，需要人工复核；不应凭扫描命中或低分作最终结论。
- 仓库与安装包不应包含真实凭据、样本、PCAP、客户报告或原始取证数据。
