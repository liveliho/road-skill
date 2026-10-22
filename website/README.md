# road-skill 网站

日间 GNOME 桌面布局与 iOS 风格的浮动玻璃工具栏；纯 HTML/CSS/JavaScript，无前端安装步骤，无 CDN、统计或远程模型。网页为视觉转译，不使用 Apple/GTK 原生组件。

## 构建

从仓库根目录运行：

```bash
python tools/build_site.py
python -m http.server 8000 --directory dist/site
```

访问 `http://localhost:8000`。Python 3.10+；仅使用标准库。构建时把明确列出的 Skill Markdown 转成保守 HTML，同时生成 Skill ZIP 和校验文件。修改手册后重新构建即可；不会把任意仓库文件或证据目录发布到网站。

## 功能

- 11 类任务工作流；18 份真实仓库文档、全文搜索、文章目录、收藏与本地完成记录。
- 安装包、SHA-256 校验文件、3 个 Markdown 模板下载。
- 浏览器本地 IOC IPv4/URL/哈希提取、SHA-256 文件校验、常见秘密脱敏、风险优先级试算。
- 明确区分网页的轻量实现与完整 Python CLI；网页不执行终端命令，不做主动网络扫描。
- 日间主题默认、夜间主题、移动导航、键盘搜索（Ctrl/⌘ K）、原生对话框焦点管理、减少动态效果。

浏览器工具输入和文件不上传；收藏、主题、已读状态存储于当前浏览器。存储不可用时降级为当前会话。启发式提取和脱敏可能遗漏，结果需人工复核。文件哈希单文件上限 50 MiB。

## GitHub Pages

`.github/workflows/pages.yml` 从 `main` 构建并发布 `dist/site`。首次使用需在仓库 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**，然后运行 **Deploy documentation website** 工作流。发布成功后站点通常位于 `https://liveliho.github.io/road-skill/`，最终 URL 以部署环境返回值为准。

## 源码

- `index.html`：应用框架与对话框。
- `styles.css`：响应式布局、主题和状态。
- `app.js`：路由、搜索、文档与工具。
- `../tools/build_site.py`：安全 Markdown 转换、文档索引和构建。
- `DESIGN.md`：设计依据与参考来源。
