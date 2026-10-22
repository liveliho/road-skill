# road-skill 设计约定

为使用安全 Skill 的学生与安全从业者，在桌面和手机上完成手册查阅、工作流路由与本地证据整理，采用 GNOME 式工作空间和少量 iOS 风格玻璃层。事实以仓库内容为准，不展示真实资产、告警或未经验证的运营数据。

## 结构

侧栏负责跨任务导航；正文负责阅读与操作；顶部玻璃工具栏负责位置与全局主题；终端只展示可复制的安装命令。对比过单页宣传页与工具工作台，选后者，因为仓库核心是可安装 Skill、11 类路由及离线 CLI。

## 视觉

背景 #F6F8FA，内容 #FFFFFF，侧栏 #F0F3F6，正文 #202E40，辅助文字 #637387，动作 #2466D8。玻璃仅放顶部工具栏和模态遮罩；正文维持实色。网页借鉴 iOS 的材质和圆角，不声称使用 Apple 官方 iOS 27 网页组件。

间距 4/8/12/16/24/32；按钮 9px、内容面板 14–20px 圆角；正文文档 15px/1.9（手机保持 15px）；常规导航 11–14px。代码使用系统等宽字体，正文系统中文字体，不加载远程字体。小屏重新排序，320px 保留全部核心操作。

## 细节与验收

1. 文档搜索 → 不离开当前任务找到手册 → Ctrl/⌘ K 原生 dialog、全文索引、空状态 → 搜索、Escape 与焦点恢复实测。
2. 本地工具 → 证据无需上传 → 浏览器内存处理，用户输入用 textContent → 示例、错误、下载和隐私说明检查。
3. 任务入口 → 清楚区分文档与操作 → 11 个真实手册、收藏、已读记录 → 手机与桌面检查导航与下载路径。

## 来源与选择

2026-10-22 查阅以下官方项目。不安装任何第三方 JS/CSS 库，也未复制其源码或图标；图标为本项目原创 SVG。

| 来源 | 用途 | 实现取舍 |
|---|---|---|
| [GNOME HIG / libadwaita](https://developer.gnome.org/hig/patterns/nav/sidebars.html) | 稳定侧栏、工具栏、响应式分栏 | GTK 为原生库，网页仅转译布局 |
| [Apple Materials](https://developer.apple.com/design/human-interface-guidelines/materials) | 内容与浮动材料分工 | CSS 玻璃，非 Apple 原生材料 |
| [Radix Primitives](https://github.com/radix-ui/primitives)（MIT） | 评估可访问交互原语 | 静态站无 React，改用浏览器原生 dialog |
| [Nextra](https://github.com/shuding/nextra) | 评估文档阅读与目录布局 | 不引入 Next.js，构建时生成静态文档 |
| [daisyUI](https://github.com/saadeghi/daisyui) | 评估主题、分段控件 | 使用项目自己的 CSS token，避免整套主题叠加 |

不加载 CDN，不增加登录、后台、遥测或付费服务。外部资源仅在用户主动打开来源链接时访问。
