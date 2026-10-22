/* road-skill: no network clients, analytics, remote dependencies or shell execution. */
(() => {
  'use strict';
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const main = $('#main');
  const docs = window.ROAD_DOCS || [];
  const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
  const storage = {
    get(key, fallback) { try { const value = JSON.parse(localStorage.getItem('road-skill:' + key)); return value ?? fallback; } catch (_) { return fallback; } },
    set(key, value) { try { localStorage.setItem('road-skill:' + key, JSON.stringify(value)); } catch (_) { /* session-only */ } }
  };
  let saved = storage.get('saved', []); if (!Array.isArray(saved)) saved = [];
  let read = storage.get('read', []); if (!Array.isArray(read)) read = [];
  let workflowCategory = 'all', workflowQuery = '';
  let resultText = '', resultKind = 'json', toastTimer;
  const command = 'git clone https://github.com/liveliho/road-skill.git';
  const svgPaths = {
    dashboard:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    workflow:'<rect x="3" y="3" width="6" height="6" rx="1.5"/><rect x="15" y="15" width="6" height="6" rx="1.5"/><path d="M6 9v6a3 3 0 0 0 3 3h6M9 6h6a3 3 0 0 1 3 3v6"/>',
    terminal:'<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    book:'<path d="M12 5c-3-2-6-2-9-1v15c3-1 6-1 9 1 3-2 6-2 9-1V4c-3-1-6-1-9 1zm0 0v15"/>',
    bookmark:'<path d="M6 5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16l-6-4-6 4z"/>',
    download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    shield:'<path d="M12 2 3.5 6v6c0 5 5 8.5 8.5 10 3.5-1.5 8.5-5 8.5-10V6z"/><path d="m8 12 3 3 5-6"/>',
    files:'<rect x="7" y="6" width="14" height="16" rx="2"/><path d="M17 6V4a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h2m4-7h6m-6 4h6"/>',
    lock:'<rect x="4" y="10" width="16" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
    github:'<path d="M9 19c-4 1-4-2-6-2m12 5v-4c0-1 .2-1.7-.6-2.4 3.2-.4 6.6-1.5 6.6-7 0-1.5-.5-2.7-1.4-3.7.1-.4.6-1.9-.2-3.9 0 0-1.2-.4-4 1.5a14 14 0 0 0-7 0C5.6.6 4.4 1 4.4 1c-.8 2-.3 3.5-.2 3.9C3.3 5.9 2.8 7.1 2.8 8.6c0 5.5 3.4 6.6 6.6 7-.7.6-.6 1.4-.6 2.4v4" transform="translate(1 0) scale(.93)"/>',
    search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
    moon:'<path d="M20.5 13.5A9 9 0 0 1 10.5 3a9 9 0 1 0 10 10.5z"/>',
    menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',
    close:'<path d="m6 6 12 12M6 18 18 6"/>',
    folder:'<path d="M3 7V5a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zm0 1h18"/>',
    arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
    back:'<path d="M20 12H4m6-6-6 6 6 6"/>',
    external:'<path d="M14 3h7v7m0-7L10 14M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
    copy:'<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
    check:'<path d="m5 12 4 4L19 6"/>',
    globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    layers:'<path d="m12 2 10 5-10 5L2 7zm-9 10 9 5 9-5M3 17l9 5 9-5"/>',
    activity:'<path d="M2 12h4l3-8 5 16 3-8h5"/>',
    bug:'<rect x="7" y="7" width="10" height="13" rx="5"/><path d="m9 7-2-4m8 4 2-4M3 10h4m10 0h4M2 15h5m10 0h5M4 21l4-3m8 0 4 3m-8-11v8"/>',
    cloud:'<path d="M6 18a5 5 0 0 1-1-10 7 7 0 0 1 13-1 5.5 5.5 0 0 1 .5 11z"/>',
    code:'<path d="m8 6-6 6 6 6m8-12 6 6-6 6M14 3l-4 18"/>',
    hash:'<path d="M10 3 6 21M18 3l-4 18M3 9h18M2 15h18"/>',
    filter:'<path d="M3 4h18l-7 8v7l-4 2v-9z"/>',
    clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
    file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zm0 0v6h6M8 13h8m-8 4h6"/>',
    spark:'<path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z"/>',
    history:'<path d="M3 10a9 9 0 1 1 1.5 7M3 3v7h7m2-3v5l3 2"/>',
  };
  function icon(name) { return '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">' + (svgPaths[name] || svgPaths.file) + '</svg>'; }
  function hydrate(root = document) { $$('[data-icon]', root).forEach(el => { el.innerHTML = icon(el.dataset.icon); }); }
  const flows = [
    {id:'scope',num:'00',title:'授权与范围',desc:'确认资产、允许动作与停止条件，为每一步建立清晰边界。',icon:'shield',color:'slate',category:'assess',tag:'任务准备',output:'Scope / RoE'},
    {id:'recon',num:'01',title:'资产发现与 OSINT',desc:'从已有线索出发，整理资产关系、公开信息与暴露面。',icon:'globe',color:'mint',category:'assess',tag:'资产侦察',output:'资产清单'},
    {id:'web',num:'02',title:'Web / API 安全',desc:'围绕身份、权限和业务逻辑，建立可复现的验证路径。',icon:'code',color:'',category:'assess',tag:'安全评估',output:'发现与复现'},
    {id:'triage',num:'03',title:'漏洞定级与修复排序',desc:'区分技术严重性与业务优先级，让每一项修复有据可依。',icon:'layers',color:'sand',category:'assess',tag:'风险管理',output:'风险清单'},
    {id:'network',num:'04',title:'网络与流量分析',desc:'从 PCAP 与协议中还原通信，追踪异常背后的证据。',icon:'activity',color:'lilac',category:'respond',tag:'流量分析',output:'通信时间线'},
    {id:'malware',num:'05',title:'恶意样本与二进制',desc:'在隔离环境中分析样本，提取行为特征与关联指标。',icon:'bug',color:'rose',category:'respond',tag:'样本分析',output:'IOC / 行为'},
    {id:'incident',num:'06',title:'事件响应与取证',desc:'围绕时间线与影响范围，组织证据、遏制和恢复行动。',icon:'shield',color:'mint',category:'respond',tag:'事件响应',output:'处置与复盘'},
    {id:'detection',num:'07',title:'检测工程与威胁狩猎',desc:'把行为假设转成检测规则，验证可观测性和误报边界。',icon:'search',color:'',category:'defend',tag:'检测工程',output:'检测与验证'},
    {id:'cloud',num:'08',title:'云与容器安全',desc:'审查云配置、容器与权限路径，建立可执行的加固计划。',icon:'cloud',color:'',category:'defend',tag:'环境加固',output:'配置与权限'},
    {id:'code',num:'09',title:'代码与供应链安全',desc:'沿着数据流与依赖链，检查代码、密钥和构建边界。',icon:'code',color:'sand',category:'defend',tag:'代码审查',output:'补丁与复测'},
    {id:'reporting',num:'10',title:'报告与复测',desc:'把观察、推断和结论分开，形成读者能行动的交付物。',icon:'files',color:'slate',category:'defend',tag:'报告交付',output:'报告与计划'},
  ];
  const categories = [['all','全部'],['assess','评估与验证'],['respond','分析与响应'],['defend','检测与加固']];
  function notify(message) { clearTimeout(toastTimer); $('#toast').textContent = message; $('#toast').classList.add('visible'); toastTimer = setTimeout(() => $('#toast').classList.remove('visible'), 2800); }
  function updateSaved() { $('#saved-count').textContent = saved.length; }
  function saveButton(id) { const selected = saved.includes(id); return '<button class="save-button' + (selected ? ' saved' : '') + '" data-action="save" data-id="' + id + '" aria-pressed="' + selected + '" aria-label="' + (selected ? '取消收藏' : '收藏') + '这份手册">' + icon('bookmark') + '</button>'; }
  function flowCard(flow) { return '<article class="workflow-card"><div class="card-top"><span class="workflow-icon ' + flow.color + '">' + icon(flow.icon) + '</span><span class="card-meta"><span class="index">' + flow.num + '</span>' + saveButton(flow.id) + '</span></div><h3><a href="#/docs/' + flow.id + '">' + flow.title + '</a></h3><p>' + flow.desc + '</p><div class="card-bottom"><span class="label">' + flow.tag + '</span><span>' + (read.includes(flow.id) ? '✓ 已读' : flow.output) + ' ' + icon('arrow') + '</span></div></article>'; }
  const sectionHeading = (title, desc, link) => '<div class="section-heading"><div><h2>' + title + '</h2>' + (desc ? '<p>' + desc + '</p>' : '') + '</div>' + (link || '') + '</div>';
  const link = (href, text) => '<a class="text-link" href="' + href + '">' + text + icon('arrow') + '</a>';
  const notice = text => '<div class="notice">' + icon('info') + '<p>' + text + '</p></div>';
  function terminal() { return '<div class="terminal"><div class="terminal-head"><span class="terminal-dots" aria-hidden="true"><i></i><i></i><i></i></span><span class="terminal-title">~/workspace / road-skill</span><button class="icon-button" data-action="copy-install" aria-label="复制克隆命令">' + icon('copy') + '</button></div><div class="terminal-body"><div class="term-comment"># 一个问题，一条证据链。</div><div class="terminal-line"><span class="term-prompt">❯</span><span class="term-blue">git clone</span> https://github.com/</div><div class="terminal-line" style="padding-left:17px">liveliho/road-skill.git</div><div class="terminal-line"><span class="term-prompt">❯</span>cd road-skill</div><div class="terminal-line"><span class="term-prompt">❯</span><span class="term-green">python</span> tools/build_release.py</div><div class="term-comment"># 生成完整的 Skill ZIP 安装包</div><div class="term-output">' + icon('check') + '<span>Python 3.10+ · 仅标准库</span><span class="term-tag">命令示例</span></div></div></div>'; }
  function toolsShortcuts() { return [['ioc','search','IOC 提取','IPv4 · URL · 文件哈希'],['hash','hash','文件哈希','本地计算 SHA-256'],['redact','lock','敏感信息脱敏','常见凭据与个人信息'],['triage','layers','优先级试算','公开公式 · 手动输入']].map(([id,ico,title,desc]) => '<a class="tool-shortcut" href="#/tools/' + id + '">' + icon(ico) + '<span><strong>' + title + '</strong><small>' + desc + '</small></span><span class="arrow">↗</span></a>').join(''); }
  function home() {
    $('#page-label').textContent = '工作台';
    return '<div class="page-heading"><div><div class="eyebrow"><span class="mini-line"></span> YOUR SECURITY WORKSPACE</div><h1>安全工作，从这里开始。</h1><p>把零散的线索，整理成有依据的下一步。</p></div><span class="version-pill"><span></span> Skill v1.1.0</span></div><section class="hero"><div class="hero-copy"><div class="hero-kicker">' + icon('spark') + ' 面向 AI Agent 的网络安全运营 Skill</div><h2>把安全工作，<br>建立在<em>证据</em>之上。</h2><p>从资产发现到事件响应，用清晰的工作流连接观察、验证与行动。每个结论，都有迹可循。</p><div class="hero-actions"><a class="button primary" href="#/workflows">选择工作流 ' + icon('arrow') + '</a><a class="button" href="#/install">' + icon('download') + ' 安装 Skill</a></div></div><div class="hero-terminal-area">' + terminal() + '</div></section><section class="facts-row" aria-label="项目组成"><div class="fact"><span class="fact-icon">' + icon('workflow') + '</span><div><strong>11<span>类工作流</span></strong><small>覆盖从评估到响应</small></div></div><div class="fact"><span class="fact-icon">' + icon('book') + '</span><div><strong>' + docs.length + '<span>份仓库文档</span></strong><small>直接来自 Markdown 源码</small></div></div><div class="fact"><span class="fact-icon">' + icon('terminal') + '</span><div><strong>5<span>个 CLI 命令</span></strong><small>4 个离线 · 1 个联网</small></div></div><div class="fact"><span class="fact-icon">' + icon('files') + '</span><div><strong>3<span>份交付模板</span></strong><small>范围 · 发现 · 报告</small></div></div></section><section class="workflow-section">' + sectionHeading('选择你的工作流','从当前任务出发，只加载需要的领域手册。',link('#/workflows','查看全部工作流')) + '<div class="workflow-grid">' + [flows[2],flows[3],flows[6],flows[4],flows[9],flows[8]].map(flowCard).join('') + '</div></section><div class="home-bottom"><section class="panel">' + sectionHeading('触手可及的本地工具','', '<span class="label">仅在浏览器处理</span>') + '<div class="tool-shortcuts">' + toolsShortcuts() + '</div></section><section class="panel">' + sectionHeading('项目手记','',link('https://github.com/liveliho/road-skill/commits/main','提交历史')) + '<div class="commit-note">' + icon('shield') + '<div><strong>让工具边界更明确<span class="mini-tag">2026.10.22</span></strong><p>仓库审计记录涵盖 HTTP 范围校验、秘密脱敏、输出注入和评分输入。详细证据与剩余限制见审计报告。</p><a class="text-link" href="https://github.com/liveliho/road-skill/blob/main/docs/SECURITY-AUDIT-2026-10-22.md" target="_blank" rel="noopener noreferrer">阅读审计记录 ' + icon('external') + '</a></div></div></section></div>';
  }
  function categoryButtons() { return '<div class="segmented" role="group" aria-label="工作流分类">' + categories.map(([id,name]) => '<button data-action="category" data-category="' + id + '" aria-pressed="' + (workflowCategory === id) + '" class="' + (workflowCategory === id ? 'active' : '') + '">' + name + '</button>').join('') + '</div>'; }
  function workflows() { $('#page-label').textContent = '工作流'; return '<div class="intro-row"><div><div class="eyebrow">WORKFLOWS / 11</div><h1>从问题出发。</h1><p>选择与你当前任务相符的领域。每条工作流都指向仓库中的完整手册，包含输入、验证方法和交付标准。</p></div></div><div class="filter-bar">' + categoryButtons() + '<label class="inline-search">' + icon('search') + '<input id="workflow-query" type="search" aria-label="筛选工作流" placeholder="搜索工作流…" value="' + escape(workflowQuery) + '"></label></div><div class="workflow-grid" id="workflow-results"></div><div id="workflow-count" class="list-count" role="status"></div>' + notice('第一次执行主动测试？先阅读 <a class="text-link" href="#/docs/scope">授权与范围 →</a>，再进入具体领域手册。'); }
  function filterFlows() { const filtered = flows.filter(f => (workflowCategory === 'all' || f.category === workflowCategory) && (f.title + f.desc + f.output + f.tag).toLowerCase().includes(workflowQuery.toLowerCase())); $('#workflow-results').innerHTML = filtered.length ? filtered.map(flowCard).join('') : empty('没有匹配的工作流','试试“流量”“权限”或清除筛选。','清除筛选','clear-filter'); $('#workflow-count').textContent = '显示 ' + filtered.length + ' / 11 类工作流'; }
  function empty(title, desc, actionText, action) { return '<div class="empty-state">' + icon('search') + '<h2>' + title + '</h2><p>' + desc + '</p>' + (action ? '<button class="button" data-action="' + action + '">' + actionText + '</button>' : '') + '</div>'; }
  function docsPage() { $('#page-label').textContent = '文档中心'; return '<div class="intro-row"><div><div class="eyebrow">DOCUMENTATION</div><h1>让每一步都有参考。</h1><p>这些是仓库内的真实文档。查看领域手册、CLI 用法和模板，沿着证据链推进任务。</p></div><button class="button" data-action="search">' + icon('search') + ' 搜索文档</button></div><div class="docs-list">' + docs.map(doc => '<a class="doc-list-item" href="#/docs/' + doc.id + '">' + icon(doc.path.startsWith('assets') ? 'files' : 'book') + '<div><h3>' + doc.title + '</h3><p>' + doc.description + '</p></div><span class="arrow">↗</span></a>').join('') + '</div>'; }
  function documentPage(id) {
    const doc = docs.find(d => d.id === id); if (!doc) return notFound();
    $('#page-label').textContent = doc.title;
    const complete = read.includes(id);
    return '<a class="back-link" href="#/docs">' + icon('back') + ' 文档中心</a><div class="docs-layout"><article class="document"><header class="document-header"><div class="eyebrow">' + escape(doc.path.startsWith('assets') ? 'TEMPLATE' : 'FIELD GUIDE') + ' / ROAD-SKILL</div><h1>' + doc.title + '</h1><div class="doc-meta"><span>' + escape(doc.path) + '</span><span>源码构建 · ' + Math.max(1,Math.ceil(doc.raw.length / 450)) + ' 分钟阅读</span></div><div class="doc-actions"><button class="button" data-action="save" data-id="' + id + '" aria-pressed="' + saved.includes(id) + '">' + icon('bookmark') + (saved.includes(id) ? '已收藏' : '收藏手册') + '</button><button class="button" data-action="read" data-id="' + id + '" aria-pressed="' + complete + '">' + icon('check') + (complete ? '已标记读完' : '标记读完') + '</button><a class="button quiet" href="https://github.com/liveliho/road-skill/blob/main/.dsh/skills/cybersecurity-ops/' + doc.path + '" target="_blank" rel="noopener noreferrer">查看源码 ' + icon('external') + '</a></div></header><div class="prose">' + doc.html + '</div></article><nav class="doc-toc" aria-label="本页目录"><strong>本页目录</strong>' + doc.toc.map(item => '<a href="#' + item.anchor + '" data-action="toc" data-anchor="' + item.anchor + '" class="toc-level-' + item.level + '">' + escape(item.title) + '</a>').join('') + '</nav></div>';
  }
  function savedPage() { $('#page-label').textContent = '我的收藏'; const items = docs.filter(d => saved.includes(d.id)); return '<div class="intro-row"><div><div class="eyebrow">PERSONAL SPACE</div><h1>留住有用的线索。</h1><p>收藏与已读状态只保存在当前浏览器，不会上传或跨设备同步。已读 ' + read.length + ' / ' + docs.length + ' 份。</p></div></div>' + (items.length ? '<div class="docs-list">' + items.map(d => '<div class="doc-list-item">' + icon('bookmark') + '<a href="#/docs/' + d.id + '"><h3>' + d.title + '</h3><p>' + d.description + '</p></a><div style="margin-left:auto">' + saveButton(d.id) + '</div></div>').join('') + '</div>' : empty('这里还没有收藏','在工作流或文档页面，点击书签保存常用手册。','浏览文档','go-docs')); }
  function installPage() { $('#page-label').textContent = '安装 Skill'; return '<div class="intro-row"><div><div class="eyebrow">GET STARTED</div><h1>把工作流带到你的 Agent。</h1><p>下载完整 Skill 包，复制到宿主的技能目录。CLI 工具需要 Python 3.10+，无需额外 Python 依赖。</p></div></div><div class="install-grid"><div><div class="install-step"><span class="step-number">01</span><div><h3>获取完整 Skill 包</h3><p>下载右侧 ZIP，或者克隆仓库。保留整个 <code>cybersecurity-ops/</code> 目录，包含手册、脚本与模板。</p>' + terminal() + '</div></div><div class="install-step"><span class="step-number">02</span><div><h3>放入 Agent 的技能目录</h3><p>以 DSH 为例：<code>&lt;项目&gt;/.dsh/skills/cybersecurity-ops/</code>。其他宿主请使用其配置的技能目录，具体加载方式以客户端为准。</p></div></div><div class="install-step"><span class="step-number">03</span><div><h3>确认加载，再选择任务</h3><p>确认 Agent 已发现 <code>cybersecurity-ops</code>。运行 CLI 前进入 Skill 目录，执行 <code>python scripts/secops.py --help</code> 查看命令。</p></div></div></div><aside class="panel"><span class="workflow-icon mint">' + icon('download') + '</span><h2 style="margin-top:20px">cybersecurity-ops</h2><p class="tool-description">Skill v1.1.0<br>与网站一同从仓库源码构建。</p><a class="button primary" href="./downloads/cybersecurity-ops-1.1.0.zip" download>' + icon('download') + ' 下载完整 Skill ZIP</a><p class="download-size"><a href="./downloads/cybersecurity-ops-1.1.0.zip.sha256" download>下载 SHA-256 校验文件 ↗</a></p><div class="notice"><p>解压后得到完整技能目录。SHA-256 可核对下载完整性，不代表数字签名或安全背书。</p></div><a class="text-link" href="#/tools/hash">在浏览器校验文件 ' + icon('arrow') + '</a></aside></div>' + notice('网站中的终端是<strong>可复制命令示例</strong>。网页不运行 Python，也不授予 Agent 工具权限。'); }
  function templatesPage() { $('#page-label').textContent = '报告与模板'; const templates = [['scope-template','授权范围','明确目标资产、时间窗、允许动作、排除项与停止条件。','scope-template.md'],['finding-template','安全发现','用统一结构记录观察、复现、影响、置信度和修复方式。','finding-template.md'],['report-template','安全报告','把摘要、证据、风险清单与复测计划组织成一份完整交付。','report-template.md']]; return '<div class="intro-row"><div><div class="eyebrow">TEMPLATES / MARKDOWN</div><h1>让结论，成为交付。</h1><p>三份仓库原生 Markdown 模板。下载后按真实任务填写，未知信息保留为未知。</p></div></div><div class="template-grid">' + templates.map(([id,title,desc,file]) => '<article class="template-card">' + icon('files') + '<h2>' + title + '</h2><p>' + desc + '</p><a class="button" href="./downloads/' + file + '" download>' + icon('download') + ' 下载 Markdown</a><a class="text-link" href="#/docs/' + id + '">先阅读模板 ' + icon('arrow') + '</a></article>').join('') + '</div>' + notice('模板仅提供结构，不会自动得出安全结论。请把证据原文与分析区分开，并在分享前复核和脱敏。'); }
  const toolList = [['ioc','search','IOC 提取'],['hash','hash','SHA-256 校验'],['redact','lock','敏感信息脱敏'],['triage','layers','优先级试算']];
  const resultPlaceholder = '<div id="tool-result"><p class="result-placeholder">结果会显示在这里。</p></div>';
  function toolPage(id = 'ioc') {
    if (!toolList.some(t => t[0] === id)) return notFound();
    resultText = ''; $('#page-label').textContent = '本地工具';
    let form = '';
    if (id === 'ioc' || id === 'redact') {
      const isIOC = id === 'ioc';
      form = '<h2>' + (isIOC ? '从线索中提取指标。' : '分享之前，先做脱敏。') + '</h2><p class="tool-description">' + (isIOC ? '提取文本中的 IPv4、HTTP(S) URL 和常见文件哈希。先过滤常见秘密，再去重。不会访问这些地址。' : '识别常见令牌、Authorization、Cookie、秘密键值与 JSON 秘密字段。启发式处理，分享前仍需人工复核。') + '</p><label class="field-label" for="tool-input">' + (isIOC ? '粘贴待分析文本' : '粘贴待脱敏文本') + '</label><textarea class="text-input" id="tool-input" spellcheck="false" placeholder="' + (isIOC ? '例如：connection to 203.0.113.42 / https://example.com/path' : '例如：Authorization: Bearer …') + '"></textarea><p class="field-note">仅在当前页面内存处理，不上传。最多 1 MiB 文本。</p>' + (!isIOC ? '<label class="checkbox-row"><input type="checkbox" id="pii" checked>额外处理邮箱、中国大陆手机号和私有 IPv4</label>' : '') + '<div class="tool-actions"><button class="button primary" data-action="run-tool" data-tool="' + id + '">' + icon(isIOC ? 'search' : 'lock') + (isIOC ? '提取 IOC' : '开始脱敏') + '</button><button class="button" data-action="clear-tool">清空</button><button class="button quiet sample-button" data-action="sample" data-tool="' + id + '">填入合成示例 ↗</button></div>' + resultPlaceholder + '<p class="tool-footnote">' + (isIOC ? '网页轻量版不提取裸域名、邮箱或 IPv6；候选指标不等于恶意判定。建议复杂证据使用仓库 CLI 并人工复核。' : '网页轻量版可能遗漏自定义/编码格式、IPv6、银行卡号、姓名和截图中的敏感值。处理范围与 Python CLI 不完全相同。') + '</p>';
    } else if (id === 'hash') {
      form = '<h2>验证文件，留下指纹。</h2><p class="tool-description">使用浏览器 Web Crypto 计算 SHA-256。文件只在本机内存读取，不会上传；单文件最多 50 MiB。</p><label class="field-label" for="hash-file">选择需要校验的文件</label><input class="text-input" type="file" id="hash-file"><p class="field-note">选择文件不会自动执行或打开它。</p><label class="field-label" for="expected-hash">预期 SHA-256（可选）</label><input class="text-input mono" id="expected-hash" placeholder="粘贴 64 位十六进制校验值" spellcheck="false"><div class="tool-actions" style="margin-top:20px"><button class="button primary" data-action="run-tool" data-tool="hash">' + icon('hash') + ' 计算并校验</button></div>' + resultPlaceholder;
    } else {
      form = '<h2>把优先级，算得明白。</h2><p class="tool-description">按照仓库公开的示例公式试算。必须手动确认全部输入，页面不会查询漏洞情报或假定未知字段为零。</p><div class="form-grid"><div class="field-control"><label for="cvss">CVSS Base（0–10）</label><input class="text-input" id="cvss" type="number" step="0.1" min="0" max="10" placeholder="例如 9.8"></div><div class="field-control"><label for="epss">EPSS 概率（0–1）</label><input class="text-input" id="epss" type="number" step="0.001" min="0" max="1" placeholder="0.5% 应填写 0.005"></div><div class="field-control"><label for="confidence">证据置信度（0–1）</label><input class="text-input" id="confidence" type="number" step="0.1" min="0" max="1" placeholder="例如 0.8"></div>' + [['kev','已列入 CISA KEV？'],['exposed','互联网暴露？'],['sensitive','涉及敏感数据？']].map(([key,label]) => '<div class="field-control"><label for="' + key + '">' + label + '</label><select class="text-input" id="' + key + '"><option value="">请选择已核实的情况</option><option value="yes">是</option><option value="no">否</option></select></div>').join('') + '</div><div class="tool-actions"><button class="button primary" data-action="run-tool" data-tool="triage">试算优先级 ' + icon('arrow') + '</button><button class="button quiet" data-action="sample" data-tool="triage">填入合成示例</button></div>' + resultPlaceholder + '<p class="tool-footnote">自定义处置优先级，不是 CVSS / SSVC 标准评分。无法替代漏洞确认或组织决策，也不会改变发现状态。<a class="text-link" href="#/docs/triage">查看公式与适用边界 →</a></p>';
    }
    return '<div class="intro-row"><div><div class="eyebrow">LOCAL UTILITIES</div><h1>证据留在你的设备上。</h1><p>四个轻量工具，只处理你主动提供的内容。</p></div><span class="version-pill"><span></span> Browser local</span></div><div class="tools-layout"><nav class="tool-nav" aria-label="本地工具">' + toolList.map(([key,ico,title]) => '<a href="#/tools/' + key + '" class="' + (key === id ? 'active' : '') + '">' + icon(ico) + title + '</a>').join('') + '</nav><section class="tool-panel">' + form + '</section></div>';
  }
  function sourcesPage() { $('#page-label').textContent = '设计与开源来源'; return '<div class="intro-row"><div><div class="eyebrow">DESIGN / SOURCES</div><h1>清晰的工作空间，开放的设计参考。</h1><p>日间 Linux 桌面的秩序，搭配 iOS 风格的轻透浮动层。网页采用独立 CSS 与浏览器原生控件，不加载第三方 UI 库。</p></div></div><section class="panel"><table class="source-table"><thead><tr><th>官方项目 / 文档</th><th>参考与取舍</th></tr></thead><tbody><tr><td><a href="https://developer.gnome.org/hig/patterns/nav/sidebars.html" target="_blank" rel="noopener noreferrer">GNOME HIG / libadwaita ↗</a></td><td>侧栏、工具栏与响应式分栏。<small>GTK 原生组件未用于网页，仅转译布局逻辑。</small></td></tr><tr><td><a href="https://developer.apple.com/design/human-interface-guidelines/materials" target="_blank" rel="noopener noreferrer">Apple Materials ↗</a></td><td>浮动层材质与阅读表面的分工。<small>CSS 玻璃是视觉借鉴，不是 Apple 官方 iOS 27 网页组件。</small></td></tr><tr><td><a href="https://github.com/radix-ui/primitives" target="_blank" rel="noopener noreferrer">Radix Primitives ↗</a><small>MIT</small></td><td>评估可访问交互原语。<small>本项目无 React 依赖，采用原生 dialog 实现搜索。</small></td></tr><tr><td><a href="https://github.com/shuding/nextra" target="_blank" rel="noopener noreferrer">Nextra ↗</a></td><td>参考内容优先的文档结构。<small>本站用 Python 构建真实 Markdown 文档。</small></td></tr><tr><td><a href="https://github.com/saadeghi/daisyui" target="_blank" rel="noopener noreferrer">daisyUI ↗</a></td><td>评估主题与分段控件。<small>本站使用独立颜色 token，未复制其组件源码。</small></td></tr></tbody></table><p class="tool-description">图标为项目内原创 SVG，字体来自设备系统。没有 CDN、远程字体、分析追踪、付费 API 或在线模型。参考核验日期：2026-10-22。</p></section>' + notice('安全内容来自 <a class="text-link" href="https://github.com/liveliho/road-skill" target="_blank" rel="noopener noreferrer">liveliho/road-skill</a>。完整专业来源与维护说明见 <a class="text-link" href="#/docs/sources">Skill 来源文档 →</a>。'); }
  function notFound() { $('#page-label').textContent = '未找到页面'; return empty('这条路径暂时不存在','返回文档中心，继续寻找你需要的内容。','打开文档中心','go-docs'); }
  function route() {
    const hash = location.hash.slice(1) || '/';
    const [page, id] = hash.replace(/^\//, '').split('?')[0].split('/');
    workflowCategory = new URLSearchParams(hash.split('?')[1] || '').get('category') || 'all';
    workflowQuery = new URLSearchParams(hash.split('?')[1] || '').get('q') || '';
    const renderers = {workflows, docs:() => id ? documentPage(id) : docsPage(), saved:savedPage, install:installPage, templates:templatesPage, tools:() => toolPage(id), sources:sourcesPage};
    main.innerHTML = '<div class="fade-in">' + (page ? (renderers[page] || notFound)() : home()) + '</div>';
    $$('[data-nav]').forEach(a => { const selected = a.dataset.nav === (page || 'home'); a.classList.toggle('active', selected); if (selected) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current'); });
    hydrate(main); updateSaved();
    if (page === 'workflows') filterFlows();
    document.title = $('#page-label').textContent + ' · road-skill';
    document.documentElement.scrollTop = 0;
    const mobile = $('#mobile-navigation'); if (mobile.open) mobile.close();
  }
  function search(query) {
    const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const results = tokens.length ? docs.filter(d => tokens.every(token => (d.title + d.description + d.raw).toLowerCase().includes(token))) : docs.slice(0,6);
    $('#search-results').innerHTML = '<div class="search-group-label">' + (tokens.length ? results.length + ' 个匹配文档' : '快速入口') + '</div>' + (results.length ? results.map(d => { const text = d.raw.replace(/[#*`|>]/g,' ').replace(/\s+/g,' '); const index = tokens.length ? text.toLowerCase().indexOf(tokens[0]) : -1; const snippet = index >= 0 ? '…' + text.slice(Math.max(0,index-30),index+100) + '…' : d.description; return '<a class="search-result" href="#/docs/' + d.id + '" data-action="search-result"><strong>' + d.title + '</strong><p>' + escape(snippet) + '</p></a>'; }).join('') : '<div class="search-empty">没有找到相关文档，试试其他关键词。</div>');
  }
  async function copy(text) { try { await navigator.clipboard.writeText(text); notify('已复制到剪贴板'); } catch (_) { notify('浏览器未允许复制，可长按或选择文本手动复制'); } }
  function setTheme(theme) { document.documentElement.dataset.theme = theme; $('#theme-toggle').innerHTML = icon(theme === 'dark' ? 'moon' : 'sun'); $('#theme-toggle').setAttribute('aria-label', theme === 'dark' ? '切换到日间主题' : '切换到夜间主题'); storage.set('theme',theme); }
  function showResult(text, kind = 'json', prefix = '') { resultText = text; resultKind = kind; const box = $('#tool-result'); if (!box) return; box.innerHTML = '<div class="result-box"><div class="result-heading"><h3>处理结果</h3><div><button class="icon-button" data-action="copy-result" aria-label="复制处理结果">' + icon('copy') + '</button><button class="icon-button" data-action="download-result" aria-label="下载处理结果">' + icon('download') + '</button></div></div>' + prefix + '<pre class="result-pre" id="result-text"></pre></div>'; $('#result-text').textContent = text; }
  function showError(message) { const box = $('#tool-result'); if (box) { resultText = ''; box.innerHTML = '<p class="error-text" role="alert">' + escape(message) + '</p>'; } }
  function resetTool() { const input = $('#tool-input'); if (input) input.value = ''; resultText = ''; $('#tool-result').innerHTML = '<p class="result-placeholder">结果会显示在这里。</p>'; input?.focus(); }
  async function runTool(id, button) {
    const routeAtStart = location.hash;
    try {
      button.disabled = true;
      if (id === 'hash') {
        const file = $('#hash-file').files[0];
        if (!file) throw new Error('请先选择文件。');
        if (file.size > 50 * 1024 * 1024) throw new Error('文件超过 50 MiB，请使用本地 CLI 计算哈希。');
        if (!crypto.subtle) throw new Error('当前浏览器不支持安全上下文下的 Web Crypto，请使用 HTTPS 或本地 CLI。');
        const expected = $('#expected-hash').value.trim().toLowerCase();
        if (expected && !/^[a-f0-9]{64}$/.test(expected)) throw new Error('预期值应为 64 位十六进制 SHA-256。');
        button.textContent = '计算中…';
        const bytes = await file.arrayBuffer();
        const buffer = await crypto.subtle.digest('SHA-256', bytes);
        if (location.hash !== routeAtStart || !button.isConnected) return;
        const sha256 = Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2,'0')).join('');
        const result = {file:file.name, bytes:file.size, algorithm:'SHA-256', sha256};
        if (expected) { result.matches = expected === sha256; result.expected = expected; }
        showResult(JSON.stringify(result,null,2),'json',expected ? '<div class="notice"><p><strong>' + (result.matches ? '校验值一致。' : '校验值不一致，请核对文件与预期值来源。') + '</strong></p></div>' : '');
      } else if (id === 'triage') {
        const input = {}; ['cvss','epss','confidence'].forEach(key => input[key] = $('#' + key).value);
        ['kev','exposed','sensitive'].forEach(key => { const val = $('#' + key).value; input[key] = val ? val === 'yes' : null; });
        const result = RoadTools.score(input);
        showResult(JSON.stringify(result,null,2),'json','<div class="score-result"><div class="score-number">' + result.score + '<small>示例加权分数 / 100</small></div><div><strong>' + result.priority + '</strong><p>处置优先级 · 不代表漏洞确认状态</p></div></div>');
      } else {
        const text = $('#tool-input').value;
        if (!text.trim()) throw new Error('请先粘贴文本，或填入合成示例。');
        if (new Blob([text]).size > 1024 * 1024) throw new Error('文本超过 1 MiB，请缩小输入或使用 CLI。');
        if (id === 'ioc') { const indicators = RoadTools.extract(text); showResult(JSON.stringify({count:indicators.length, indicators, note:'候选指标，不等于恶意判定；未进行网络查询。'},null,2)); }
        else showResult(RoadTools.redact(text,$('#pii').checked),'txt');
      }
    } catch (error) { if (location.hash === routeAtStart && button.isConnected) showError(error.message); }
    finally { if (button.isConnected) { button.disabled = false; if (id === 'hash') button.innerHTML = icon('hash') + ' 计算并校验'; } }
  }
  document.addEventListener('click', event => {
    if (event.target.closest('.skip')) { event.preventDefault(); main.focus(); main.scrollIntoView(); return; }
    const button = event.target.closest('[data-action]'); if (!button) return;
    const action = button.dataset.action;
    if (action === 'search') { const dialog = $('#search-dialog'); search($('#global-search').value); if (!dialog.open) dialog.showModal(); $('#global-search').focus(); }
    if (action === 'close-search') $('#search-dialog').close();
    if (action === 'search-result') { $('#search-dialog').close(); if (button.hash === location.hash) main.focus({preventScroll:true}); }
    if (action === 'theme') setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
    if (action === 'menu') { $('#mobile-navigation').showModal(); button.setAttribute('aria-expanded','true'); }
    if (action === 'close-menu') $('#mobile-navigation').close();
    if (action === 'copy-install') copy(command);
    if (action === 'copy-result' && resultText) copy(resultText);
    if (action === 'download-result' && resultText) { const url = URL.createObjectURL(new Blob([resultText],{type:resultKind === 'json' ? 'application/json' : 'text/plain;charset=utf-8'})); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'road-skill-result.' + resultKind; anchor.click(); setTimeout(() => URL.revokeObjectURL(url),1000); }
    if (action === 'save') { const id = button.dataset.id; if (saved.includes(id)) saved = saved.filter(item => item !== id); else saved.push(id); storage.set('saved',saved); updateSaved(); if (location.hash.startsWith('#/saved')) route(); else $$('[data-action="save"][data-id="' + id + '"]').forEach(el => { const active = saved.includes(id); el.classList.toggle('saved',active); el.setAttribute('aria-pressed',active); el.setAttribute('aria-label',(active ? '取消收藏' : '收藏') + '这份手册'); if (location.hash.startsWith('#/docs/')) el.innerHTML = icon('bookmark') + (active ? '已收藏' : '收藏手册'); }); notify(saved.includes(id) ? '已加入收藏' : '已取消收藏'); }
    if (action === 'read') { const id = button.dataset.id; read = read.includes(id) ? read.filter(item => item !== id) : [...read,id]; storage.set('read',read); button.setAttribute('aria-pressed',read.includes(id)); button.innerHTML = icon('check') + (read.includes(id) ? '已标记读完' : '标记读完'); notify(read.includes(id) ? '已标记读完，仅保存在当前浏览器' : '已取消已读标记'); }
    if (action === 'toc') { event.preventDefault(); document.getElementById(button.dataset.anchor)?.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth',block:'start'}); }
    if (action === 'category') { workflowCategory = button.dataset.category; updateWorkflowURL(); route(); }
    if (action === 'clear-filter') { workflowCategory = 'all'; workflowQuery = ''; updateWorkflowURL(); route(); }
    if (action === 'go-docs') location.hash = '/docs';
    if (action === 'clear-tool') resetTool();
    if (action === 'sample') {
      if (button.dataset.tool === 'triage') { $('#cvss').value = '9.8'; $('#epss').value = '0.72'; $('#confidence').value = '0.9'; $('#kev').value = 'yes'; $('#exposed').value = 'yes'; $('#sensitive').value = 'no'; }
      else { $('#tool-input').value = button.dataset.tool === 'ioc' ? '# 合成示例，非真实安全事件\nConnection to 203.0.113.42\nGET hxxps://example[.]com/updates\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nRepeated: 203.0.113.42' : '# 合成示例，请勿填入真实生产凭据\nAuthorization: Bearer example_token_for_demo_only\napi_key=synthetic-secret-for-demo\nCookie: session=demo_only\nContact: analyst@example.com\nInternal host: 192.168.10.8'; }
      resultText = ''; $('#tool-result').innerHTML = '<p class="result-placeholder">已填入合成示例，点击上方按钮处理。</p>';
    }
    if (action === 'run-tool') runTool(button.dataset.tool,button);
  });
  function updateWorkflowURL() { const params = new URLSearchParams(); if (workflowCategory !== 'all') params.set('category',workflowCategory); if (workflowQuery) params.set('q',workflowQuery); history.replaceState(null,'','#/workflows' + (params.size ? '?' + params : '')); }
  document.addEventListener('input', event => { if (event.target.id === 'global-search') search(event.target.value); if (event.target.id === 'workflow-query') { workflowQuery = event.target.value; updateWorkflowURL(); filterFlows(); } });
  document.addEventListener('keydown', event => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); $('.search-trigger').click(); } if (event.key === 'Enter' && event.target.id === 'global-search') { const result = $('#search-results .search-result'); if (result) result.click(); } });
  $('#mobile-navigation').addEventListener('close',() => $('[data-action="menu"]').setAttribute('aria-expanded','false'));
  $('#mobile-navigation').addEventListener('click',event => { if (event.target.closest('nav a')) $('#mobile-navigation').close(); });
  for (const dialog of [$('#search-dialog'),$('#mobile-navigation')]) dialog.addEventListener('click',event => { if (event.target === dialog) { const box = dialog.getBoundingClientRect(); if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) dialog.close(); } });
  window.addEventListener('hashchange',() => { route(); main.focus({preventScroll:true}); });
  hydrate(); setTheme(storage.get('theme','light') === 'dark' ? 'dark' : 'light'); route();
})();
