#!/usr/bin/env python3
"""Build a dependency-free static documentation site from allowlisted skill files."""
import argparse
import html
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from build_release import build as build_release

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / '.dsh/skills/cybersecurity-ops'
DOCS = [
    ('skill', 'Skill 使用指南', '入口、证据标准与统一工作流', 'SKILL.md'),
    ('cli', 'CLI 工具说明', '安装、命令和输出边界', 'README.md'),
    ('scope', '授权与范围', 'RoE、允许动作与停止条件', 'references/00-scope-and-rules.md'),
    ('recon', '资产发现与 OSINT', '资产关系、被动侦察与暴露面', 'references/01-recon-osint.md'),
    ('web', 'Web / API 安全', '身份、权限与业务逻辑验证', 'references/02-web-api.md'),
    ('triage', '漏洞定级与修复排序', '去重、严重性与处置优先级', 'references/03-vuln-triage.md'),
    ('network', '网络与流量分析', 'PCAP、协议与异常通信', 'references/04-network-pcap.md'),
    ('malware', '恶意样本与二进制', '隔离分析、行为与 IOC', 'references/05-malware-binary.md'),
    ('incident', '事件响应与取证', '时间线、影响范围与处置', 'references/06-incident-response.md'),
    ('detection', '检测工程与威胁狩猎', '检测假设、规则与误报验证', 'references/07-detection-engineering.md'),
    ('cloud', '云与容器安全', '云配置、K8s、镜像与权限', 'references/08-cloud-container.md'),
    ('code', '代码与供应链安全', '代码审查、依赖和 CI/CD', 'references/09-secure-code-supply-chain.md'),
    ('reporting', '报告与复测', '结论、证据索引与修复计划', 'references/10-reporting.md'),
    ('frameworks', '框架与评分口径', '标准映射、术语与冲突裁决', 'references/frameworks.md'),
    ('sources', 'Skill 来源与维护', '原始来源、核验与维护说明', 'references/sources.md'),
    ('scope-template', '授权范围模板', '记录资产、时间窗与排除项', 'assets/scope-template.md'),
    ('finding-template', '安全发现模板', '记录证据、影响和修复', 'assets/finding-template.md'),
    ('report-template', '安全报告模板', '从摘要到复测的完整结构', 'assets/report-template.md'),
]
PATH_IDS = {path: doc_id for doc_id, _, _, path in DOCS}


def safe_link(target, current):
    """Allow navigation only; never interpret embedded content as executable HTML."""
    if re.search(r'[\x00-\x20\x7f]', target):
        return None
    parts = urlsplit(target)
    if parts.scheme:
        return target if parts.scheme.lower() in ('https', 'http') else None
    if target.startswith('//') or target.startswith('#'):
        return None
    candidate = (Path(current).parent / target.split('#')[0]).as_posix()
    import posixpath
    candidate = posixpath.normpath(candidate)
    if candidate in PATH_IDS:
        return '#/docs/' + PATH_IDS[candidate]
    if candidate.startswith('../') or candidate.startswith('/'):
        return None
    return 'https://github.com/liveliho/road-skill/blob/main/.dsh/skills/cybersecurity-ops/' + candidate


def inline(text, current):
    tokens = []

    def stash(value):
        tokens.append(value)
        return '\x00' + str(len(tokens) - 1) + '\x00'

    text = text.replace('\x00', '')
    text = re.sub(r'`([^`]+)`', lambda m: stash('<code>' + html.escape(m[1]) + '</code>'), text)

    def autolink(m):
        target = safe_link(m[1], current)
        if not target:
            return stash(html.escape(m[0]))
        return stash('<a href="' + html.escape(target, quote=True) + '" target="_blank" rel="noopener noreferrer">' + html.escape(m[1]) + '</a>')

    text = re.sub(r'<(https?://[^>\s]+)>', autolink, text)

    def link(m):
        target = safe_link(m[2], current)
        label = html.escape(m[1])
        if not target:
            return stash(label)
        external = ' target="_blank" rel="noopener noreferrer"' if target.startswith('http') else ''
        return stash('<a href="' + html.escape(target, quote=True) + '"' + external + '>' + label + '</a>')

    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, text)
    text = html.escape(text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<em>\1</em>', text)
    return re.sub(r'\x00(\d+)\x00', lambda m: tokens[int(m[1])], text)


def render_markdown(source, current):
    """Conservative Markdown subset: raw HTML escaped, safe links, no remote embeds."""
    source = re.sub(r'\A---\n.*?\n---\n', '', source, flags=re.S)
    lines = source.splitlines()
    output, toc = [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith('```'):
            code = []
            i += 1
            while i < len(lines) and not lines[i].startswith('```'):
                code.append(lines[i])
                i += 1
            output.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
            i += 1
            continue
        heading = re.match(r'^(#{1,4})\s+(.+)$', line)
        if heading:
            level = len(heading[1])
            anchor = 'section-' + str(len(toc))
            toc.append({'level': level, 'title': re.sub(r'[*`]', '', heading[2]), 'anchor': anchor})
            # The reader provides its own title and metadata.
            if level != 1:
                output.append(f'<h{level} id="{anchor}">{inline(heading[2], current)}</h{level}>')
            i += 1
            continue
        if line.startswith('|') and i + 1 < len(lines) and re.fullmatch(r'[|:\s-]+', lines[i + 1]):
            rows = [line]
            i += 2
            while i < len(lines) and lines[i].startswith('|'):
                rows.append(lines[i])
                i += 1
            table = '<div class="table-scroll" tabindex="0" role="region" aria-label="文档表格"><table><thead>'
            for n, row in enumerate(rows):
                tag = 'th' if n == 0 else 'td'
                table += '<tr>' + ''.join(f'<{tag}>{inline(cell.strip(), current)}</{tag}>' for cell in re.split(r'(?<!\\)\|', row.strip().strip('|'))) + '</tr>'
                if n == 0:
                    table += '</thead><tbody>'
            output.append(table + '</tbody></table></div>')
            continue
        if line.startswith('>'):
            quote = []
            while i < len(lines) and lines[i].startswith('>'):
                quote.append(lines[i].lstrip('> '))
                i += 1
            output.append('<blockquote><p>' + inline(' '.join(quote), current) + '</p></blockquote>')
            continue
        if re.match(r'^\s*(?:[-*]|\d+\.)\s+', line):
            ordered = bool(re.match(r'^\s*\d+\.', line))
            tag = 'ol' if ordered else 'ul'
            items = []
            while i < len(lines) and re.match(r'^\s*(?:[-*]|\d+\.)\s+', lines[i]):
                value = re.sub(r'^\s*(?:[-*]|\d+\.)\s+', '', lines[i])
                value = re.sub(r'^\[ \]\s*', '☐ ', value)
                items.append('<li>' + inline(value, current) + '</li>')
                i += 1
            output.append(f'<{tag}>' + ''.join(items) + f'</{tag}>')
            continue
        if line.strip() == '---':
            output.append('<hr>')
            i += 1
            continue
        paragraph = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r'^(?:#|```|>|\||\s*[-*] |\s*\d+\. )', lines[i]):
            paragraph.append(lines[i])
            i += 1
        output.append('<p>' + inline(' '.join(paragraph), current) + '</p>')
    return ''.join(output), [entry for entry in toc if entry['level'] in (2, 3)]


def build_site(output):
    output = output.resolve()
    # Restrict cleanup to the dedicated generated site directory.
    if output == ROOT or output == SKILL or output in ROOT.parents:
        raise ValueError('refusing to overwrite source tree')
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(ROOT / 'website', output)
    docs = []
    for doc_id, title, description, path in DOCS:
        source = (SKILL / path).read_text(encoding='utf-8')
        body, toc = render_markdown(source, path)
        docs.append(dict(id=doc_id, title=title, description=description, path=path, raw=source, html=body, toc=toc))
    payload = json.dumps(docs, ensure_ascii=False).replace('<', '\\u003c').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    (output / 'content.js').write_text('window.ROAD_DOCS = ' + payload + ';\n', encoding='utf-8')
    downloads = output / 'downloads'
    downloads.mkdir()
    archive = build_release(SKILL, downloads)
    for _, _, _, path in DOCS:
        if path.startswith('assets/'):
            shutil.copy2(SKILL / path, downloads / Path(path).name)
    (output / '.nojekyll').touch()
    print(json.dumps({'output': str(output), 'documents': len(docs), 'skill_archive': archive.name}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist/site')
    build_site(parser.parse_args().output_dir)
