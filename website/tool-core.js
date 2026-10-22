/* Browser-only helpers: these do not execute the Python CLI or make requests. */
(function (root) {
  'use strict';
  const privateIPv4 = /^(?:10\.|127\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)/;
  function redact(text, pii = false) {
    let value = String(text);
    const secret = /^(?:password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|refresh_token|token|authorization|cookie|set-cookie)$/i;
    const walk = obj => {
      if (Array.isArray(obj)) return obj.map(walk);
      if (obj && typeof obj === 'object') return Object.fromEntries(Object.entries(obj).map(([key, val]) => [key, secret.test(key) ? '[REDACTED:SECRET]' : walk(val)]));
      return typeof obj === 'string' ? redactText(obj, pii) : obj;
    };
    try { return JSON.stringify(walk(JSON.parse(value)), null, 2); } catch (_) { return redactText(value, pii); }
  }
  function redactText(value, pii) {
    let result = value
      .replace(/-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g, '[REDACTED:PRIVATE_KEY]')
      .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9+\/_=.-]+/gi, '[REDACTED:AUTH]')
      .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{16,})\b/g, '[REDACTED:TOKEN]')
      .replace(/((?:https?):\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED:CREDENTIALS]@')
      .replace(/^(\s*(?:set-cookie|cookie)\s*:)\s*[^\r\n]*/gim, '$1 [REDACTED:COOKIE]')
      .replace(/((?:[?&]|\b)(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token)\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s&;,\n]+)/gi, '$1[REDACTED:SECRET]');
    if (pii) result = result
      .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED:EMAIL]')
      .replace(/(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)/g, '[REDACTED:PHONE]')
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ip => validIPv4(ip) && privateIPv4.test(ip) ? '[REDACTED:PRIVATE_IP]' : ip);
    return result;
  }
  function validIPv4(ip) { return ip.split('.').every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255); }
  function extract(text) {
    const clean = redact(text).replace(/hxxps:/gi, 'https:').replace(/hxxp:/gi, 'http:').replace(/\[\.\]/g, '.');
    const items = [], seen = new Set();
    const add = (type, value) => { const key = type + ':' + value; if (!seen.has(key)) { seen.add(key); items.push({ type, value }); } };
    for (const m of clean.matchAll(/https?:\/\/[^\s<>"'`]+/gi)) {
      const value = m[0].replace(/[),.;\]]+$/, '');
      // Only syntactic parsing; no DNS lookup or requests.
      try { const url = new URL(value); if (url.hostname && !url.username && !url.password && !value.includes('[REDACTED:')) add('url', value); } catch (_) { /* ignore */ }
    }
    for (const m of clean.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) if (validIPv4(m[0])) add('ipv4', m[0]);
    for (const m of clean.matchAll(/\b[a-fA-F0-9]{64}\b/g)) add('sha256', m[0].toLowerCase());
    for (const m of clean.matchAll(/\b[a-fA-F0-9]{40}\b/g)) add('sha1', m[0].toLowerCase());
    for (const m of clean.matchAll(/\b[a-fA-F0-9]{32}\b/g)) add('md5', m[0].toLowerCase());
    return items;
  }
  function numeric(value, min, max, label) {
    if (typeof value !== 'string' || !/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(value.trim())) throw new Error(label + '必须填写有效数值');
    const number = Number(value);
    if (!Number.isFinite(number) || number < min || number > max) throw new Error(label + '必须介于 ' + min + ' 与 ' + max + ' 之间');
    return number;
  }
  function score(input) {
    const cvss = numeric(input.cvss, 0, 10, 'CVSS');
    const epss = numeric(input.epss, 0, 1, 'EPSS');
    const confidence = numeric(input.confidence, 0, 1, '置信度');
    for (const key of ['kev', 'exposed', 'sensitive']) if (typeof input[key] !== 'boolean') throw new Error('请确认全部上下文信息');
    const result = Math.round(1000 * (.5 * cvss / 10 + .2 * epss + .15 * Number(input.kev) + .1 * Number(input.exposed) + .05 * Number(input.sensitive)) * confidence) / 10;
    let priority = 'P3';
    if (result >= 85 || (confidence >= .8 && input.kev && input.exposed && cvss >= 9)) priority = 'P0';
    else if (result >= 70 || (confidence >= .7 && (input.kev || cvss >= 9))) priority = 'P1';
    else if (result >= 40 || cvss >= 7) priority = 'P2';
    return { score: result, priority, formula: '100 × (0.50×CVSS/10 + 0.20×EPSS + 0.15×KEV + 0.10×暴露 + 0.05×敏感性) × 置信度', note: '自定义处置优先级示例，不是 CVSS / SSVC 标准分数；不会推断漏洞存在或生命周期状态。', inputs: { cvss, epss, confidence, kev: input.kev, exposed: input.exposed, sensitive: input.sensitive } };
  }
  const api = { redact, extract, score, validIPv4 };
  root.RoadTools = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(globalThis);
