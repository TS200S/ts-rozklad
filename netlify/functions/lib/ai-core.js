'use strict';
// Shared AI helpers: global config, per-user access/limits, usage counters,
// web tools (search + fetch with SSRF guard) and the quotes store.
// Used by ai-chat.js, quotes.js, quotes-refill.js, admin.js, system-diagnostics.js.
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const { atomicUpdateJSON } = require('./store');

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

// ---------------------------------------------------------------- config
const DEFAULT_CONFIG = {
  enabled: true,
  model: 'openai/gpt-oss-120b',
  maxTokens: 2500,          // max answer length (Groq allows up to 65 536 for this model)
  temperature: 0.5,
  reasoningEffort: 'low',   // low | medium | high - lower = faster, fewer hidden tokens
  webSearch: true,
  files: true,
  quotesTool: true,
  healthTool: true,
  historyMessages: 10,
  maxToolRounds: 4,
  timeBudgetSec: 20,        // stop calling tools after this many seconds (platform timeout safety)
  userWindowLimit: 20,      // messages per window per user
  userWindowMinutes: 10,
  userDailyLimit: 150,      // messages per day per user
  globalPerMinute: 25,
  disabledMessage: 'ІІ тимчасово вимкнено адміністратором.',
  // multi-model routing
  fallbackModels: ['openai/gpt-oss-20b', 'qwen/qwen3.8-27b'], // tried in order if the primary fails (429/5xx/unknown model/timeout)
  reportModel: 'openai/gpt-oss-20b',                           // writes admin security reports
  // security "shield": a classifier checks every user message before the main model sees it
  guardEnabled: true,
  guardModel: 'meta-llama/llama-prompt-guard-2-86m',
  guardThreshold: 0.8,       // score 0..1 at/above which a message counts as an attack
  guardMode: 'block',        // block | log
  guardFailOpen: true,       // if the guard itself errors, let the message through
  guardAutoBlockStrikes: 5   // flagged messages within 24h before the user's AI access is switched off (0 = never)
};
const MODEL_RE = /^[A-Za-z0-9._\/:-]{2,80}$/;

const LIMITS = {
  maxTokens: [200, 16000], temperature: [0, 1.5], historyMessages: [0, 30], maxToolRounds: [0, 8],
  guardThreshold: [0.05, 0.999], guardAutoBlockStrikes: [0, 100],
  timeBudgetSec: [5, 25], userWindowLimit: [1, 500], userWindowMinutes: [1, 1440], userDailyLimit: [0, 100000], globalPerMinute: [1, 600]
};
const EFFORTS = ['low', 'medium', 'high'];

function clampNum(v, [lo, hi], fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, n));
}

function sanitizeConfig(input, base = DEFAULT_CONFIG) {
  const c = input && typeof input === 'object' ? input : {};
  const out = { ...base };
  for (const k of ['enabled', 'webSearch', 'files', 'quotesTool', 'healthTool', 'guardEnabled', 'guardFailOpen']) if (c[k] !== undefined) out[k] = c[k] === true || c[k] === 'true';
  if (c.model !== undefined) { const m = String(c.model).trim(); if (MODEL_RE.test(m)) out.model = m; }
  for (const k of ['reportModel', 'guardModel']) if (c[k] !== undefined) { const m = String(c[k]).trim(); if (MODEL_RE.test(m)) out[k] = m; }
  if (c.fallbackModels !== undefined) {
    const raw = Array.isArray(c.fallbackModels) ? c.fallbackModels : String(c.fallbackModels).split(/[\s,;]+/);
    out.fallbackModels = [...new Set(raw.map(x => String(x).trim()).filter(x => MODEL_RE.test(x)))].slice(0, 5);
  }
  if (c.guardMode !== undefined && ['block', 'log'].includes(c.guardMode)) out.guardMode = c.guardMode;
  if (c.reasoningEffort !== undefined && EFFORTS.includes(c.reasoningEffort)) out.reasoningEffort = c.reasoningEffort;
  if (c.disabledMessage !== undefined) out.disabledMessage = String(c.disabledMessage).slice(0, 300) || DEFAULT_CONFIG.disabledMessage;
  for (const k of Object.keys(LIMITS)) {
    if (c[k] === undefined) continue;
    const n = clampNum(c[k], LIMITS[k], base[k]);
    out[k] = k === 'temperature' ? Math.round(n * 100) / 100 : Math.round(n);
  }
  return out;
}

let cfgCache = { at: 0, value: null };
async function getConfig(s, { fresh = false } = {}) {
  if (!fresh && cfgCache.value && Date.now() - cfgCache.at < 10000) return cfgCache.value;
  const stored = await s.get('ai-config', { type: 'json', consistency: 'strong' }).catch(() => null);
  const value = sanitizeConfig(stored || {});
  cfgCache = { at: Date.now(), value };
  return value;
}
async function setConfig(s, patch) {
  const cur = await getConfig(s, { fresh: true });
  const next = sanitizeConfig(patch, cur);
  next.updatedAt = Date.now();
  await s.setJSON('ai-config', next);
  cfgCache = { at: Date.now(), value: next };
  return next;
}

// ---------------------------------------------------------------- per-user access
// null = "use the global default". Stored per userId.
function sanitizeAccess(input) {
  const c = input && typeof input === 'object' ? input : {};
  const tri = v => (v === true || v === 'true' ? true : v === false || v === 'false' ? false : null);
  const num = (v, r) => (v === null || v === undefined || v === '' ? null : Math.round(clampNum(v, r, null)));
  const out = {
    enabled: tri(c.enabled), webSearch: tri(c.webSearch), files: tri(c.files),
    dailyLimit: num(c.dailyLimit, [0, 100000]), windowLimit: num(c.windowLimit, [1, 500]), maxTokens: num(c.maxTokens, [200, 16000]),
    model: MODEL_RE.test(String(c.model || '').trim()) ? String(c.model).trim() : null,
    note: String(c.note || '').slice(0, 200), updatedAt: Date.now()
  };
  for (const k of ['dailyLimit', 'windowLimit', 'maxTokens']) if (Number.isNaN(out[k])) out[k] = null;
  return out;
}
async function getAccess(s, userId) {
  return (await s.get(`ai-access:${userId}`, { type: 'json', consistency: 'strong' }).catch(() => null)) || null;
}
function effectiveAccess(cfg, access) {
  const a = access || {};
  return {
    enabled: cfg.enabled && a.enabled !== false,
    blockedBy: !cfg.enabled ? 'global' : a.enabled === false ? 'user' : null,
    webSearch: cfg.webSearch && (a.webSearch ?? true),
    files: cfg.files && (a.files ?? true),
    dailyLimit: a.dailyLimit ?? cfg.userDailyLimit,
    windowLimit: a.windowLimit ?? cfg.userWindowLimit,
    windowMinutes: cfg.userWindowMinutes,
    maxTokens: a.maxTokens ?? cfg.maxTokens,
    model: a.model || cfg.model,
    models: [...new Set([a.model || cfg.model, cfg.model, ...(cfg.fallbackModels || [])])]
  };
}

// ---------------------------------------------------------------- usage
function kyivDayKey(d = new Date()) {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Kyiv', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  return p; // YYYY-MM-DD
}
async function getUsage(s, userId, day = kyivDayKey()) {
  return (await s.get(`ai-usage:${userId}:${day}`, { type: 'json', consistency: 'strong' }).catch(() => null)) || { count: 0, tokens: 0, last: 0 };
}
async function addUsage(s, userId, tokens = 0, day = kyivDayKey()) {
  await atomicUpdateJSON(`ai-usage:${userId}:${day}`, { count: 0, tokens: 0, last: 0 }, cur => ({
    count: Number(cur.count || 0) + 1, tokens: Number(cur.tokens || 0) + Math.max(0, Math.round(tokens)), last: Date.now()
  }), { store: s });
}
async function resetUsage(s, userId, day = kyivDayKey()) { await s.delete(`ai-usage:${userId}:${day}`).catch(() => {}); }

// ---------------------------------------------------------------- Groq
async function callGroq({ model, messages, tools, maxTokens, temperature, reasoningEffort, timeoutMs = 20000 }) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const body = { model, messages, temperature, max_tokens: maxTokens };
    if (tools && tools.length) { body.tools = tools; body.tool_choice = 'auto'; }
    if (reasoningEffort && /gpt-oss/.test(model)) body.reasoning_effort = reasoningEffort;
    const r = await fetch(GROQ_URL, {
      method: 'POST', signal: ctl.signal,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.GROQ_API_KEY}` },
      body: JSON.stringify(body)
    });
    if (!r.ok) {
      const detail = await r.text().catch(() => '');
      const err = new Error('GROQ_ERROR'); err.status = r.status; err.detail = detail.slice(0, 400);
      err.retryAfter = Number(r.headers.get('retry-after') || 0) || undefined;
      throw err;
    }
    return await r.json();
  } catch (e) {
    if (e.name === 'AbortError') { const err = new Error('GROQ_TIMEOUT'); err.status = 'TIMEOUT'; throw err; }
    throw e;
  } finally { clearTimeout(timer); }
}


// ---------------------------------------------------------------- multi-model fallback
const FALLBACK_STATUS = new Set([404, 408, 429, 500, 502, 503, 504, 'TIMEOUT']);
function canFallback(err) {
  if (FALLBACK_STATUS.has(err.status)) return true;
  // unknown/decommissioned model or a model that cannot do tool calling
  return err.status === 400 && /model|tool|function|decommission/i.test(err.detail || '');
}
// Tries each model in order. Returns { completion, model, tried:[{model,status}] }.
async function callGroqChain(models, params) {
  const tried = [];
  let lastErr;
  for (const model of models) {
    try {
      const completion = await callGroq({ ...params, model });
      return { completion, model, tried };
    } catch (err) {
      lastErr = err; tried.push({ model, status: err.status || 'ERR' });
      if (!canFallback(err)) break;
    }
  }
  lastErr.tried = tried;
  throw lastErr;
}

// ---------------------------------------------------------------- prompt-injection guard
// Groq documents no output format for Llama Prompt Guard 2, so parse defensively:
// a number in [0,1] is the attack score; otherwise look for the labels.
function parseGuardOutput(text) {
  const t = String(text || '').trim();
  const num = t.match(/-?\d*\.?\d+(?:e-?\d+)?/i);
  if (num) { const v = Number(num[0]); if (v >= 0 && v <= 1) return { score: v, raw: t.slice(0, 80) }; }
  const l = t.toLowerCase();
  if (/malicious|injection|jailbreak|unsafe/.test(l)) return { score: 1, raw: t.slice(0, 80) };
  if (/benign|safe/.test(l)) return { score: 0, raw: t.slice(0, 80) };
  return { score: null, raw: t.slice(0, 80) };
}
async function guardCheck(cfg, text) {
  // The classifier window is 512 tokens: scan the first ~1500 characters.
  const sample = String(text || '').slice(0, 1500);
  if (!sample.trim()) return { flagged: false, score: 0 };
  try {
    const r = await callGroq({ model: cfg.guardModel, messages: [{ role: 'user', content: sample }], maxTokens: 20, temperature: 0, timeoutMs: 6000 });
    const p = parseGuardOutput(r.choices?.[0]?.message?.content);
    if (p.score === null) return { flagged: false, score: null, raw: p.raw, error: 'UNPARSEABLE' };
    return { flagged: p.score >= cfg.guardThreshold, score: p.score, raw: p.raw };
  } catch (e) {
    return { flagged: false, score: null, error: String(e.status || e.message) };
  }
}
async function recordIncident(s, inc) {
  await atomicUpdateJSON('ai-incidents', [], list => {
    const rows = Array.isArray(list) ? list : [];
    return [...rows, { id: crypto.randomUUID(), at: Date.now(), ...inc }].slice(-200);
  }, { store: s });
}
async function recentIncidents(s) { const l = await s.get('ai-incidents', { type: 'json', consistency: 'strong' }).catch(() => null); return Array.isArray(l) ? l : []; }

// ---------------------------------------------------------------- web tools
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:');
  }
  return true;
}
async function assertPublicUrl(raw) {
  let u;
  try { u = new URL(String(raw)); } catch { throw new Error('Некоректне посилання'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Дозволені лише http/https');
  if (u.username || u.password) throw new Error('Посилання з логіном заборонені');
  if (u.port && !['80', '443'].includes(u.port)) throw new Error('Нестандартний порт заборонено');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Внутрішні адреси заборонені');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) throw new Error('Внутрішні адреси заборонені');
  return u;
}

function htmlToText(html) {
  return String(html || '')
    .replace(/<(script|style|noscript|svg|nav|footer|header|form|iframe)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<\/(p|div|li|h[1-6]|tr|blockquote|br)>|<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => { try { return String.fromCodePoint(Number(n)); } catch { return ' '; } })
    .replace(/[ \t\r\f\v]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();
}

// DNS-rebinding safe: the address is validated INSIDE the socket's own lookup, so the IP
// that is checked is exactly the IP that is connected to (no second, unchecked resolve).
function safeLookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { all: true, ...(options || {}) }).then(addrs => {
    const list = Array.isArray(addrs) ? addrs : [addrs];
    if (!list.length || list.some(a => isPrivateIp(a.address))) return cb(new Error('Внутрішні адреси заборонені'));
    if (options && options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  }).catch(cb);
}
function httpGet(u, { timeoutMs, maxBytes }) {
  const mod = u.protocol === 'https:' ? require('https') : require('http');
  return new Promise((resolve, reject) => {
    const req = mod.request(u, { method: 'GET', lookup: safeLookup, timeout: timeoutMs, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; TS_Daily-bot/1.0)', Accept: 'text/html,text/plain,application/json;q=0.9,*/*;q=0.5', 'Accept-Language': 'uk,en;q=0.8,ru;q=0.6' } }, res => {
      const chunks = []; let total = 0;
      res.on('data', c => { total += c.length; if (total <= maxBytes) chunks.push(c); else { res.destroy(); } });
      const done = () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      res.on('end', done); res.on('close', done);
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}
async function fetchText(url, { timeoutMs = 7000, maxBytes = 800000, maxRedirects = 3 } = {}) {
  let cur = await assertPublicUrl(url);
  for (let i = 0; i <= maxRedirects; i++) {
    const r = await httpGet(cur, { timeoutMs, maxBytes });
    if ([301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers.location; if (!loc) throw new Error('Redirect без Location');
      cur = await assertPublicUrl(new URL(loc, cur).toString()); continue;
    }
    if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);
    const ctype = String(r.headers['content-type'] || '').toLowerCase();
    if (!/text\/|json|xml|html/.test(ctype)) throw new Error('Непідтримуваний тип вмісту: ' + ctype.split(';')[0]);
    const raw = r.body.toString('utf8');
    return { url: cur.toString(), contentType: ctype, text: /html/.test(ctype) ? htmlToText(raw) : raw };
  }
  throw new Error('Забагато перенаправлень');
}

function parseDuckDuckGo(html) {
  const out = [];
  const re = /<a[^>]+class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>)?/g;
  let m;
  while ((m = re.exec(html)) && out.length < 8) {
    let href = m[1].replace(/&amp;/g, '&');
    const uddg = href.match(/[?&]uddg=([^&]+)/);
    if (uddg) { try { href = decodeURIComponent(uddg[1]); } catch {} }
    if (href.startsWith('//')) href = 'https:' + href;
    if (!/^https?:\/\//i.test(href)) continue;
    out.push({ title: htmlToText(m[2]).slice(0, 160), url: href, snippet: htmlToText(m[3] || '').slice(0, 300) });
  }
  return out;
}

async function webSearch(query, lang = 'uk') {
  const q = String(query || '').trim().slice(0, 200);
  if (!q) throw new Error('Порожній запит');
  const results = [];
  const errors = [];
  // 1) DuckDuckGo HTML (no API key). Optional Brave API if key is configured.
  if (process.env.BRAVE_API_KEY) {
    try {
      const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 6000);
      const r = await fetch('https://api.search.brave.com/res/v1/web/search?count=8&q=' + encodeURIComponent(q), { signal: ctl.signal, headers: { Accept: 'application/json', 'X-Subscription-Token': process.env.BRAVE_API_KEY } });
      clearTimeout(t);
      if (r.ok) { const d = await r.json(); for (const x of (d.web?.results || []).slice(0, 8)) results.push({ title: String(x.title || '').slice(0, 160), url: x.url, snippet: htmlToText(x.description || '').slice(0, 300) }); }
      else errors.push('brave HTTP ' + r.status);
    } catch (e) { errors.push('brave ' + (e.name || 'err')); }
  }
  if (!results.length) {
    try {
      const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 6000);
      const r = await fetch('https://html.duckduckgo.com/html/', { method: 'POST', signal: ctl.signal, headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (compatible; TS_Daily-bot/1.0)' }, body: 'q=' + encodeURIComponent(q) + '&kl=' + (lang === 'uk' ? 'ua-uk' : lang === 'ru' ? 'ru-ru' : 'wt-wt') });
      clearTimeout(t);
      if (r.ok) results.push(...parseDuckDuckGo(await r.text())); else errors.push('ddg HTTP ' + r.status);
    } catch (e) { errors.push('ddg ' + (e.name || 'err')); }
  }
  // 2) Fallback: Wikipedia / Wikiquote search APIs (stable, no key).
  if (!results.length) {
    for (const host of [`${lang === 'ru' ? 'ru' : 'uk'}.wikiquote.org`, 'en.wikiquote.org', `${lang === 'ru' ? 'ru' : 'uk'}.wikipedia.org`]) {
      try {
        const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 5000);
        const r = await fetch(`https://${host}/w/api.php?action=query&list=search&srlimit=5&format=json&origin=*&srsearch=${encodeURIComponent(q)}`, { signal: ctl.signal, headers: { 'User-Agent': 'TS_Daily-bot/1.0' } });
        clearTimeout(t);
        if (!r.ok) continue;
        const d = await r.json();
        for (const x of d.query?.search || []) results.push({ title: x.title, url: `https://${host}/wiki/${encodeURIComponent(String(x.title).replace(/ /g, '_'))}`, snippet: htmlToText(x.snippet || '').slice(0, 300) });
        if (results.length >= 5) break;
      } catch (e) { errors.push(host + ' ' + (e.name || 'err')); }
    }
  }
  return { results: results.slice(0, 8), errors };
}

// ---------------------------------------------------------------- quotes store
const GLOBAL_QUOTES_KEY = 'quotes:global';
function cleanQuote(q, extra = {}) {
  const text = String(q?.text || '').replace(/\s+/g, ' ').trim().slice(0, 400);
  const author = String(q?.author || '').replace(/\s+/g, ' ').trim().slice(0, 120);
  if (text.length < 8 || !author) return null;
  let url = '';
  try { const u = new URL(String(q?.url || '')); if (['http:', 'https:'].includes(u.protocol)) url = u.toString().slice(0, 400); } catch {}
  return {
    id: crypto.randomUUID(), text, author,
    source: String(q?.source || '').replace(/\s+/g, ' ').trim().slice(0, 160),
    url, lang: /^(uk|ru|en|pl|de|fr|es|it)$/.test(String(q?.lang || '')) ? q.lang : '',
    verified: extra.verified === true, by: extra.by || 'ai', addedAt: Date.now()
  };
}
function normQuote(t) { return String(t || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim(); }
async function addQuotes(s, key, list, extra = {}, cap = 120) {
  let added = 0, skipped = 0;
  await atomicUpdateJSON(key, { items: [] }, cur => {
    const items = Array.isArray(cur.items) ? cur.items.slice() : [];
    const seen = new Set(items.map(x => normQuote(x.text)));
    added = 0; skipped = 0;
    for (const raw of list) {
      const q = cleanQuote(raw, extra);
      if (!q || seen.has(normQuote(q.text))) { skipped++; continue; }
      seen.add(normQuote(q.text)); items.push(q); added++;
    }
    return { items: items.slice(-cap), updatedAt: Date.now() };
  }, { store: s });
  return { added, skipped };
}
async function getQuotes(s, key) {
  const d = await s.get(key, { type: 'json', consistency: 'strong' }).catch(() => null);
  return Array.isArray(d?.items) ? d.items : [];
}
async function deleteQuote(s, key, id) {
  let removed = false;
  await atomicUpdateJSON(key, { items: [] }, cur => {
    const items = (Array.isArray(cur.items) ? cur.items : []);
    const next = items.filter(x => x.id !== id);
    removed = next.length !== items.length;
    return removed ? { items: next, updatedAt: Date.now() } : undefined;
  }, { store: s });
  return removed;
}

module.exports = {
  safeLookup,
  GROQ_URL, DEFAULT_CONFIG, sanitizeConfig, getConfig, setConfig,
  sanitizeAccess, getAccess, effectiveAccess,
  kyivDayKey, getUsage, addUsage, resetUsage,
  callGroq, callGroqChain, guardCheck, parseGuardOutput, recordIncident, recentIncidents, webSearch, fetchText, htmlToText, parseDuckDuckGo, assertPublicUrl, isPrivateIp,
  GLOBAL_QUOTES_KEY, cleanQuote, addQuotes, getQuotes, deleteQuote
};
