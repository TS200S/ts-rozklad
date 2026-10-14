'use strict';
// Static health-check of the deployed front-end (index.html). It catches the class of
// bugs that make buttons "disappear" or stop working: a script syntax error, a button
// whose onclick handler no longer exists, a tab button without its pane, missing UI ids.
const vm = require('vm');

const check = (id, label, status, detail) => ({ id, label, status, detail });
const TABS_REQUIRED = ['today', 'week', 'all', 'subjects', 'calendar', 'lectures', 'edit', 'notes', 'health', 'help', 'settings'];
const IDS_REQUIRED = ['ai-avatar-btn', 'ai-chat-panel', 'ai-chat-input', 'ai-chat-list', 'bell-btn', 'notes-modal-overlay', 'lock-screen'];
// functions that exist in the browser or are language keywords and may appear as "name(" in handlers
const BUILTIN = new Set(['if', 'for', 'while', 'switch', 'return', 'function', 'event', 'confirm', 'alert', 'prompt', 'window', 'document', 'this', 'JSON', 'Number', 'String', 'Boolean', 'parseInt', 'parseFloat', 'Math', 'Date', 'Array', 'Object', 'setTimeout', 'setInterval', 'clearTimeout', 'location', 'history', 'navigator', 'localStorage', 'stopPropagation', 'preventDefault', 'open', 'close', 'click', 'focus', 'blur', 'select', 'remove', 'add', 'toggle', 'getElementById', 'querySelector', 'querySelectorAll', 'closest', 'reset', 'submit', 'reload', 'stringify', 'parse', 'trim', 'toFixed', 'push', 'splice', 'filter', 'map', 'includes', 'replace', 'slice', 'test', 'call', 'apply', 'bind', 'then', 'catch', 'finally', 'matches', 'contains', 'back', 'print', 'scrollTo', 'scrollIntoView']);

function inlineScripts(html) {
  const out = []; const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi; let m;
  while ((m = re.exec(html))) out.push(m[1]);
  return out;
}

function analyzeIndexHtml(html) {
  const checks = [];
  const scripts = inlineScripts(html);
  const code = scripts.join('\n;\n');

  // 1. syntax of every inline script
  const syntaxErrors = [];
  scripts.forEach((src, i) => { try { new vm.Script(src, { filename: `inline-script-${i + 1}.js` }); } catch (e) { syntaxErrors.push(`script #${i + 1}: ${String(e.message).slice(0, 120)}`); } });
  checks.push(check('site-syntax', 'Синтаксис JavaScript сайту', syntaxErrors.length ? 'FAIL' : 'PASS', syntaxErrors.length ? syntaxErrors.join('; ') : `Перевірено ${scripts.length} inline-скриптів — помилок немає.`));

  // 2. required elements
  const missingIds = IDS_REQUIRED.filter(id => !new RegExp(`id=["']${id}["']`).test(html));
  checks.push(check('site-ids', 'Ключові елементи інтерфейсу', missingIds.length ? 'FAIL' : 'PASS', missingIds.length ? 'Відсутні: ' + missingIds.join(', ') : 'Кнопка ІІ, чат, сповіщення, модалки й екран входу на місці.'));

  // 3. tabs: button -> pane -> ALL_TABS
  const tabsBar = (html.match(/<div class="tabs">([\s\S]*?)<\/div>\s*<\/div>/) || [])[1] || '';
  const btnTabs = [...tabsBar.matchAll(/<button[^>]*class="tab-btn[^"]*"[^>]*onclick="switchTab\('([\w-]+)'\)"/g)].map(m => m[1]);
  const arr = (code.match(/const ALL_TABS\s*=\s*\[([^\]]*)\]/) || [])[1] || '';
  const allTabs = [...arr.matchAll(/'([\w-]+)'/g)].map(m => m[1]);
  const panes = [...html.matchAll(/<div id="tab-([\w-]+)"/g)].map(m => m[1]);
  const problems = [];
  if (btnTabs.join() !== allTabs.join()) problems.push(`кнопки вкладок (${btnTabs.join(',') || '—'}) ≠ ALL_TABS (${allTabs.join(',') || '—'}) — порядок/склад має збігатися`);
  const noPane = allTabs.filter(t => !panes.includes(t)); if (noPane.length) problems.push('немає контейнера tab-' + noPane.join(', tab-'));
  const missingTabs = TABS_REQUIRED.filter(t => !btnTabs.includes(t)); if (missingTabs.length) problems.push('немає кнопки вкладки: ' + missingTabs.join(', '));
  checks.push(check('site-tabs', 'Кнопки вкладок', problems.length ? 'FAIL' : 'PASS', problems.length ? problems.join('; ') : `Усі ${btnTabs.length} вкладок мають кнопку, контейнер і запис у ALL_TABS.`));

  // 4. every inline handler points to an existing function
  const defined = new Set();
  for (const m of code.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)/g)) defined.add(m[1]);
  for (const m of code.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) defined.add(m[1]);
  for (const m of code.matchAll(/\bwindow\.([A-Za-z_$][\w$]*)\s*=/g)) defined.add(m[1]);
  const used = new Map();
  const attrRe = /\bon(?:click|change|input|keydown|keyup|submit|focus|blur)=(?:"([^"]*)"|'([^']*)')/g;
  for (const m of html.matchAll(attrRe)) {
    const v = m[1] ?? m[2];
    for (const c of v.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(/g)) { const n = c[1]; if (!BUILTIN.has(n)) used.set(n, (used.get(n) || 0) + 1); }
  }
  const undef = [...used.keys()].filter(n => !defined.has(n));
  checks.push(check('site-handlers', 'Обробники кнопок (onclick)', undef.length ? 'FAIL' : 'PASS', undef.length ? 'Кнопки викликають неіснуючі функції: ' + undef.slice(0, 15).join(', ') : `Перевірено ${used.size} обробників — усі функції існують.`));

  // 5. exports / sizes
  checks.push(check('site-size', 'Розмір сторінки', html.length > 900000 ? 'WARN' : 'PASS', `${Math.round(html.length / 1024)} КБ HTML.`));
  return checks;
}

async function runSiteCheck(origin) {
  const checks = [];
  let html = '';
  try {
    const r = await fetch(origin + '/index.html', { headers: { 'Cache-Control': 'no-cache' } });
    html = await r.text();
    checks.push(check('site-fetch', 'Завантаження index.html', r.ok ? 'PASS' : 'FAIL', `HTTP ${r.status}, ${Math.round(html.length / 1024)} КБ.`));
    if (!r.ok) return checks;
  } catch (e) { return [check('site-fetch', 'Завантаження index.html', 'FAIL', 'Не вдалося отримати сторінку: ' + (e.name || 'error'))]; }
  checks.push(...analyzeIndexHtml(html));
  for (const [path, label] of [['/sw.js', 'Service Worker файл'], ['/manifest.json', 'PWA manifest']]) {
    try { const r = await fetch(origin + path); checks.push(check('site-' + path.slice(1), label, r.ok ? 'PASS' : 'WARN', `HTTP ${r.status}`)); }
    catch { checks.push(check('site-' + path.slice(1), label, 'WARN', 'Недоступний')); }
  }
  return checks;
}

module.exports = { analyzeIndexHtml, runSiteCheck, TABS_REQUIRED };
