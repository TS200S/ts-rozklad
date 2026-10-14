'use strict';
// Refills the shared quote pool ("quotes:global") ahead of time.
// Flow per author: fetch Wikiquote page -> ask the model to copy quotes VERBATIM
// from that text -> keep a quote only if its text really occurs in the fetched page.
const core = require('./ai-core');

const AUTHORS = [
  ['Григорій Сковорода', 'uk'], ['Леся Українка', 'uk'], ['Тарас Шевченко', 'uk'], ['Іван Франко', 'uk'], ['Ліна Костенко', 'uk'],
  ['Василь Стус', 'uk'], ['Василь Сухомлинський', 'uk'], ['Януш Корчак', 'uk'], ['Антон Макаренко', 'uk'], ['Марк Аврелій', 'uk'],
  ['Сенека', 'uk'], ['Епіктет', 'uk'], ['Арістотель', 'uk'], ['Сократ', 'uk'], ['Конфуцій', 'uk'], ['Альберт Ейнштейн', 'uk'],
  ['Антуан де Сент-Екзюпері', 'uk'], ['Лев Толстой', 'uk'], ['Йоганн Вольфґанг фон Ґете', 'uk'], ['Вінстон Черчилль', 'uk'],
  ['Мартін Лютер Кінг', 'uk'], ['Нельсон Мандела', 'uk'], ['Мухаммед Алі', 'en'], ['Майкл Джордан', 'en'], ['Брюс Лі', 'en'],
  ['Пеле', 'en'], ['Арнольд Шварценеггер', 'en'], ['Віктор Франкл', 'uk'], ['Стів Джобс', 'uk'], ['Мері Кюрі', 'uk'],
  ['Бенджамін Франклін', 'uk'], ['Авраам Лінкольн', 'uk'], ['Жан-Жак Руссо', 'uk'], ['Ян Амос Коменський', 'uk']
];

function norm(t) { return String(t || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim(); }

function parseJsonArray(text) {
  const m = String(text || '').match(/\[[\s\S]*\]/);
  if (!m) return [];
  try { const a = JSON.parse(m[0]); return Array.isArray(a) ? a : []; } catch { return []; }
}

async function fetchAuthorPage(author, lang) {
  const slug = encodeURIComponent(author.replace(/ /g, '_'));
  const hosts = lang === 'en' ? ['en.wikiquote.org', 'uk.wikiquote.org'] : ['uk.wikiquote.org', 'en.wikiquote.org'];
  for (const h of hosts) {
    try { const r = await core.fetchText(`https://${h}/wiki/${slug}`, { timeoutMs: 7000 }); if (r.text.length > 400) return r; } catch { /* try next */ }
  }
  return null;
}

async function runRefill(s, { maxAuthors = 3, force = false } = {}) {
  const cfg = await core.getConfig(s, { fresh: true });
  if (!process.env.GROQ_API_KEY) return { ok: false, skipped: 'no GROQ_API_KEY' };
  if (!cfg.enabled || !cfg.quotesTool) return { ok: false, skipped: 'AI or quotes tool disabled' };
  const pool = await core.getQuotes(s, core.GLOBAL_QUOTES_KEY);
  if (!force && pool.length >= 100) return { ok: true, skipped: 'pool is full', pool: pool.length };

  const have = new Set(pool.map(q => q.author));
  const order = AUTHORS.slice().sort(() => Math.random() - 0.5).sort((a, b) => (have.has(a[0]) ? 1 : 0) - (have.has(b[0]) ? 1 : 0));
  let added = 0, tried = 0; const log = [];
  for (const [author, lang] of order) {
    if (tried >= maxAuthors) break;
    tried++;
    const page = await fetchAuthorPage(author, lang);
    if (!page) { log.push(`${author}: сторінку не отримано`); continue; }
    const pageNorm = norm(page.text);
    try {
      const { completion } = await core.callGroqChain([cfg.model, ...(cfg.fallbackModels || [])], {
        maxTokens: 1500, temperature: 0.2, reasoningEffort: 'low', timeoutMs: 20000,
        messages: [
          { role: 'system', content: 'Ти витягуєш цитати з наданого тексту. Копіюй цитати ДОСЛІВНО (мова оригіналу тексту), нічого не вигадуй і не переказуй. Відповідай лише JSON-масивом.' },
          { role: 'user', content: `Автор: ${author}\nЗ тексту нижче вибери до 8 коротких (до 220 символів) мотиваційних/мудрих цитат, корисних студенту. Формат: [{"text":"...","source":"твір/промова, якщо вказано в тексті, інакше порожньо"}]\n\nТЕКСТ:\n${page.text.slice(0, 9000)}` }
        ]
      });
      const items = parseJsonArray(completion.choices?.[0]?.message?.content);
      const good = items.filter(x => x && typeof x.text === 'string' && norm(x.text).length >= 12 && pageNorm.includes(norm(x.text)))
        .map(x => ({ text: x.text, author, source: x.source || '', url: page.url, lang: /uk\./.test(page.url) ? 'uk' : 'en' }));
      const r = await core.addQuotes(s, core.GLOBAL_QUOTES_KEY, good, { verified: true, by: 'auto' }, 200);
      added += r.added; log.push(`${author}: +${r.added} (запропоновано ${items.length}, перевірено ${good.length})`);
    } catch (e) { log.push(`${author}: помилка ${e.status || e.message}`); if (e.status === 429) break; }
  }
  const total = (await core.getQuotes(s, core.GLOBAL_QUOTES_KEY)).length;
  return { ok: true, added, pool: total, log };
}

module.exports = { runRefill, AUTHORS, parseJsonArray };
