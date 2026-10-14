const crypto = require('crypto');
const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest, rateLimit, getClientIp } = require('./lib/security');
const core = require('./lib/ai-core');
const H = require('./lib/health');

function cleanText(v, n = 2000) { return String(v ?? '').slice(0, n); }
function validDeadline(v) { return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(String(v || '')) ? String(v) : ''; }
const J = (statusCode, body) => ({ statusCode, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) });

// Additive/reversible actions run immediately. Destructive or overwriting ones are
// returned to the client for an explicit "Підтвердити" click before anything is written.
const RISKY_TOOLS = new Set(['delete_note', 'update_note', 'health_delete_day']);
const TEXT_MIME = /^(text\/|application\/json$)/;

function fn(name, description, properties = {}, required = []) {
  return { type: 'function', function: { name, description, parameters: { type: 'object', properties, required } } };
}
const S = (description) => ({ type: 'string', description });
const N = (description) => ({ type: 'number', description });

function buildTools(cfg, acc) {
  const t = [
    fn('add_note', 'Додати нотатку/завдання з необов’язковим дедлайном. Для кількох кроків виклич окремо для кожного.', { text: S('Текст'), deadline: S('YYYY-MM-DDTHH:MM, якщо відомий') }, ['text']),
    fn('mark_note_done', 'Позначити нотатку виконаною за id.', { noteId: S('id нотатки') }, ['noteId']),
    fn('set_saturday_override', 'За який будній день відпрацьовується субота.', { date: S('YYYY-MM-DD суботи; порожньо = найближча'), dayIndex: { type: 'integer', description: '0=Пн..4=Пт' } }, ['dayIndex']),
    fn('delete_note', 'Видалити нотатку за id (застосунок сам спитає підтвердження).', { noteId: S('id') }, ['noteId']),
    fn('update_note', 'Змінити текст/дедлайн нотатки (застосунок спитає підтвердження).', { noteId: S('id'), text: S('новий текст'), deadline: S('новий дедлайн') }, ['noteId'])
  ];
  if (cfg.healthTool) t.push(
    fn('health_log', 'Записати/оновити показники здоров’я за день (лише передані поля змінюються).', { date: S('YYYY-MM-DD, за замовчуванням сьогодні'), sleep: N('години сну'), mood: N('настрій 1-5'), water: N('склянок води за день (абсолютне значення)'), waterAdd: N('додати стільки склянок до поточного значення'), steps: N('кроки'), workout: N('хвилини тренування'), weight: N('вага, кг'), note: S('коментар') }),
    fn('health_get', 'Отримати записи здоров’я за останні N днів і цілі.', { days: N('1-60, за замовчуванням 7') }),
    fn('health_set_goals', 'Змінити денні цілі здоров’я.', { sleep: N('год сну'), water: N('склянок'), steps: N('кроків'), workout: N('хвилин') }),
    fn('health_delete_day', 'Видалити запис здоров’я за дату (застосунок спитає підтвердження).', { date: S('YYYY-MM-DD') }, ['date'])
  );
  if (cfg.quotesTool) t.push(
    fn('quotes_list', 'Показати збережені цитати користувача (id, текст, автор, джерело).', { limit: N('макс. 30') }),
    fn('save_quotes', 'Зберегти цитати у запас. Автор і (якщо це книга/фільм/промова) джерело ОБОВ’ЯЗКОВІ. Бери цитати лише з результатів web_search/fetch_url, не вигадуй.', { quotes: { type: 'array', description: 'Список цитат', items: { type: 'object', properties: { text: S('текст цитати дослівно'), author: S('автор'), source: S('книга/твір/промова, якщо відомо'), url: S('сторінка, звідки взято'), lang: S('uk|ru|en|...') }, required: ['text', 'author'] } } }, ['quotes']),
    fn('delete_quote', 'Видалити цитату за id.', { quoteId: S('id цитати') }, ['quoteId'])
  );
  if (acc.webSearch) t.push(
    fn('web_search', 'Пошук в інтернеті. Повертає заголовки, посилання й уривки.', { query: S('пошуковий запит'), lang: S('uk|ru|en') }, ['query']),
    fn('fetch_url', 'Відкрити сторінку за посиланням і прочитати її текст (наприклад вікіцитати).', { url: S('https://...') }, ['url'])
  );
  if (acc.files) t.push(
    fn('save_files_to_note', 'Прикріпити файли, які користувач додав у чат, до нотатки. Якщо noteId не вказано — буде створено нову нотатку з text.', { noteId: S('id існуючої нотатки (необов’язково)'), text: S('текст нової нотатки'), deadline: S('дедлайн') }),
    fn('read_note_file', 'Прочитати вміст текстового файлу, прикріпленого до нотатки.', { noteId: S('id нотатки'), fileId: S('id файлу') }, ['noteId', 'fileId'])
  );
  return t;
}

function resolveSatIndex(satRotation, dateStr) {
  if (!satRotation || satRotation.enabled !== true) return 5;
  const ov = satRotation.overrides && satRotation.overrides[dateStr];
  if (Number.isInteger(ov) && ov >= 0 && ov <= 4) return ov;
  if (!satRotation.anchorDate) return 5;
  const anchor = new Date(satRotation.anchorDate + 'T00:00:00');
  const target = new Date(dateStr + 'T00:00:00');
  if (isNaN(anchor.getTime()) || isNaN(target.getTime())) return 5;
  const weeks = Math.round((target - anchor) / (7 * 24 * 60 * 60 * 1000));
  return ((Number(satRotation.anchorDayIdx || 0) + weeks) % 5 + 5) % 5;
}

function kyivNow() {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Kyiv', weekday: 'long', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(new Date());
  const get = t => parts.find(p => p.type === t)?.value;
  return { dateKey: `${get('year')}-${get('month')}-${get('day')}`, weekday: get('weekday'), time: `${get('hour')}:${get('minute')}` };
}
function t2m(t) { const [h, m] = String(t).split(':').map(Number); return (h || 0) * 60 + (m || 0); }
function hhmm(mins) { const h = Math.floor(mins / 60) % 24, m = ((mins % 60) + 60) % 60; return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0'); }

function buildContext(data, name, ctx) {
  const { cfg, acc, quotesCount, files, saveToNotes } = ctx;
  const weekdayMap = { Monday: 0, Tuesday: 1, Wednesday: 2, Thursday: 3, Friday: 4, Saturday: 5, Sunday: 6 };
  const { dateKey, weekday, time } = kyivNow();
  const dayIdx = weekdayMap[weekday];
  const effIdx = dayIdx === 5 ? resolveSatIndex(data.satRotation, dateKey) : dayIdx;
  const dayNames = ['понеділок', 'вівторок', 'середа', 'четвер', 'п’ятниця', 'субота', 'неділя'];
  const subjById = {}; (data.subjects || []).forEach(s => { subjById[s.id] = s; });
  const todaySlots = (data.schedule?.[effIdx] || []).slice().sort((a, b) => String(a.time).localeCompare(String(b.time)));
  const scheduleLines = todaySlots.length
    ? todaySlots.map(sl => `- ${sl.time}–${hhmm(t2m(sl.time) + Number(sl.duration || 0))} ${subjById[sl.subjId]?.name || '?'}${subjById[sl.subjId]?.teacher ? ' (' + subjById[sl.subjId].teacher + ')' : ''}`).join('\n')
    : '(пар немає)';

  const thisWeekSatDate = new Date(dateKey + 'T00:00:00');
  thisWeekSatDate.setDate(thisWeekSatDate.getDate() + (5 - dayIdx));
  const satEffIdx = resolveSatIndex(data.satRotation, thisWeekSatDate.toISOString().slice(0, 10));
  const weekLines = [0, 1, 2, 3, 4, 5, 6].map(i => {
    const useIdx = i === 5 && data.satRotation?.enabled ? satEffIdx : i;
    const daySlots = (data.schedule?.[useIdx] || []).slice().sort((a, b) => String(a.time).localeCompare(String(b.time)));
    const names = daySlots.map(sl => subjById[sl.subjId]?.name || '?');
    const totalMin = daySlots.reduce((s, sl) => s + Number(sl.duration || 0), 0);
    const rotNote = i === 5 && data.satRotation?.enabled ? ` (за ${dayNames[satEffIdx]})` : '';
    return `${dayNames[i]}${rotNote}: ${names.length ? names.join(', ') + ` (${names.length} пар${totalMin ? ', ' + (totalMin / 60).toFixed(1) + ' год' : ''})` : 'пар немає'}`;
  }).join('\n');

  const notes = Array.isArray(data.notes) ? data.notes : [];
  const open = notes.filter(n => !n.done);
  const nowTs = Date.now();
  const noteLines = open.length
    ? open.slice(0, 40).map(n => {
        let status = '';
        if (n.deadline) {
          const t = new Date(n.deadline).getTime();
          if (t < nowTs) status = ' [ПРОСТРОЧЕНО]'; else if (t - nowTs < 24 * 3600 * 1000) status = ' [дедлайн сьогодні/завтра]';
        }
        const att = Array.isArray(n.attachments) && n.attachments.length ? ' 📎' + n.attachments.map(a => `${String(a.name).slice(0, 40)}(fileId=${a.id})`).join(',') : '';
        return `- id=${n.id} :: ${String(n.text || '').slice(0, 200)}${n.deadline ? ' (дедлайн: ' + n.deadline.replace('T', ' ') + ')' : ''}${status}${att}`;
      }).join('\n')
    : '(відкритих нотаток немає)';

  let healthBlock = '';
  if (cfg.healthTool) {
    const goals = H.safeHealthGoals(data.healthGoals);
    const journal = H.safeHealthJournal(data.healthJournal);
    const sum = H.summarize(journal, goals, 7, dateKey);
    const today = journal[dateKey];
    healthBlock = `\nЗдоров’я (сьогодні ${dateKey}): ${today ? JSON.stringify(today) : 'записів немає'}. Цілі: сон ${goals.sleep} год, вода ${goals.water} склянок, кроки ${goals.steps}, тренування ${goals.workout} хв. За ${sum.days} дн.: сон ${sum.avgSleep ?? '—'}, настрій ${sum.avgMood ?? '—'}, вода ${sum.avgWater ?? '—'}, кроки ${sum.avgSteps ?? '—'}, тренування ${sum.avgWorkout ?? '—'} хв${sum.lastWeight ? ', остання вага ' + sum.lastWeight + ' кг' : ''}.\n`;
  }

  const siteHelp = 'Вкладки: «Сьогодні» (поточна пара), «Тиждень», «Всі», «Предмети», «Календар» (.ics), «Лекції», «Редактор» (пари/період/одноразові), «Нотатки» (дедлайни + приватні файли), «Здоров’я» (сон, настрій, вода, кроки, тренування, вага, цілі, цитати), «Довідка», «Налаш.» (push, пароль, сесії, ротація субот, нагадування, тема). Якщо щось зламане — написати адміністрації TS_Daily.';

  const filesBlock = files.length
    ? `\nКористувач прикріпив до цього повідомлення файли (${files.length}). ${saveToNotes ? 'Він просить зберегти їх у нотатки — виклич save_files_to_note.' : 'Зберігати у нотатки лише якщо про це просять (тоді save_files_to_note).'}\n`
    : '';

  return `Ти — ІІ-помічник у застосунку TS_Daily для студента на ім'я ${name || 'Студент'}. Зараз ${dayNames[dayIdx]}, ${dateKey}, ${time} (Київ).

Розклад сьогодні:
${scheduleLines}

Розклад тижня:
${weekLines}

Відкриті нотатки (використовуй id із списку, НІКОЛИ не вигадуй id):
${noteLines}
${healthBlock}${cfg.quotesTool ? `\nУ запасі цитат користувача: ${quotesCount}.\n` : ''}${filesBlock}
Про застосунок: ${siteHelp}

Правила:
- Мова відповіді — мова користувача (за замовчуванням українська; якщо пише російською — російською).
- Відповідай повно й по суті, без обривів і води. Порівняння, розклади, плани, графіки подавай markdown-ТАБЛИЦЯМИ; списки — для переліків; код — у блоках.
- Не вигадуй факти. Для актуальних даних (новини, ціни, «хто зараз…», точні цитати) ${acc.webSearch ? 'спочатку виклич web_search, за потреби fetch_url, і вкажи джерела посиланнями' : 'скажи, що доступу до інтернету немає'}.
- Час закінчення пари бери лише з розкладу вище.
- Дії роби інструментами: нотатки (add_note/mark_note_done/update_note/delete_note), субота (set_saturday_override), здоров’я (health_*), цитати (save_quotes/delete_quote), файли (save_files_to_note/read_note_file). Підтвердження для delete/update запитає сам застосунок.
- Цитати: кожна — з автором і джерелом (книга/твір/промова), знайдена через пошук; не придумуй і не перекручуй. Коли просять «оновити/поповнити цитати» — знайди 8–12 нових різних (укр. і світові автори, спорт, навчання, дисципліна), збережи через save_quotes.
- Здоров’я: ти не лікар; порадь звернутись до лікаря при тривожних симптомах. Записуй показники лише коли користувач їх повідомив.
- Для флешкарток — текст «Питання/Відповідь» без інструментів.
- Якщо бачиш прострочені нотатки чи завантажений день — ненав’язливо згадай.`;
}

function noteSummary(notes, noteId) {
  const n = (notes || []).find(x => x.id === noteId);
  if (!n) return 'нотатку (не знайдено, можливо вже видалена)';
  return `«${String(n.text || '').slice(0, 80)}»${n.deadline ? ' (дедлайн ' + n.deadline.replace('T', ' ') + ')' : ''}`;
}
const norm = t => String(t || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();

// ------------------------------------------------------------------ tool execution
async function execTool(ctx, name, args) {
  const { s, userId } = ctx;
  const key = `schedule-data:${userId}`;
  const cap = (txt, n = 4000) => String(txt).slice(0, n);
  switch (name) {
    case 'add_note': {
      const text = cleanText(args.text, 4000);
      if (!text) return 'error: empty text';
      const note = { id: crypto.randomUUID(), text, deadline: validDeadline(args.deadline), done: false, createdAt: Date.now(), link: '', attachments: [] };
      await atomicUpdateJSON(key, ctx.data, cur => ({ ...cur, notes: [...(Array.isArray(cur.notes) ? cur.notes : []), note], updatedAt: Date.now() }), { store: s });
      ctx.changed.data = true; return `ok, created note id=${note.id}`;
    }
    case 'mark_note_done': {
      const noteId = cleanText(args.noteId, 120); let found = false;
      await atomicUpdateJSON(key, ctx.data, cur => ({ ...cur, notes: (Array.isArray(cur.notes) ? cur.notes : []).map(n => { if (n.id === noteId) { found = true; return { ...n, done: true }; } return n; }), updatedAt: Date.now() }), { store: s });
      if (found) ctx.changed.data = true; return found ? 'ok, marked done' : 'error: note not found';
    }
    case 'set_saturday_override': {
      const dayIndex = Number(args.dayIndex);
      if (!Number.isInteger(dayIndex) || dayIndex < 0 || dayIndex > 4) return 'error: invalid dayIndex';
      let dateStr = /^\d{4}-\d{2}-\d{2}$/.test(String(args.date || '')) ? args.date : '';
      if (!dateStr) { const d = new Date(kyivNow().dateKey + 'T00:00:00'); d.setDate(d.getDate() + ((6 - d.getDay() + 7) % 7)); dateStr = d.toISOString().slice(0, 10); }
      await atomicUpdateJSON(key, ctx.data, cur => {
        const rot = cur.satRotation && typeof cur.satRotation === 'object' ? cur.satRotation : { enabled: true, anchorDate: '', anchorDayIdx: 0, overrides: {} };
        return { ...cur, satRotation: { ...rot, enabled: true, overrides: { ...(rot.overrides || {}), [dateStr]: dayIndex } }, updatedAt: Date.now() };
      }, { store: s });
      ctx.changed.data = true; return `ok, saturday ${dateStr} -> weekday ${dayIndex}`;
    }
    // ---- health
    case 'health_log': {
      if (!ctx.cfg.healthTool) return 'error: disabled';
      const date = H.isDate(args.date) ? args.date : kyivNow().dateKey;
      let saved = null;
      await atomicUpdateJSON(key, ctx.data, cur => {
        const journal = H.safeHealthJournal(cur.healthJournal);
        const prev = journal[date] || H.safeEntry({});
        const patch = {};
        for (const k of ['sleep', 'mood', 'water', 'steps', 'workout', 'weight']) if (args[k] !== undefined && args[k] !== null) patch[k] = args[k];
        if (args.waterAdd !== undefined && Number.isFinite(Number(args.waterAdd))) patch.water = (prev.water || 0) + Number(args.waterAdd);
        if (args.note !== undefined) patch.note = args.note;
        journal[date] = H.safeEntry({ ...prev, ...patch });
        saved = journal[date];
        return { ...cur, healthJournal: journal, healthGoals: H.safeHealthGoals(cur.healthGoals), updatedAt: Date.now() };
      }, { store: s });
      ctx.changed.data = true; return `ok, ${date}: ${JSON.stringify(saved)}`;
    }
    case 'health_get': {
      if (!ctx.cfg.healthTool) return 'error: disabled';
      const days = Math.min(60, Math.max(1, Number(args.days) || 7));
      const fresh = await s.get(key, { type: 'json', consistency: 'strong' }).catch(() => null) || {};
      const goals = H.safeHealthGoals(fresh.healthGoals);
      const sum = H.summarize(H.safeHealthJournal(fresh.healthJournal), goals, days, kyivNow().dateKey);
      return cap(JSON.stringify(sum), 6000);
    }
    case 'health_set_goals': {
      if (!ctx.cfg.healthTool) return 'error: disabled';
      let goals;
      await atomicUpdateJSON(key, ctx.data, cur => { goals = H.safeHealthGoals({ ...H.safeHealthGoals(cur.healthGoals), ...args }); return { ...cur, healthGoals: goals, updatedAt: Date.now() }; }, { store: s });
      ctx.changed.data = true; return `ok, goals=${JSON.stringify(goals)}`;
    }
    // ---- quotes
    case 'quotes_list': {
      const items = (await core.getQuotes(s, `quotes:${userId}`)).slice(-Math.min(30, Number(args.limit) || 15));
      return items.length ? cap(items.map(q => `id=${q.id} :: «${q.text}» — ${q.author}${q.source ? ', ' + q.source : ''}`).join('\n'), 5000) : '(цитат ще немає)';
    }
    case 'save_quotes': {
      if (!ctx.cfg.quotesTool) return 'error: disabled';
      const list = (Array.isArray(args.quotes) ? args.quotes : []).slice(0, 20);
      if (!list.length) return 'error: no quotes';
      // A quote counts as "verified" only when its text really occurs in a page or
      // search snippet that was fetched during this request.
      const corpus = ctx.corpus.join(' ');
      let added = 0, skipped = 0, verified = 0;
      for (const q of list) {
        const ok = norm(q?.text).length >= 12 && corpus.includes(norm(q.text));
        const r = await core.addQuotes(s, `quotes:${userId}`, [q], { verified: ok, by: 'ai' });
        added += r.added; skipped += r.skipped; if (ok && r.added) verified++;
      }
      if (added) ctx.changed.quotes = true;
      return `ok, added=${added}, skipped(duplicates/invalid)=${skipped}, verified_in_sources=${verified}`;
    }
    case 'delete_quote': {
      const removed = await core.deleteQuote(s, `quotes:${userId}`, cleanText(args.quoteId, 80));
      if (removed) ctx.changed.quotes = true; return removed ? 'ok, deleted' : 'error: not found';
    }
    // ---- web
    case 'web_search': {
      if (!ctx.acc.webSearch) return 'error: web search disabled';
      const r = await core.webSearch(args.query, ['uk', 'ru', 'en'].includes(args.lang) ? args.lang : 'uk');
      for (const x of r.results) { ctx.seenUrls.add(x.url); ctx.corpus.push(norm(x.title + ' ' + x.snippet)); }
      if (!r.results.length) return 'Нічого не знайдено' + (r.errors.length ? ' (' + r.errors.join(', ') + ')' : '');
      return cap(r.results.map((x, i) => `${i + 1}. ${x.title}\n${x.url}\n${x.snippet}`).join('\n\n'), 4500);
    }
    case 'fetch_url': {
      if (!ctx.acc.webSearch) return 'error: web access disabled';
      try {
        const r = await core.fetchText(args.url, { timeoutMs: 7000 });
        ctx.seenUrls.add(r.url); ctx.corpus.push(norm(r.text).slice(0, 120000));
        return cap(`URL: ${r.url}\n${r.text}`, 6500);
      } catch (e) { return 'error: ' + String(e.message || 'fetch failed').slice(0, 120); }
    }
    // ---- files
    case 'save_files_to_note': {
      if (!ctx.acc.files) return 'error: files disabled';
      if (!ctx.files.length) return 'error: no files attached to this message';
      let noteId = cleanText(args.noteId, 120);
      if (noteId) {
        const fresh = await s.get(key, { type: 'json', consistency: 'strong' }).catch(() => null);
        if (!(fresh?.notes || []).some(n => n.id === noteId)) return 'error: note not found';
      } else {
        noteId = crypto.randomUUID();
        const text = cleanText(args.text, 4000) || ('Файли: ' + ctx.files.map(f => f.name).join(', ')).slice(0, 300);
        const note = { id: noteId, text, deadline: validDeadline(args.deadline), done: false, createdAt: Date.now(), link: '', attachments: [] };
        await atomicUpdateJSON(key, ctx.data, cur => ({ ...cur, notes: [...(Array.isArray(cur.notes) ? cur.notes : []), note], updatedAt: Date.now() }), { store: s });
        ctx.changed.data = true;
      }
      ctx.fileUpload = { noteId };
      return `ok, noteId=${noteId}; застосунок сам завантажить ${ctx.files.length} файл(ів) у цю нотатку після відповіді`;
    }
    case 'read_note_file': {
      if (!ctx.acc.files) return 'error: files disabled';
      const fresh = await s.get(key, { type: 'json', consistency: 'strong' }).catch(() => null) || {};
      const note = (fresh.notes || []).find(n => n.id === args.noteId);
      const att = (note?.attachments || []).find(a => a.id === args.fileId);
      if (!att) return 'error: file not found';
      if (!TEXT_MIME.test(att.mime)) return `error: файл ${att.mime} ІІ прочитати не може (лише текстові: txt, csv, md, json)`;
      const blob = await s.get(`file:${userId}:${att.id}`, { type: 'blob' }).catch(() => null);
      if (!blob) return 'error: blob missing';
      const text = Buffer.from(await blob.arrayBuffer()).toString('utf8');
      return cap(`Файл ${att.name}:\n${text}`, 12000);
    }
    default: return 'error: unknown tool';
  }
}

function pendingSummary(name, args, data) {
  if (name === 'delete_note') return `Видалити нотатку ${noteSummary(data.notes, args.noteId)}?`;
  if (name === 'update_note') return `Оновити нотатку ${noteSummary(data.notes, args.noteId)}${args.text ? ' — новий текст: «' + String(args.text).slice(0, 80) + '»' : ''}${args.deadline ? ', новий дедлайн: ' + String(args.deadline).replace('T', ' ') : ''}?`;
  if (name === 'health_delete_day') return `Видалити запис здоров’я за ${cleanText(args.date, 10)}?`;
  return 'Підтвердити дію?';
}

function groqErrorReply(err) {
  if (err.status === 429) return `Ліміт Groq вичерпано (запити/токени за хвилину чи за день). Спробуй через ${err.retryAfter ? err.retryAfter + ' с' : 'хвилину'}. Адмін може підняти ліміти або перейти на платний тариф Groq.`;
  if (err.status === 413 || /too large|reduce your message|tokens per minute/i.test(err.detail || '')) return 'Запит завеликий для ліміту токенів Groq за хвилину. Скороти повідомлення/файл або попроси адміна зменшити «довжину відповіді» чи підняти тариф Groq.';
  if (err.status === 'TIMEOUT') return 'ІІ відповідає надто довго (таймаут). Спробуй ще раз або сформулюй простіше.';
  return null;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return J(403, { error: 'Недозволене походження запиту' });
  if (!process.env.GROQ_API_KEY) return J(503, { error: 'ІІ-чат ще не налаштовано на сервері (немає GROQ_API_KEY)' });
  const startedAt = Date.now();
  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event); if (ipBan) return J(403, { error: 'Цей IP-адрес заблоковано' });
    const sess = await validateSession(s, extractToken(event), event); if (!sess) return J(401, { error: 'Сесія недійсна, увійди ще раз' });
    if (sess.banned) return J(403, { error: 'Акаунт заблоковано' });

    if (String(event.body || '').length > 90000) return J(413, { error: 'Повідомлення завелике' });
    let body; try { body = JSON.parse(event.body || '{}'); } catch { return J(400, { error: 'Некоректний JSON' }); }

    const cfg = await core.getConfig(s);
    const access = await core.getAccess(s, sess.userId);
    const acc = core.effectiveAccess(cfg, access);
    const usage = await core.getUsage(s, sess.userId);
    const publicState = { enabled: acc.enabled, blockedBy: acc.blockedBy, features: { web: acc.webSearch, files: acc.files, quotes: cfg.quotesTool, health: cfg.healthTool }, usage: { used: usage.count, limit: acc.dailyLimit, tokens: usage.tokens } };

    if (body.action === 'status') return J(200, { ...publicState, message: acc.enabled ? '' : (acc.blockedBy === 'user' ? 'Доступ до ІІ для твого акаунта вимкнено адміністратором.' : cfg.disabledMessage) });
    if (!acc.enabled) return J(403, { error: acc.blockedBy === 'user' ? 'Доступ до ІІ для твого акаунта вимкнено адміністратором.' : cfg.disabledMessage, aiDisabled: true, state: publicState });

    const data = await s.get(`schedule-data:${sess.userId}`, { type: 'json', consistency: 'strong' }).catch(() => null) || { schedule: [], subjects: [], notes: [] };

    // Path 1: the client confirmed a previously-proposed risky action - execute directly, no Groq call.
    if (body.confirmedAction && RISKY_TOOLS.has(body.confirmedAction.tool)) {
      const { tool, args } = body.confirmedAction;
      let replyText = '';
      await atomicUpdateJSON(`schedule-data:${sess.userId}`, data, cur => {
        if (tool === 'health_delete_day') {
          const d = cleanText(args?.date, 10); const j = H.safeHealthJournal(cur.healthJournal);
          replyText = j[d] ? 'Видалив запис здоров’я.' : 'Такого запису вже немає.'; delete j[d];
          return { ...cur, healthJournal: j, updatedAt: Date.now() };
        }
        const noteId = cleanText(args?.noteId, 120); const notes = Array.isArray(cur.notes) ? cur.notes : [];
        if (tool === 'delete_note') {
          replyText = notes.some(n => n.id === noteId) ? 'Видалив нотатку.' : 'Цю нотатку вже не знайшов — можливо, видалена раніше.';
          return { ...cur, notes: notes.filter(n => n.id !== noteId), updatedAt: Date.now() };
        }
        let found = false;
        const updated = notes.map(n => { if (n.id !== noteId) return n; found = true; return { ...n, text: args.text ? cleanText(args.text, 4000) : n.text, deadline: args.deadline !== undefined ? (validDeadline(args.deadline) || n.deadline) : n.deadline }; });
        replyText = found ? 'Оновив нотатку.' : 'Цю нотатку не знайшов — можливо, видалена раніше.';
        return { ...cur, notes: updated, updatedAt: Date.now() };
      }, { store: s });
      return J(200, { reply: replyText, done: true, dataChanged: true });
    }

    // Limits: per-user window, per-user daily, global per-minute.
    if (usage.count >= acc.dailyLimit) return J(429, { error: `Денний ліміт ІІ-повідомлень вичерпано (${acc.dailyLimit}). Завтра лічильник обнулиться.`, state: publicState });
    const userLimit = await rateLimit(s, `ai-chat:user:${sess.userId}`, acc.windowLimit, acc.windowMinutes * 60 * 1000);
    if (!userLimit.allowed) return J(429, { error: `Забагато повідомлень, спробуй за ${userLimit.retryAfter} с.`, state: publicState });
    const globalLimit = await rateLimit(s, 'ai-chat:global', cfg.globalPerMinute, 60 * 1000);
    if (!globalLimit.allowed) return J(429, { error: 'ІІ зараз перевантажений запитами від усіх користувачів, спробуй за хвилину.', state: publicState });

    const message = cleanText(body.message, 6000).trim();
    if (!message) return J(400, { error: 'Порожнє повідомлення' });

    // Attached files: text content goes to the model, the files themselves are
    // uploaded by the browser into a note when the model calls save_files_to_note.
    const files = acc.files ? (Array.isArray(body.files) ? body.files : []).slice(0, 5).filter(f => f && typeof f.name === 'string').map(f => ({ name: cleanText(f.name, 120), mime: cleanText(f.mime, 100), size: Number(f.size) || 0, text: typeof f.text === 'string' ? f.text.slice(0, 12000) : '' })) : [];
    let userContent = message;
    if (files.length) {
      let budget = 24000;
      userContent += '\n\n[Прикріплені файли]\n' + files.map((f, i) => {
        const t = f.text && budget > 0 ? f.text.slice(0, budget) : ''; budget -= t.length;
        return `#${i + 1} ${f.name} (${f.mime || '?'}, ${Math.round(f.size / 1024)} КБ)${t ? '\nВміст:\n"""\n' + t + '\n"""' : '\n(вміст ІІ недоступний — не текстовий файл)'}`;
      }).join('\n');
    }

    // Security shield: classifier model screens the message (and attached text) before the main model sees it.
    let guardInfo = null;
    if (cfg.guardEnabled) {
      const scanText = message + (files.length ? '\n' + files.map(f => f.text).filter(Boolean).join('\n') : '');
      const g = await core.guardCheck(cfg, scanText);
      guardInfo = g;
      if (g.error && !cfg.guardFailOpen) return J(503, { error: 'Перевірка безпеки тимчасово недоступна, спробуй пізніше.' });
      if (g.flagged) {
        const ip = getClientIp(event);
        const blocked = cfg.guardMode === 'block';
        await core.recordIncident(s, { userId: sess.userId, username: sess.username, ip, score: g.score, blocked, excerpt: message.slice(0, 220) }).catch(() => {});
        if (cfg.guardAutoBlockStrikes > 0) {
          const since = Date.now() - 24 * 3600 * 1000;
          const strikes = (await core.recentIncidents(s)).filter(x => x.userId === sess.userId && x.at >= since).length;
          if (strikes >= cfg.guardAutoBlockStrikes) {
            await s.setJSON(`ai-access:${sess.userId}`, core.sanitizeAccess({ ...(access || {}), enabled: false, note: 'auto: щит безпеки (' + strikes + ' спроб за добу)' })).catch(() => {});
          }
        }
        if (blocked) return J(200, { reply: '🛡️ Запит відхилено системою безпеки (схожий на спробу обійти правила ІІ). Якщо це помилка — перефразуй.', blocked: true, state: publicState });
      }
    }

    const history = (Array.isArray(body.history) ? body.history : [])
      .slice(-cfg.historyMessages)
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
      .map(m => ({ role: m.role, content: cleanText(m.content, 4000) }));

    const quotesCount = cfg.quotesTool ? (await core.getQuotes(s, `quotes:${sess.userId}`)).length : 0;
    const ctx = { s, userId: sess.userId, data, cfg, acc, files, saveToNotes: body.saveToNotes === true, quotesCount, changed: { data: false, quotes: false }, seenUrls: new Set(), corpus: [], fileUpload: null };
    const name = cleanText(data.name || sess.username, 60);
    const messages = [{ role: 'system', content: buildContext(data, name, ctx) }, ...history, { role: 'user', content: userContent }];
    const tools = buildTools(cfg, acc);
    const toolsUsed = [];
    let tokens = 0, finalText = '', finish = 'stop', pending = [];
    let chain = acc.models.slice(); let modelUsed = chain[0]; let triedAll = [];

    try {
      for (let round = 0; round <= cfg.maxToolRounds; round++) {
        const budgetLeft = cfg.timeBudgetSec * 1000 - (Date.now() - startedAt);
        const allowTools = round < cfg.maxToolRounds && budgetLeft > 6000;
        const res = await core.callGroqChain(chain, {
          messages, tools: allowTools ? tools : undefined, maxTokens: acc.maxTokens,
          temperature: cfg.temperature, reasoningEffort: cfg.reasoningEffort, timeoutMs: Math.max(6000, Math.min(24000, budgetLeft + 4000))
        });
        const completion = res.completion; triedAll.push(...res.tried);
        if (res.model !== modelUsed) { modelUsed = res.model; chain = [res.model, ...chain.filter(m => m !== res.model)]; }
        tokens += Number(completion.usage?.total_tokens || 0);
        const choice = completion.choices?.[0]?.message;
        finish = completion.choices?.[0]?.finish_reason || 'stop';
        if (!choice) { finalText = 'Не вдалося отримати відповідь, спробуй ще раз.'; break; }
        const calls = choice.tool_calls || [];
        if (!calls.length) { finalText = String(choice.content || '').trim(); break; }

        messages.push({ role: 'assistant', content: choice.content || '', tool_calls: calls.map(c => ({ id: c.id, type: 'function', function: { name: c.function?.name, arguments: c.function?.arguments || '{}' } })) });
        for (const tc of calls) {
          const toolName = tc.function?.name; let args = {};
          try { args = JSON.parse(tc.function?.arguments || '{}'); } catch { args = {}; }
          toolsUsed.push(toolName);
          if (RISKY_TOOLS.has(toolName)) {
            pending.push({ summary: pendingSummary(toolName, args, data), action: { tool: toolName, args: { noteId: cleanText(args.noteId, 120) || undefined, text: args.text ? cleanText(args.text, 4000) : undefined, deadline: args.deadline ? cleanText(args.deadline, 20) : undefined, date: args.date ? cleanText(args.date, 10) : undefined } } });
            messages.push({ role: 'tool', tool_call_id: tc.id, content: 'queued: waiting for user confirmation' });
            continue;
          }
          let result;
          try { result = await execTool(ctx, toolName, args); } catch (e) { console.error('ai tool failed', toolName, e?.code || e?.message); result = 'error: ' + String(e?.message || 'failed').slice(0, 100); }
          messages.push({ role: 'tool', tool_call_id: tc.id, content: String(result).slice(0, 7000) });
        }
        if (pending.length) break; // wait for the human before going further
      }
    } catch (err) {
      const friendly = groqErrorReply(err);
      console.error('ai-chat groq failed', { status: err?.status, detail: err?.detail, tried: err?.tried });
      if (friendly) return J(200, { reply: friendly, dataChanged: ctx.changed.data, quotesChanged: ctx.changed.quotes, state: publicState });
      throw err;
    }

    // Deterministic fallback: the user asked to keep attached files but the model forgot the tool call.
    if (body.saveToNotes === true && files.length && !ctx.fileUpload && !pending.length) {
      try { await execTool(ctx, 'save_files_to_note', {}); } catch { /* ignore */ }
    }
    await core.addUsage(s, sess.userId, tokens).catch(() => {});
    const used = usage.count + 1;
    const state = { ...publicState, usage: { used, limit: acc.dailyLimit, tokens: usage.tokens + tokens } };
    const common = { model: modelUsed, fallback: modelUsed !== acc.models[0] ? { from: acc.models[0], to: modelUsed } : undefined, guard: guardInfo ? { score: guardInfo.score, error: guardInfo.error } : undefined, dataChanged: ctx.changed.data, quotesChanged: ctx.changed.quotes, fileUpload: ctx.fileUpload || undefined, toolsUsed, state };

    if (pending.length) {
      return J(200, { reply: pending.map(p => p.summary).join('\n'), needsConfirm: true, pending, ...common });
    }
    const truncated = finish === 'length';
    return J(200, { reply: cleanText(finalText, 24000) || (toolsUsed.length ? 'Готово.' : '...'), truncated, ...common });
  } catch (err) {
    const requestId = String(event.headers?.['x-nf-request-id'] || event.headers?.['X-Nf-Request-Id'] || '').slice(0, 80);
    console.error('ai-chat failed', { requestId, status: err?.status || 'UNKNOWN', name: err?.name || 'Error', message: err?.message, groqDetail: err?.detail });
    return J(500, { error: 'Не вдалося звʼязатись з ІІ', requestId: requestId || undefined });
  }
};

exports._test = { buildTools, execTool, buildContext };
