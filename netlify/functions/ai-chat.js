const crypto = require('crypto');
const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest, rateLimit, getClientIp } = require('./lib/security');

const GROQ_MODEL = 'llama-3.3-70b-versatile';
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

function cleanText(v, n = 2000) { return String(v ?? '').slice(0, n); }
function validDeadline(v) { return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(String(v || '')) ? String(v) : ''; }

// Only note-mutating actions are exposed as tools - schedule/lesson structure
// stays read-only to the AI (it's riskier to mutate correctly: subject ids,
// time slots, etc). Additive/reversible actions run immediately; destructive
// or overwriting ones are returned to the client for explicit confirmation
// before anything is written.
const SAFE_TOOLS = new Set(['add_note', 'mark_note_done', 'set_saturday_override']);
const RISKY_TOOLS = new Set(['delete_note', 'update_note']);

const TOOLS = [
  { type: 'function', function: { name: 'add_note', description: 'Додати нову нотатку/завдання (наприклад домашнє завдання) з необов\u2019язковим дедлайном. Якщо користувач просить розбити велике завдання на кілька кроків - виклич цей інструмент окремо для кожного кроку в одній відповіді.', parameters: { type: 'object', properties: { text: { type: 'string', description: 'Текст нотатки/завдання' }, deadline: { type: 'string', description: 'Дедлайн у форматі YYYY-MM-DDTHH:MM, якщо відомий' } }, required: ['text'] } } },
  { type: 'function', function: { name: 'mark_note_done', description: 'Позначити існуючу нотатку виконаною за її id.', parameters: { type: 'object', properties: { noteId: { type: 'string' } }, required: ['noteId'] } } },
  { type: 'function', function: { name: 'set_saturday_override', description: 'Встановити, за який будній день конкретна субота відпрацьовує (ротація субот). Якщо користувач не назвав дату явно, застосовується до найближчої суботи.', parameters: { type: 'object', properties: { date: { type: 'string', description: 'Дата суботи у форматі YYYY-MM-DD; залиш порожнім для найближчої суботи' }, dayIndex: { type: 'integer', description: '0=Понеділок,1=Вівторок,2=Середа,3=Четвер,4=Пятниця' } }, required: ['dayIndex'] } } },
  { type: 'function', function: { name: 'delete_note', description: 'Видалити існуючу нотатку за id. Це незворотна дія - завжди виклич цей інструмент, якщо користувач просить видалити щось, навіть якщо не певен; застосунок сам запитає підтвердження у людини перед видаленням.', parameters: { type: 'object', properties: { noteId: { type: 'string' } }, required: ['noteId'] } } },
  { type: 'function', function: { name: 'update_note', description: 'Змінити текст і/або дедлайн існуючої нотатки за id. Застосунок запитає підтвердження у людини перед збереженням.', parameters: { type: 'object', properties: { noteId: { type: 'string' }, text: { type: 'string' }, deadline: { type: 'string' } }, required: ['noteId'] } } }
];

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

function buildContext(data, name) {
  const weekdayMap = { Monday: 0, Tuesday: 1, Wednesday: 2, Thursday: 3, Friday: 4, Saturday: 5, Sunday: 6 };
  const { dateKey, weekday, time } = kyivNow();
  const dayIdx = weekdayMap[weekday];
  const effIdx = dayIdx === 5 ? resolveSatIndex(data.satRotation, dateKey) : dayIdx;
  const dayNames = ['понеділок', 'вівторок', 'середа', 'четвер', 'п\u2019ятниця', 'субота', 'неділя'];
  const subjById = {}; (data.subjects || []).forEach(s => { subjById[s.id] = s; });
  const todaySlots = (data.schedule?.[effIdx] || []).slice().sort((a, b) => String(a.time).localeCompare(String(b.time)));
  const scheduleLines = todaySlots.length
    ? todaySlots.map(sl => `- ${sl.time} ${subjById[sl.subjId]?.name || '?'}${subjById[sl.subjId]?.teacher ? ' (' + subjById[sl.subjId].teacher + ')' : ''}`).join('\n')
    : '(пар немає)';

  // Full week overview so the AI can actually analyze workload (busiest
  // day, free days, subject frequency) instead of only seeing today.
  // This week's Saturday is resolved by its own date, independent of what
  // weekday today happens to be.
  const thisWeekSatDate = new Date(dateKey + 'T00:00:00');
  thisWeekSatDate.setDate(thisWeekSatDate.getDate() + (5 - dayIdx));
  const satEffIdx = resolveSatIndex(data.satRotation, thisWeekSatDate.toISOString().slice(0, 10));
  const weekLines = [0, 1, 2, 3, 4, 5, 6].map(i => {
    const useIdx = i === 5 && data.satRotation?.enabled ? satEffIdx : i;
    const daySlots = (data.schedule?.[useIdx] || []).slice().sort((a, b) => String(a.time).localeCompare(String(b.time)));
    const names = daySlots.map(sl => subjById[sl.subjId]?.name || '?');
    const rotNote = i === 5 && data.satRotation?.enabled ? ` (за ${dayNames[satEffIdx]})` : '';
    return `${dayNames[i]}${rotNote}: ${names.length ? names.join(', ') + ` (${names.length})` : 'пар немає'}`;
  }).join('\n');

  const notes = Array.isArray(data.notes) ? data.notes : [];
  const open = notes.filter(n => !n.done);
  const nowTs = Date.now();
  const noteLines = open.length
    ? open.slice(0, 40).map(n => {
        let status = '';
        if (n.deadline) {
          const t = new Date(n.deadline).getTime();
          if (t < nowTs) status = ' [ПРОСТРОЧЕНО]';
          else if (t - nowTs < 24 * 3600 * 1000) status = ' [дедлайн сьогодні/завтра]';
        }
        return `- id=${n.id} :: ${String(n.text || '').slice(0, 200)}${n.deadline ? ' (дедлайн: ' + n.deadline.replace('T', ' ') + ')' : ''}${status}`;
      }).join('\n')
    : '(відкритих нотаток немає)';

  const journal = data.healthJournal && typeof data.healthJournal === 'object' ? data.healthJournal : {};
  const recentDates = Object.keys(journal).sort().reverse().slice(0, 3);
  const sleepVals = recentDates.map(d => journal[d]?.sleep).filter(v => typeof v === 'number');
  const healthLine = sleepVals.length ? `Середній сон за останні дні: ${(sleepVals.reduce((a, b) => a + b, 0) / sleepVals.length).toFixed(1)} год.` : 'Даних про сон поки немає.';

  return `Ти — дружній, короткий і чесний помічник у застосунку TS_Daily для студента на ім'я ${name || 'Студент'}.
Сьогодні ${dayNames[dayIdx]}, ${dateKey}, зараз ${time} за Києвом.

Розклад на сьогодні:
${scheduleLines}

Розклад на весь тиждень (для аналізу завантаженості, пошуку вільних днів тощо):
${weekLines}

Відкриті нотатки/завдання (використовуй id у викликах інструментів, НІКОЛИ не вигадуй id):
${noteLines}

${healthLine}

Правила:
- Відповідай українською, коротко й по суті, без зайвої води.
- Не вигадуй дані, яких немає вище — якщо чогось не знаєш, так і скажи.
- Якщо просять додати завдання/нагадування — виклич add_note.
- Якщо просять позначити щось виконаним — mark_note_done.
- Якщо просять видалити або змінити існуючу нотатку — виклич delete_note/update_note з правильним id; підтвердження в людини запитає сам застосунок, тобі підтверджувати не потрібно.
- Якщо просять змінити, за який день відпрацьовує субота — виклич set_saturday_override.
- Якщо просять розбити завдання на кроки/підзадачі — виклич add_note окремо для кожного кроку в одній відповіді.
- Якщо просять картки для повторення/флешкартки з якоїсь теми чи нотатки — просто згенеруй їх текстом у форматі "Питання: ... / Відповідь: ...", без виклику інструментів.
- Якщо бачиш прострочені нотатки або завантажений день — можеш сам ненав\u2019язливо це згадати та порадити з чого почати.`;
}

async function callGroq(messages, useTools) {
  const r = await fetch(GROQ_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
    body: JSON.stringify({ model: GROQ_MODEL, messages, ...(useTools ? { tools: TOOLS, tool_choice: 'auto' } : {}), temperature: 0.5, max_tokens: 500 })
  });
  if (!r.ok) {
    const detail = await r.text().catch(() => '');
    const err = new Error('GROQ_ERROR'); err.status = r.status; err.detail = detail.slice(0, 300);
    throw err;
  }
  return r.json();
}

function noteSummary(notes, noteId) {
  const n = (notes || []).find(x => x.id === noteId);
  if (!n) return 'нотатку (не знайдено, можливо вже видалена)';
  return `«${String(n.text || '').slice(0, 80)}»${n.deadline ? ' (дедлайн ' + n.deadline.replace('T', ' ') + ')' : ''}`;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return { statusCode: 403, body: JSON.stringify({ error: 'Недозволене походження запиту' }) };
  if (!process.env.GROQ_API_KEY) return { statusCode: 503, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'AI-чат ще не налаштовано на сервері' }) };
  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event); if (ipBan) return { statusCode: 403, body: JSON.stringify({ error: 'Цей IP-адрес заблоковано' }) };
    const sess = await validateSession(s, extractToken(event), event); if (!sess) return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна, увійди ще раз' }) };
    if (sess.banned) return { statusCode: 403, body: JSON.stringify({ error: 'Акаунт заблоковано' }) };

    // Protect the shared Groq free-tier quota: per-user and global caps.
    const ip = getClientIp(event);
    const userLimit = await rateLimit(s, `ai-chat:user:${sess.userId}`, 20, 10 * 60 * 1000);
    if (!userLimit.allowed) return { statusCode: 429, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: `Забагато повідомлень, спробуй за ${userLimit.retryAfter} с.` }) };
    const globalLimit = await rateLimit(s, 'ai-chat:global', 25, 60 * 1000);
    if (!globalLimit.allowed) return { statusCode: 429, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'AI зараз перевантажений запитами від усіх користувачів, спробуй за хвилину.' }) };

    if (String(event.body || '').length > 20000) return { statusCode: 413, body: JSON.stringify({ error: 'Повідомлення завелике' }) };
    const body = JSON.parse(event.body || '{}');

    const data = await s.get(`schedule-data:${sess.userId}`, { type: 'json', consistency: 'strong' }).catch(() => null) || { schedule: [], subjects: [], notes: [] };

    // Path 1: the client confirmed a previously-proposed risky action - just
    // execute it directly, no new Groq call needed.
    if (body.confirmedAction && RISKY_TOOLS.has(body.confirmedAction.tool)) {
      const { tool, args } = body.confirmedAction;
      const noteId = cleanText(args?.noteId, 120);
      let replyText = '';
      await atomicUpdateJSON(`schedule-data:${sess.userId}`, data, cur => {
        const notes = Array.isArray(cur.notes) ? cur.notes : [];
        if (tool === 'delete_note') {
          const existed = notes.some(n => n.id === noteId);
          replyText = existed ? 'Видалив нотатку.' : 'Цю нотатку вже не знайшов — можливо, видалена раніше.';
          return { ...cur, notes: notes.filter(n => n.id !== noteId), updatedAt: Date.now() };
        }
        if (tool === 'update_note') {
          let found = false;
          const updated = notes.map(n => {
            if (n.id !== noteId) return n;
            found = true;
            return { ...n, text: args.text ? cleanText(args.text, 4000) : n.text, deadline: args.deadline !== undefined ? (validDeadline(args.deadline) || n.deadline) : n.deadline };
          });
          replyText = found ? 'Оновив нотатку.' : 'Цю нотатку не знайшов — можливо, видалена раніше.';
          return { ...cur, notes: updated, updatedAt: Date.now() };
        }
        return cur;
      });
      return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ reply: replyText, done: true, dataChanged: true }) };
    }

    const message = cleanText(body.message, 2000).trim();
    if (!message) return { statusCode: 400, body: JSON.stringify({ error: 'Порожнє повідомлення' }) };
    const history = (Array.isArray(body.history) ? body.history : [])
      .slice(-12)
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
      .map(m => ({ role: m.role, content: cleanText(m.content, 2000) }));

    const name = cleanText(data.name || sess.username, 60);
    const systemPrompt = buildContext(data, name);
    const messages = [{ role: 'system', content: systemPrompt }, ...history, { role: 'user', content: message }];

    let completion;
    try { completion = await callGroq(messages, true); }
    catch (err) {
      if (err.status === 429) return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reply: 'Схоже, вичерпався спільний ліміт AI на сьогодні/зараз. Спробуй трохи пізніше.' }) };
      throw err;
    }
    const choice = completion.choices?.[0]?.message;
    if (!choice) return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reply: 'Не вдалося отримати відповідь, спробуй ще раз.' }) };

    const toolCalls = choice.tool_calls || [];
    if (!toolCalls.length) {
      return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ reply: cleanText(choice.content, 3000) || '...' }) };
    }

    const notesSnapshot = Array.isArray(data.notes) ? data.notes : [];
    const pendingActions = [];
    const toolResults = [];
    let anyChanged = false;

    for (const tc of toolCalls) {
      const toolName = tc.function?.name;
      let args = {};
      try { args = JSON.parse(tc.function?.arguments || '{}'); } catch { args = {}; }

      if (RISKY_TOOLS.has(toolName)) {
        const summary = toolName === 'delete_note'
          ? `Видалити нотатку ${noteSummary(notesSnapshot, args.noteId)}?`
          : `Оновити нотатку ${noteSummary(notesSnapshot, args.noteId)}${args.text ? ' — новий текст: «' + String(args.text).slice(0, 80) + '»' : ''}${args.deadline ? ', новий дедлайн: ' + String(args.deadline).replace('T', ' ') : ''}?`;
        pendingActions.push({ summary, action: { tool: toolName, args: { noteId: cleanText(args.noteId, 120), text: args.text ? cleanText(args.text, 4000) : undefined, deadline: args.deadline ? cleanText(args.deadline, 20) : undefined } } });
        continue;
      }

      if (!SAFE_TOOLS.has(toolName)) { toolResults.push({ role: 'tool', tool_call_id: tc.id, content: 'error: unknown tool' }); continue; }

      let toolResultText = 'ok';
      if (toolName === 'add_note') {
        const text = cleanText(args.text, 4000);
        if (!text) { toolResultText = 'error: empty text'; }
        else {
          const note = { id: crypto.randomUUID(), text, deadline: validDeadline(args.deadline), done: false, createdAt: Date.now(), link: '', attachments: [] };
          await atomicUpdateJSON(`schedule-data:${sess.userId}`, data, cur => ({ ...cur, notes: [...(Array.isArray(cur.notes) ? cur.notes : []), note], updatedAt: Date.now() }));
          toolResultText = `ok, created note id=${note.id}`;
        }
      } else if (toolName === 'mark_note_done') {
        const noteId = cleanText(args.noteId, 120);
        let found = false;
        await atomicUpdateJSON(`schedule-data:${sess.userId}`, data, cur => {
          const notes = (Array.isArray(cur.notes) ? cur.notes : []).map(n => { if (n.id === noteId) { found = true; return { ...n, done: true }; } return n; });
          return { ...cur, notes, updatedAt: Date.now() };
        });
        toolResultText = found ? 'ok, marked done' : 'error: note not found';
      } else if (toolName === 'set_saturday_override') {
        const dayIndex = Number(args.dayIndex);
        if (!Number.isInteger(dayIndex) || dayIndex < 0 || dayIndex > 4) { toolResultText = 'error: invalid dayIndex'; }
        else {
          let dateStr = /^\d{4}-\d{2}-\d{2}$/.test(String(args.date || '')) ? args.date : '';
          if (!dateStr) {
            const { dateKey: todayKey } = kyivNow();
            const d = new Date(todayKey + 'T00:00:00');
            d.setDate(d.getDate() + ((6 - d.getDay() + 7) % 7));
            dateStr = d.toISOString().slice(0, 10);
          }
          await atomicUpdateJSON(`schedule-data:${sess.userId}`, data, cur => {
            const rot = cur.satRotation && typeof cur.satRotation === 'object' ? cur.satRotation : { enabled: true, anchorDate: '', anchorDayIdx: 0, overrides: {} };
            return { ...cur, satRotation: { ...rot, enabled: true, overrides: { ...(rot.overrides || {}), [dateStr]: dayIndex } }, updatedAt: Date.now() };
          });
          toolResultText = `ok, saturday ${dateStr} set to weekday ${dayIndex}`;
        }
      }
      if (toolResultText.startsWith('ok')) anyChanged = true;
      toolResults.push({ role: 'tool', tool_call_id: tc.id, content: toolResultText });
    }

    if (pendingActions.length) {
      const reply = pendingActions.map(p => p.summary).join('\n');
      return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ reply, needsConfirm: true, pending: pendingActions, dataChanged: anyChanged }) };
    }

    const followUp = [...messages, choice, ...toolResults];
    let final;
    try { final = await callGroq(followUp, false); }
    catch { return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ reply: 'Готово.', dataChanged: anyChanged }) }; }
    const finalText = cleanText(final.choices?.[0]?.message?.content, 3000) || 'Готово.';
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ reply: finalText, dataChanged: anyChanged }) };
  } catch (err) {
    const requestId = String(event.headers?.['x-nf-request-id'] || event.headers?.['X-Nf-Request-Id'] || '').slice(0, 80);
    console.error('ai-chat failed', { requestId, code: err?.code || err?.status || 'UNKNOWN', name: err?.name || 'Error' });
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Не вдалося звʼязатись з AI', requestId: requestId || undefined }) };
  }
};
