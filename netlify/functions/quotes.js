// Quotes API for the browser. GET returns the user's own quotes plus the shared pool.
// POST: add (manual), delete, clear. The AI assistant manages the same data via tools.
const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest, rateLimit } = require('./lib/security');
const core = require('./lib/ai-core');

const J = (statusCode, body) => ({ statusCode, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) });
const pub = q => ({ id: q.id, text: q.text, author: q.author, source: q.source || '', url: q.url || '', verified: !!q.verified, by: q.by || '', addedAt: q.addedAt || 0 });

exports.handler = async event => {
  if (!['GET', 'POST'].includes(event.httpMethod)) return { statusCode: 405, body: 'Method Not Allowed' };
  if (event.httpMethod === 'POST' && !isSameOriginRequest(event)) return J(403, { error: 'Недозволене походження запиту' });
  try {
    const s = store();
    if (await enforceIpBan(s, event)) return J(403, { error: 'IP заблоковано' });
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess || sess.banned) return J(401, { error: 'Сесія недійсна' });
    const mine = `quotes:${sess.userId}`;

    if (event.httpMethod === 'GET') {
      const [own, pool] = await Promise.all([core.getQuotes(s, mine), core.getQuotes(s, core.GLOBAL_QUOTES_KEY)]);
      return J(200, { ok: true, own: own.slice(-120).map(pub), pool: pool.slice(-120).map(pub) });
    }

    const rl = await rateLimit(s, `quotes:${sess.userId}`, 60, 10 * 60 * 1000);
    if (!rl.allowed) return J(429, { error: 'Забагато запитів' });
    let body; try { body = JSON.parse(event.body || '{}'); } catch { return J(400, { error: 'Некоректний JSON' }); }

    if (body.action === 'add') {
      const r = await core.addQuotes(s, mine, [{ text: body.text, author: body.author, source: body.source, url: body.url }], { verified: false, by: 'user' });
      return r.added ? J(200, { ok: true }) : J(400, { error: 'Потрібні текст (від 8 символів) і автор; дублікати не додаються' });
    }
    if (body.action === 'delete') return J(200, { ok: await core.deleteQuote(s, mine, String(body.id || '').slice(0, 80)) });
    if (body.action === 'clear') { await s.setJSON(mine, { items: [], updatedAt: Date.now() }); return J(200, { ok: true }); }
    return J(400, { error: 'Невідома дія' });
  } catch (err) {
    console.error('quotes failed', err?.code || err?.name);
    return J(500, { error: 'Не вдалося обробити запит' });
  }
};
