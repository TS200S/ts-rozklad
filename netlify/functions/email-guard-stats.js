const { store } = require('./lib/store');
const { getStats } = require('./lib/email-guard');
const { queueStats } = require('./lib/email-queue');
const { validateSession, extractToken } = require('./lib/session');


exports.handler = async event => {
  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };
  try {
    const s = store();
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess) return { statusCode: 403, body: JSON.stringify({ error: 'Доступ заборонено' }) };
    const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
    const master = String(process.env.ADMIN_USERNAME || '').trim().toLowerCase();
    if (!user || !(user.role === 'admin' || String(user.username).toLowerCase() === master)) return { statusCode: 403, body: JSON.stringify({ error: 'Доступ заборонено' }) };
    const stats = await getStats();
    const queue = await queueStats();
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ ...stats, queue }) };
  } catch {
    return { statusCode: 500, body: JSON.stringify({ error: 'Помилка' }) };
  }
};
