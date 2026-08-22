const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan } = require('./lib/security');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return { statusCode: 403, body: JSON.stringify({ error: 'Цей IP-адрес заблоковано', ipBlocked: true }) };
    const sess = await validateSession(s, extractToken(event));
    if (!sess) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна, увійди ще раз' }) };
    }
    if (sess.banned) return { statusCode: 403, body: JSON.stringify({ error: 'Акаунт заблоковано', banned: true }) };
    const userId = sess.userId;

    const body = JSON.parse(event.body || '{}');
    const { schedule, subjects, cfg, notes } = body;

    if (!schedule || !subjects) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає даних розкладу' }) };
    }

    await s.setJSON(`schedule-data:${userId}`, {
      schedule,
      subjects,
      notes: notes || [],
      notif10: cfg?.notif10 !== false,
      notif5: cfg?.notif5 !== false,
      updatedAt: Date.now()
    });

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
