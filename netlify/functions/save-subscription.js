const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest } = require('./lib/security');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  if (!isSameOriginRequest(event)) return { statusCode: 403, body: JSON.stringify({ error: 'Недозволене походження запиту' }) };

  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return { statusCode: 403, body: JSON.stringify({ error: 'Цей IP-адрес заблоковано', ipBlocked: true }) };
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна, увійди ще раз' }) };
    }
    const userId = sess.userId;

    if (sess.banned) return { statusCode: 403, body: JSON.stringify({ error: 'Акаунт заблоковано', banned: true }) };

    const body = JSON.parse(event.body || '{}');
    const { subscription, action } = body;
    const currentOrigin = String(process.env.URL || process.env.DEPLOY_PRIME_URL || '').replace(/\/$/, '');

    if (!subscription || !subscription.endpoint) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає підписки' }) };
    }

    const key = `subscriptions:${userId}`;
    const result = await atomicUpdateJSON(key, [], current => {
      const existing = Array.isArray(current) ? current : [];
      if (action === 'unsubscribe') {
        return existing.filter(sub => sub && sub.endpoint !== subscription.endpoint);
      }
      const updated = existing.filter(sub => sub && sub.endpoint !== subscription.endpoint);
      updated.push({ ...subscription, siteOrigin: currentOrigin || null, savedAt: Date.now() });
      return updated.slice(-20);
    }, { store: s });
    const updated = Array.isArray(result.value) ? result.value : [];

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, count: updated.length })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Внутрішня помилка сервера' }) };
  }
};
