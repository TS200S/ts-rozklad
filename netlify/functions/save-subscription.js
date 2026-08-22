const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const s = store();
    const sess = await validateSession(s, extractToken(event));
    if (!sess) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна, увійди ще раз' }) };
    }
    const userId = sess.userId;

    const body = JSON.parse(event.body || '{}');
    const { subscription, action } = body;

    if (!subscription || !subscription.endpoint) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає підписки' }) };
    }

    const key = `subscriptions:${userId}`;
    const existing = (await s.get(key, { type: 'json' })) || [];

    let updated;
    if (action === 'unsubscribe') {
      updated = existing.filter(sub => sub.endpoint !== subscription.endpoint);
    } else {
      updated = existing.filter(sub => sub.endpoint !== subscription.endpoint);
      updated.push(subscription);
    }

    await s.setJSON(key, updated);

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, count: updated.length })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
