const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const s = store();
    const sess = await validateSession(s, extractToken(event));
    if (!sess) {
      return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна, увійди ще раз' }) };
    }

    const data = await s.get(`schedule-data:${sess.userId}`, { type: 'json' });

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data || null)
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
