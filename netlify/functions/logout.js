const { store } = require('./lib/store');
const { isSameOriginRequest } = require('./lib/security');
const { deleteSession, extractToken, clearSessionCookie } = require('./lib/session');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  if (!isSameOriginRequest(event)) return { statusCode: 403, body: JSON.stringify({ error: 'Недозволене походження запиту' }) };
  try {
    const s = store();
    await deleteSession(s, extractToken(event), 'logout');
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearSessionCookie() }, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Внутрішня помилка сервера' }) };
  }
};
