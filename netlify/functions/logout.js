const { store } = require('./lib/store');
const { deleteSession, extractToken } = require('./lib/session');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  try {
    const s = store();
    await deleteSession(s, extractToken(event));
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
