const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, getClientIp } = require('./lib/security');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') return { statusCode: 405, body: 'Method Not Allowed' };
  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return { statusCode: 403, headers: {'Content-Type':'application/json'}, body: JSON.stringify({ error:'Цей IP-адрес заблоковано', ipBlocked:true }) };
    const sess = await validateSession(s, extractToken(event));
    if (!sess) return { statusCode: 401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error:'Сесія недійсна', sessionExpired:true }) };
    if (sess.banned) return { statusCode: 403, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error:'Акаунт заблоковано', banned:true }) };
    return {
      statusCode: 200,
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        ok:true, username:sess.username, expiresAt:sess.expiresAt,
        lastActive:sess.lastActive, ip:getClientIp(event)
      })
    };
  } catch (err) {
    return { statusCode:500, body:JSON.stringify({error:String(err)}) };
  }
};
