const { store } = require('./lib/store');
const { validateSession, extractToken, listSessionsForUser, getSessionPublicId, revokeSessionById, revokeOtherSessions, sessionKey } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest } = require('./lib/security');
const { recordActivity } = require('./lib/activity');

function json(statusCode, body) {
  return { statusCode, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  if (!['GET','POST'].includes(event.httpMethod)) return json(405, { error: 'Method Not Allowed' });
  if (event.httpMethod !== 'GET' && !isSameOriginRequest(event)) return json(403,{error:'Недозволене походження запиту'});
  try {
    const s = store();
    if (await enforceIpBan(s, event)) return json(403, { error: 'Цей IP-адрес заблоковано' });
    const token = extractToken(event);
    const sess = await validateSession(s, token, event);
    if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });

    if (event.httpMethod === 'GET') {
      const sessions = await listSessionsForUser(s, sess.userId);
      return json(200, {
        ok: true,
        currentSessionId: getSessionPublicId(token, sess),
        sessions: sessions.map(x => ({
          sessionId: getSessionPublicId('', x),
          current: x.sessionId === getSessionPublicId(token, sess),
          createdAt: x.createdAt,
          lastActive: x.lastActive,
          expiresAt: x.expiresAt,
          ip: x.ip,
          ipLastSeen: x.ipLastSeen,
          ipChanges: Number(x.ipChanges || 0),
          device: x.device,
          authMethod: x.authMethod || 'password'
        }))
      });
    }

    const body = JSON.parse(event.body || '{}');
    if (body.action === 'revoke') {
      if (!body.sessionId) return json(400, { error: 'Не вказано сесію' });
      if (String(body.sessionId) === getSessionPublicId(token, sess)) return json(400, { error: 'Поточну сесію заверши через кнопку «Вийти»' });
      const ok = await revokeSessionById(s, sess.userId, body.sessionId, token);
      if (!ok) return json(404, { error: 'Сесію не знайдено або вона вже завершена' });
      await recordActivity(s, sess.userId, 'session-revoked-by-user', { targetSessionId: String(body.sessionId).slice(0,32) });
      return json(200, { ok: true });
    }
    if (body.action === 'revoke-others') {
      const count = await revokeOtherSessions(s, sess.userId, token);
      await recordActivity(s, sess.userId, 'all-other-sessions-revoked', { count });
      return json(200, { ok: true, count });
    }
    return json(400, { error: 'Невідома дія' });
  } catch (err) {
    return json(500, { error: 'Внутрішня помилка сервера' });
  }
};
