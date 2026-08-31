const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest } = require('./lib/security');
const { recordActivity } = require('./lib/activity');
function json(statusCode, body) { return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }; }
exports.handler = async event => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method Not Allowed' });
  if (!isSameOriginRequest(event)) return json(403, { error: 'Недозволене походження запиту' });
  try {
    const s = store();
    if (await enforceIpBan(s, event)) return json(403, { error: 'Цей IP-адрес заблоковано' });
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
    const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
    if (!user) return json(401, { error: 'Акаунт не знайдено' });
    const body = JSON.parse(event.body || '{}');
    if (body.action === 'status') return json(200, { ok: true, security: { newDeviceEmail: user.security?.newDeviceEmail !== false, requireNewDeviceEmail: user.security?.requireNewDeviceEmail === true, requireEveryLoginEmail: user.security?.requireEveryLoginEmail === true } });
    if (body.action !== 'update') return json(400, { error: 'Невідома дія' });
    const requireNewDeviceEmail = body.requireNewDeviceEmail === true;
    const requireEveryLoginEmail = body.requireEveryLoginEmail === true;
    if ((requireNewDeviceEmail || requireEveryLoginEmail) && (!user.email || user.emailVerified !== true)) return json(400, { error: 'Спочатку підтвердь email акаунта, щоб увімкнути додаткове підтвердження входу' });
    user.security = {
      newDeviceEmail: body.newDeviceEmail !== false,
      requireNewDeviceEmail,
      requireEveryLoginEmail
    };
    await s.setJSON(`user:${user.username}`, user);
    await recordActivity(s, user.userId, 'security-settings-changed', { security: user.security });
    return json(200, { ok: true, security: user.security });
  } catch (err) { return json(500, { error: 'Внутрішня помилка сервера' }); }
};
