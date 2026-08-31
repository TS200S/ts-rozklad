const crypto = require('crypto');
const { store } = require('./lib/store');
const { createSession, sessionCookie } = require('./lib/session');
const { enforceIpBan, rateLimit, getClientIp, protectCodeAttempt, safeCodeEqual, isSameOriginRequest } = require('./lib/security');
const { sendLoginCodeEmail } = require('./lib/mailer');
const { recordActivity } = require('./lib/activity');
function json(statusCode, body) { return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }; }
exports.handler = async event => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method Not Allowed' });
  if (!isSameOriginRequest(event)) return json(403, { error: 'Недозволене походження запиту' });
  try {
    const s = store();
    if (await enforceIpBan(s, event)) return json(403, { error: 'Цей IP-адрес заблоковано' });
    const body = JSON.parse(event.body || '{}');
    const challengeId = String(body.challengeId || '');
    const pending = await s.get(`pending-login:${challengeId}`, { type: 'json' }).catch(() => null);
    if (!pending) return json(400, { error: 'Запит на підтвердження не знайдено або прострочено' });
    if (pending.expiresAt <= Date.now()) { await s.delete(`pending-login:${challengeId}`).catch(() => {}); return json(400, { error: 'Код прострочено. Увійди ще раз.' }); }
    const ip = getClientIp(event);
    const rl = await rateLimit(s, `login-code:${challengeId}:${ip}`, 5, 15 * 60 * 1000);
    const globalRl = await protectCodeAttempt(s, 'login-code-global', pending.userId || pending.username, ip, 10, 15 * 60 * 1000);
    if (!rl.allowed || !globalRl.allowed) return json(429, { error: 'Забагато спроб. Запроси новий код.' });
    const code = String(body.code || '').trim();
    if (!/^\d{6}$/.test(code) || !safeCodeEqual(code, pending.codeHash || '')) {
      pending.attempts = (pending.attempts || 0) + 1;
      if (pending.attempts >= 5) await s.delete(`pending-login:${challengeId}`).catch(() => {});
      else await s.setJSON(`pending-login:${challengeId}`, pending);
      return json(400, { error: 'Невірний код' });
    }
    const user = await s.get(`user:${pending.username}`, { type: 'json' }).catch(() => null);
    if (!user || user.banned) return json(403, { error: 'Акаунт недоступний' });
    const { token, expiresAt } = await createSession(s, user.userId, user.username, pending.meta, { authMethod: 'password+email' });
    const devices = Array.isArray(user.trustedDeviceIds) ? user.trustedDeviceIds : [];
    if (pending.deviceId && !devices.includes(pending.deviceId)) devices.push(pending.deviceId);
    user.trustedDeviceIds = devices.slice(-50);
    user.lastActive = Date.now();
    await s.setJSON(`user:${user.username}`, user);
    await s.delete(`pending-login:${challengeId}`).catch(() => {});
    await recordActivity(s, user.userId, 'login-email-verified', { ip: pending.meta.ip, device: pending.meta.device, challenge: true });
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(token) }, body: JSON.stringify({ ok: true, userId: user.userId, username: user.username, email: user.email || null, emailVerified: user.emailVerified === true, nickname: user.nickname || user.username, role: (user.role === 'admin' || String(user.username).toLowerCase() === String(process.env.ADMIN_USERNAME || '').trim().toLowerCase()) ? 'admin' : 'user', expiresAt }) };
  } catch (err) { return json(500, { error: 'Внутрішня помилка сервера' }); }
};
