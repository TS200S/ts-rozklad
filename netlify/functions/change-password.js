const crypto = require('crypto');
const { store } = require('./lib/store');
const { validateSession, extractToken, deleteAllSessionsForUser } = require('./lib/session');
const { enforceIpBan, rateLimit, getClientIp } = require('./lib/security');
const { recordActivity } = require('./lib/activity');

function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function json(statusCode, body) { return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }; }

exports.handler = async event => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method Not Allowed' });
  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return json(403, { error: 'Цей IP-адрес заблоковано' });
    const token = extractToken(event);
    const sess = await validateSession(s, token, event);
    if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
    const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
    if (!user) return json(401, { error: 'Акаунт не знайдено' });
    const ip = getClientIp(event);
    const rl = await rateLimit(s, `password-change:${user.userId}:${ip}`, 5, 60 * 60 * 1000);
    if (!rl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${rl.retryAfter} с.` });
    const { currentPassword, newPassword, confirmPassword } = JSON.parse(event.body || '{}');
    if (!currentPassword || !newPassword || !confirmPassword) return json(400, { error: 'Заповни всі поля' });
    if (newPassword !== confirmPassword) return json(400, { error: 'Нові паролі не збігаються' });
    if (String(newPassword).length < 8 || String(newPassword).length > 128) return json(400, { error: 'Пароль має містити від 8 до 128 символів' });
    const a = Buffer.from(hashPassword(String(currentPassword), user.salt), 'hex');
    const b = Buffer.from(String(user.hash || ''), 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return json(400, { error: 'Поточний пароль невірний' });
    const salt = crypto.randomBytes(16).toString('hex');
    user.salt = salt;
    user.hash = hashPassword(String(newPassword), salt);
    user.passwordChangedAt = Date.now();
    user.trustedDeviceIds = [];
    await s.setJSON(`user:${user.username}`, user);
    await recordActivity(s, user.userId, 'password-changed', { ip, device: sess.device });
    await deleteAllSessionsForUser(s, user.userId);
    return json(200, { ok: true, reLoginRequired: true });
  } catch (err) { return json(500, { error: String(err) }); }
};
