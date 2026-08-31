const crypto = require('crypto');
const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { sendCodeEmail } = require('./lib/mailer');
const { enforceIpBan, getClientIp, rateLimit, protectCodeAttempt, safeCodeEqual, hashCode, isSameOriginRequest } = require('./lib/security');
const { recordActivity } = require('./lib/activity');

const CODE_TTL_MS = 15 * 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;

function genCode() { return String(crypto.randomInt(100000, 1000000)); }

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  };
}

async function getSessionUser(event, s) {
  const token = extractToken(event);
  const sess = await validateSession(s, token, event);
  if (!sess) return null;
  return await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return json(403, { error: 'Недозволене походження запиту' });

  try {
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return json(403, { error: 'Цей IP-адрес заблоковано', ipBlocked: true });
    const user = await getSessionUser(event, s);
    if (!user) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
    if (user.banned) return json(403, { error: 'Цей акаунт заблоковано' });

    const body = JSON.parse(event.body || '{}');
    const action = body.action;

    if (action === 'status') {
      return json(200, {
        ok: true,
        email: user.email || null,
        emailVerified: user.emailVerified === true
      });
    }

    if (action === 'request') {
      const mail = String(body.email || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
        return json(400, { error: 'Невірний формат email' });
      }

      // Do not allow an email to belong to two accounts.
      const existing = await s.get(`email:${mail}`, { type: 'json' }).catch(() => null);
      if (existing && String(existing.username).toLowerCase() !== user.username.toLowerCase()) {
        return json(409, { error: 'Цей email вже прив’язаний до іншого акаунта' });
      }

      const code = genCode();
      await recordActivity(s, user.userId, 'email-change-request', { ip: getClientIp(event), email: mail });
      await s.setJSON(`pending-email:${user.username}`, {
        userId: user.userId,
        username: user.username,
        email: mail,
        codeHash: hashCode(code).toString('hex'),
        expiresAt: Date.now() + CODE_TTL_MS,
        attempts: 0
      });

      try {
        const ip = getClientIp(event);
        const recent = await s.get(`email-cooldown:${mail}`, { type: 'json' }).catch(() => null);
        const ipRecent = await s.get(`email-cooldown-ip:${ip}`, { type: 'json' }).catch(() => null);
        if ((recent && Date.now() - recent.sentAt < 60 * 1000) || (ipRecent && Date.now() - ipRecent.sentAt < 60 * 1000)) throw new Error('RATE_LIMIT_COOLDOWN');
        const emailLimit = await rateLimit(s, `email-send:${mail}`, 3, 15 * 60 * 1000);
        const ipEmailLimit = await rateLimit(s, `email-send-ip:${ip}`, 5, 60 * 60 * 1000);
        if (!emailLimit.allowed || !ipEmailLimit.allowed) throw new Error('RATE_LIMIT');
        await sendCodeEmail(mail, code, 'email');
        await s.setJSON(`email-cooldown:${mail}`, { sentAt: Date.now() });
        await s.setJSON(`email-cooldown-ip:${ip}`, { sentAt: Date.now() });
      } catch {
        await s.delete(`pending-email:${user.username}`).catch(() => {});
        return json(500, { error: 'Не вдалось надіслати листа з кодом. Перевір налаштування Gmail і спробуй ще раз.' });
      }

      return json(200, { ok: true, email: mail });
    }

    if (action === 'verify') {
      const code = String(body.code || '').trim();
      if (!code) return json(400, { error: 'Введи код' });

      const pending = await s.get(`pending-email:${user.username}`, { type: 'json' }).catch(() => null);
      if (!pending) return json(400, { error: 'Запит не знайдено. Запроси код ще раз.' });

      if (pending.expiresAt < Date.now()) {
        await s.delete(`pending-email:${user.username}`).catch(() => {});
        return json(400, { error: 'Код прострочено. Запроси новий.' });
      }

      if ((pending.attempts || 0) >= MAX_CODE_ATTEMPTS) {
        await s.delete(`pending-email:${user.username}`).catch(() => {});
        return json(429, { error: 'Забагато спроб. Запроси код ще раз.' });
      }

      const globalRl = await protectCodeAttempt(s, 'email-change-verify', user.userId, getClientIp(event), 8, 15 * 60 * 1000);
      if (!globalRl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${globalRl.retryAfter} с.` });
      if (!safeCodeEqual(code, pending.codeHash)) {
        pending.attempts = (pending.attempts || 0) + 1;
        await s.setJSON(`pending-email:${user.username}`, pending);
        return json(400, { error: 'Невірний код' });
      }

      const existing = await s.get(`email:${pending.email}`, { type: 'json' }).catch(() => null);
      if (existing && String(existing.username).toLowerCase() !== user.username.toLowerCase()) {
        await s.delete(`pending-email:${user.username}`).catch(() => {});
        return json(409, { error: 'Цей email вже прив’язаний до іншого акаунта' });
      }

      // Remove the old email index if this account already had one.
      if (user.email && user.email !== pending.email) {
        await s.delete(`email:${user.email}`).catch(() => {});
      }

      user.email = pending.email;
      user.emailVerified = true;
      user.lastActive = Date.now();

      await s.setJSON(`user:${user.username}`, user);
      await recordActivity(s, user.userId, 'email-changed', { ip: getClientIp(event), email: user.email });
      await s.setJSON(`email:${pending.email}`, { username: user.username });
      await s.delete(`pending-email:${user.username}`).catch(() => {});

      return json(200, { ok: true, email: user.email, emailVerified: true });
    }

    return json(400, { error: 'Невідома дія' });
  } catch (err) {
    return json(500, { error: 'Внутрішня помилка сервера' });
  }
};
