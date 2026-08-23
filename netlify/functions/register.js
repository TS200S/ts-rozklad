const crypto = require('crypto');
const { store } = require('./lib/store');
const { createSession, sessionMeta, sessionCookie } = require('./lib/session');
const { sendCodeEmail } = require('./lib/mailer');
const { enforceIpBan, getClientIp, rateLimit, protectCodeAttempt, safeCodeEqual, hashCode } = require('./lib/security');
const { recordActivity } = require('./lib/activity');

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function genCode() { return String(crypto.randomInt(100000, 1000000)); }
const CODE_TTL_MS = 15 * 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  try {
    const body = JSON.parse(event.body || '{}');
    const { action } = body;
    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) return { statusCode: 403, body: JSON.stringify({ error: 'Цей IP-адрес заблоковано', ipBlocked: true }) };
    const ip = getClientIp(event);

    // ---- Step 1: validate input, stash a pending registration, email a code ----
    if (action === 'request') {
      const { username, password, confirmPassword, email } = body;
      if (!username || !password || !email || !confirmPassword) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Заповни всі поля' }) };
      }
      const uname = String(username).trim().toLowerCase();
      const mail = String(email).trim().toLowerCase();

      if (uname.length < 3 || !/^[a-z0-9_.]+$/.test(uname)) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Логін: мінімум 3 символи, лише латиниця/цифри/_/.' }) };
      }
      if (String(password) !== String(confirmPassword)) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Паролі не збігаються' }) };
      }
      if (String(password).length < 8 || String(password).length > 128) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Пароль має містити від 8 до 128 символів' }) };
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Невірний формат email' }) };
      }

      const regLimit = await rateLimit(s, `register-ip:${ip}`, 3, 15 * 60 * 1000);
      if (!regLimit.allowed) {
        return { statusCode: 429, body: JSON.stringify({ error: `Забагато спроб реєстрації. Спробуй через ${regLimit.retryAfter} с.` }) };
      }

      const existingUser = await s.get(`user:${uname}`, { type: 'json' }).catch(() => null);
      if (existingUser) {
        return { statusCode: 409, body: JSON.stringify({ error: 'Цей логін вже зайнятий' }) };
      }
      const existingEmail = await s.get(`email:${mail}`, { type: 'json' }).catch(() => null);
      if (existingEmail) {
        return { statusCode: 409, body: JSON.stringify({ error: 'На цей email вже зареєстровано акаунт' }) };
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const code = genCode();

      await s.setJSON(`pending-reg:${mail}`, {
        username: uname, salt, hash, codeHash: hashCode(code).toString('hex'),
        expiresAt: Date.now() + CODE_TTL_MS,
        attempts: 0
      });

      try {
        const recent = await s.get(`email-cooldown:${mail}`, { type: 'json' }).catch(() => null);
        const ipRecent = await s.get(`email-cooldown-ip:${ip}`, { type: 'json' }).catch(() => null);
        if ((recent && Date.now() - recent.sentAt < 60 * 1000) || (ipRecent && Date.now() - ipRecent.sentAt < 60 * 1000)) throw new Error('RATE_LIMIT_COOLDOWN');
        const emailLimit = await rateLimit(s, `email-send:${mail}`, 3, 15 * 60 * 1000);
        const ipEmailLimit = await rateLimit(s, `email-send-ip:${ip}`, 5, 60 * 60 * 1000);
        if (!emailLimit.allowed || !ipEmailLimit.allowed) throw new Error('RATE_LIMIT');
        await sendCodeEmail(mail, code, 'register');
        await s.setJSON(`email-cooldown:${mail}`, { sentAt: Date.now() });
        await s.setJSON(`email-cooldown-ip:${ip}`, { sentAt: Date.now() });
      } catch (mailErr) {
        return { statusCode: 500, body: JSON.stringify({ error: 'Не вдалось надіслати листа з кодом. Спробуй пізніше.' }) };
      }

      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true, email: mail }) };
    }

    // ---- Step 2: check the code, create the account, log the user in ----
    if (action === 'verify') {
      const { email, code, deviceId = '' } = body;
      if (!email || !code) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Потрібен email і код' }) };
      }
      const mail = String(email).trim().toLowerCase();
      const pending = await s.get(`pending-reg:${mail}`, { type: 'json' }).catch(() => null);
      if (!pending) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Запит не знайдено, зареєструйся ще раз' }) };
      }
      if (pending.expiresAt < Date.now()) {
        await s.delete(`pending-reg:${mail}`).catch(() => {});
        return { statusCode: 400, body: JSON.stringify({ error: 'Код прострочено, зареєструйся ще раз' }) };
      }
      if ((pending.attempts || 0) >= MAX_CODE_ATTEMPTS) {
        await s.delete(`pending-reg:${mail}`).catch(() => {});
        return { statusCode: 429, body: JSON.stringify({ error: 'Забагато невірних спроб, зареєструйся ще раз' }) };
      }
      const globalRl = await protectCodeAttempt(s, 'register-verify', pending.username || mail, ip, 8, 15 * 60 * 1000);
      if (!globalRl.allowed) return { statusCode: 429, body: JSON.stringify({ error: `Забагато спроб. Спробуй через ${globalRl.retryAfter} с.` }) };
      if (!safeCodeEqual(String(code).trim(), pending.codeHash)) {
        pending.attempts = (pending.attempts || 0) + 1;
        await s.setJSON(`pending-reg:${mail}`, pending);
        return { statusCode: 400, body: JSON.stringify({ error: 'Невірний код' }) };
      }

      // Re-check uniqueness in case someone else grabbed the login/email
      // while this code was pending.
      const existingUser = await s.get(`user:${pending.username}`, { type: 'json' }).catch(() => null);
      if (existingUser) {
        await s.delete(`pending-reg:${mail}`).catch(() => {});
        return { statusCode: 409, body: JSON.stringify({ error: 'Цей логін щойно зайняли, зареєструйся ще раз' }) };
      }

      const userId = crypto.randomUUID();
      const userRecord = {
        userId, username: pending.username, email: mail, emailVerified: true,
        salt: pending.salt, hash: pending.hash,
        createdAt: Date.now(), lastActive: Date.now(), security: { newDeviceEmail: true, requireNewDeviceEmail: false, requireEveryLoginEmail: false }, trustedDeviceIds: []
      };
      await s.setJSON(`user:${pending.username}`, userRecord);
      await s.setJSON(`email:${mail}`, { username: pending.username });
      await s.delete(`pending-reg:${mail}`).catch(() => {});

      const meta = sessionMeta(event);
      const registrationDeviceId = String(deviceId || '').slice(0, 128);
      meta.deviceId = registrationDeviceId;
      const { token, expiresAt } = await createSession(s, userId, pending.username, meta);
      if (registrationDeviceId) { userRecord.trustedDeviceIds = [registrationDeviceId]; await s.setJSON(`user:${pending.username}`, userRecord); }
      await recordActivity(s, userId, 'account-created', { ip, device: meta.device });

      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(token) }, body: JSON.stringify({ ok: true, userId, username: pending.username, expiresAt })
      };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'Невідома дія' }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
