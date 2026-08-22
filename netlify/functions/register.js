const crypto = require('crypto');
const { store } = require('./lib/store');
const { createSession } = require('./lib/session');
const { sendCodeEmail } = require('./lib/mailer');

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function genCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
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

    // ---- Step 1: validate input, stash a pending registration, email a code ----
    if (action === 'request') {
      const { username, password, email } = body;
      if (!username || !password || !email) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Заповни всі поля' }) };
      }
      const uname = String(username).trim().toLowerCase();
      const mail = String(email).trim().toLowerCase();

      if (uname.length < 3 || !/^[a-z0-9_.]+$/.test(uname)) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Логін: мінімум 3 символи, лише латиниця/цифри/_/.' }) };
      }
      if (String(password).length < 4) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Пароль мінімум 4 символи' }) };
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Невірний формат email' }) };
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
        username: uname, salt, hash, code,
        expiresAt: Date.now() + CODE_TTL_MS,
        attempts: 0
      });

      try {
        await sendCodeEmail(mail, code, 'register');
      } catch (mailErr) {
        return { statusCode: 500, body: JSON.stringify({ error: 'Не вдалось надіслати листа з кодом. Спробуй пізніше.' }) };
      }

      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true, email: mail }) };
    }

    // ---- Step 2: check the code, create the account, log the user in ----
    if (action === 'verify') {
      const { email, code } = body;
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
      if (String(code).trim() !== pending.code) {
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
        userId, username: pending.username, email: mail,
        salt: pending.salt, hash: pending.hash,
        createdAt: Date.now(), lastActive: Date.now()
      };
      await s.setJSON(`user:${pending.username}`, userRecord);
      await s.setJSON(`email:${mail}`, { username: pending.username });
      await s.delete(`pending-reg:${mail}`).catch(() => {});

      const { token, expiresAt } = await createSession(s, userId, pending.username);

      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: true, userId, username: pending.username, token, expiresAt })
      };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'Невідома дія' }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
