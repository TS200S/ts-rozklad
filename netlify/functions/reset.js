const crypto = require('crypto');
const { store } = require('./lib/store');
const { deleteAllSessionsForUser } = require('./lib/session');
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

    // Always returns the same generic response whether or not the email is
    // registered, so this endpoint can't be used to check which emails have
    // an account here.
    const generic = {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, message: 'Якщо такий email зареєстрований, код надіслано на нього' })
    };

    if (action === 'request') {
      const { email } = body;
      if (!email) return generic;
      const mail = String(email).trim().toLowerCase();

      const emailRecord = await s.get(`email:${mail}`, { type: 'json' }).catch(() => null);
      if (!emailRecord) return generic;
      const user = await s.get(`user:${emailRecord.username}`, { type: 'json' }).catch(() => null);
      if (!user || user.banned) return generic;

      const code = genCode();
      await s.setJSON(`pending-reset:${mail}`, {
        userId: user.userId, username: user.username, code,
        expiresAt: Date.now() + CODE_TTL_MS, attempts: 0
      });

      try {
        await sendCodeEmail(mail, code, 'reset');
      } catch {
        // Swallow mail errors here too, for the same anti-enumeration reason.
      }
      return generic;
    }

    if (action === 'confirm') {
      const { email, code, newPassword } = body;
      if (!email || !code || !newPassword) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Заповни всі поля' }) };
      }
      if (String(newPassword).length < 4) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Пароль мінімум 4 символи' }) };
      }
      const mail = String(email).trim().toLowerCase();
      const pending = await s.get(`pending-reset:${mail}`, { type: 'json' }).catch(() => null);
      if (!pending) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Запит не знайдено або прострочено, запроси код ще раз' }) };
      }
      if (pending.expiresAt < Date.now()) {
        await s.delete(`pending-reset:${mail}`).catch(() => {});
        return { statusCode: 400, body: JSON.stringify({ error: 'Код прострочено, запроси новий' }) };
      }
      if ((pending.attempts || 0) >= MAX_CODE_ATTEMPTS) {
        await s.delete(`pending-reset:${mail}`).catch(() => {});
        return { statusCode: 429, body: JSON.stringify({ error: 'Забагато спроб, запроси код ще раз' }) };
      }
      if (String(code).trim() !== pending.code) {
        pending.attempts = (pending.attempts || 0) + 1;
        await s.setJSON(`pending-reset:${mail}`, pending);
        return { statusCode: 400, body: JSON.stringify({ error: 'Невірний код' }) };
      }

      const user = await s.get(`user:${pending.username}`, { type: 'json' }).catch(() => null);
      if (!user) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Користувача не знайдено' }) };
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(newPassword, salt);
      user.salt = salt;
      user.hash = hash;
      await s.setJSON(`user:${pending.username}`, user);
      await s.delete(`pending-reset:${mail}`).catch(() => {});

      // A password reset means any device/session using the old password
      // should be signed out.
      await deleteAllSessionsForUser(s, user.userId);

      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true }) };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'Невідома дія' }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
