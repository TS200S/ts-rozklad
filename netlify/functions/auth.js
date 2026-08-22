const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

function store() {
  return getStore({
    name: 'ts-app',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const { action, username, password } = body;

    if (!username || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Потрібні логін і пароль' }) };
    }
    const uname = String(username).trim().toLowerCase();
    if (uname.length < 3 || !/^[a-z0-9_.]+$/.test(uname)) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Логін: мінімум 3 символи, лише латиниця/цифри/_/.' }) };
    }
    if (String(password).length < 4) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Пароль мінімум 4 символи' }) };
    }

    const s = store();
    const userKey = `user:${uname}`;

    if (action === 'register') {
      const existing = await s.get(userKey, { type: 'json' });
      if (existing) {
        return { statusCode: 409, body: JSON.stringify({ error: 'Цей логін вже зайнятий' }) };
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const userId = crypto.randomUUID();
      await s.setJSON(userKey, { userId, username: uname, salt, hash, createdAt: Date.now() });
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: true, userId, username: uname })
      };
    }

    if (action === 'login') {
      const user = await s.get(userKey, { type: 'json' });
      if (!user) {
        return { statusCode: 401, body: JSON.stringify({ error: 'Користувача не знайдено' }) };
      }
      const hash = hashPassword(password, user.salt);
      if (hash !== user.hash) {
        return { statusCode: 401, body: JSON.stringify({ error: 'Невірний пароль' }) };
      }
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: true, userId: user.userId, username: user.username })
      };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'Невідома дія' }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
