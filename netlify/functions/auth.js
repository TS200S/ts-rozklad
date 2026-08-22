const crypto = require('crypto');
const { store } = require('./lib/store');
const { createSession, sessionMeta } = require('./lib/session');
const { enforceIpBan, getClientIp, rateLimit } = require('./lib/security');

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

const MAX_ATTEMPTS = 6;
const LOCK_MINUTES = 15;

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const { username, password } = body;

    if (!username || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Потрібні логін і пароль' }) };
    }
    const uname = String(username).trim().toLowerCase();

    const s = store();
    const ipBan = await enforceIpBan(s, event);
    if (ipBan) {
      return { statusCode: 403, body: JSON.stringify({ error:'Цей IP-адрес заблоковано', ipBlocked:true,
        ipBanReason:ipBan.reason||'', ipBanExpiresAt:Number(ipBan.expiresAt||0), ipBanPermanent:!Number(ipBan.expiresAt||0) }) };
    }
    const ip = getClientIp(event);
    const loginLimit = await rateLimit(s, `login-ip:${ip}`, 20, 15 * 60 * 1000);
    if (!loginLimit.allowed) {
      return { statusCode: 429, body: JSON.stringify({ error: `Забагато спроб. Спробуй через ${loginLimit.retryAfter} с.` }) };
    }

    const userKey = `user:${uname}`;
    const attemptsKey = `login-attempts:${uname}`;
    const genericError = () => JSON.stringify({ error: 'Невірний логін або пароль' });

    const attempts = (await s.get(attemptsKey, { type: 'json' }).catch(() => null)) || { count: 0, lockedUntil: 0 };
    if (attempts.lockedUntil > Date.now()) {
      const waitMin = Math.ceil((attempts.lockedUntil - Date.now()) / 60000);
      return { statusCode: 429, body: JSON.stringify({ error: `Забагато спроб входу. Спробуй через ${waitMin} хв.` }) };
    }

    const user = await s.get(userKey, { type: 'json' }).catch(() => null);

    // Same error whether the account doesn't exist or the password is wrong,
    // so a logged error can't be used to enumerate which logins are taken.
    if (!user) {
      return { statusCode: 401, body: genericError() };
    }
    if (user.banned) {
      const expiresAt = Number(user.banExpiresAt || 0);
      if (expiresAt && expiresAt <= Date.now()) {
        user.banned=false; user.banReason=null; user.banExpiresAt=0;
        await s.setJSON(`user:${user.username}`, user);
      } else {
        return { statusCode:403, headers:{'Content-Type':'application/json'}, body:JSON.stringify({
          error:'Акаунт заблоковано', banned:true, banReason:user.banReason||'',
          banExpiresAt:expiresAt, banPermanent:!expiresAt
        }) };
      }
    }

    const hash = hashPassword(password, user.salt);
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(String(user.hash || ''), 'hex');
    const validHash = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!validHash) {
      const newCount = (attempts.count || 0) + 1;
      const newAttempts = { count: newCount, lockedUntil: 0 };
      if (newCount >= MAX_ATTEMPTS) {
        newAttempts.lockedUntil = Date.now() + LOCK_MINUTES * 60 * 1000;
        newAttempts.count = 0;
      }
      await s.setJSON(attemptsKey, newAttempts);
      return { statusCode: 401, body: genericError() };
    }

    await s.delete(attemptsKey).catch(() => {});

    user.lastActive = Date.now();
    await s.setJSON(userKey, user);

    const { token, expiresAt } = await createSession(s, user.userId, user.username, sessionMeta(event));

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, userId: user.userId, username: user.username, email: user.email || null, emailVerified: user.emailVerified === true, role: (user.role === 'admin' || String(user.username).toLowerCase() === String(process.env.ADMIN_USERNAME || '').trim().toLowerCase()) ? 'admin' : 'user', token, expiresAt })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
