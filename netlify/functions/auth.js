const crypto = require('crypto');
const { store } = require('./lib/store');
const { createSession, sessionMeta, sessionCookie } = require('./lib/session');
const { enforceIpBan, getClientIp, rateLimit, hashCode } = require('./lib/security');
const { sendLoginCodeEmail, sendNewDeviceAlertEmail } = require('./lib/mailer');
const { recordActivity } = require('./lib/activity');

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
    const { username, password, deviceId = '' } = body;

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
      await recordActivity(s, user.userId, 'login-failed', { ip, device: require('./lib/security').parseDevice(require('./lib/security').getUserAgent(event)), reason: 'invalid-password' });
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
    const meta = sessionMeta(event);
    meta.deviceId = String(deviceId || '').slice(0, 128);
    const trusted = Array.isArray(user.trustedDeviceIds) ? user.trustedDeviceIds : [];
    const isNewDevice = !!meta.deviceId && !trusted.includes(meta.deviceId);
    const requireEmail = user.security?.requireEveryLoginEmail === true || (isNewDevice && user.security?.requireNewDeviceEmail === true);

    if (requireEmail) {
      if (!user.email || user.emailVerified !== true) return { statusCode: 403, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Для додаткового захисту підтверди email у налаштуваннях акаунта' }) };
      const challengeId = crypto.randomBytes(24).toString('hex');
      const code = String(crypto.randomInt(100000, 1000000));
      await s.setJSON(`pending-login:${challengeId}`, { username: user.username, userId: user.userId, codeHash: hashCode(code).toString('hex'), deviceId: meta.deviceId, meta, createdAt: Date.now(), expiresAt: Date.now() + 15 * 60 * 1000, attempts: 0 });
      try {
        const rl = await rateLimit(s, `login-code-send:${user.email}`, 3, 15 * 60 * 1000);
        if (!rl.allowed) return { statusCode: 429, body: JSON.stringify({ error: 'Забагато кодів підтвердження. Спробуй пізніше.' }) };
        await sendLoginCodeEmail(user.email, code);
      } catch {
        await s.delete(`pending-login:${challengeId}`).catch(() => {});
        return { statusCode: 500, body: JSON.stringify({ error: 'Не вдалося надіслати код на email. Спробуй пізніше.' }) };
      }
      await recordActivity(s, user.userId, 'login-challenge', { ip, device: meta.device, newDevice: isNewDevice });
      return { statusCode: 202, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ requiresEmailVerification: true, challengeId, email: user.email }) };
    }

    if (meta.deviceId && !trusted.includes(meta.deviceId)) {
      trusted.push(meta.deviceId);
      user.trustedDeviceIds = trusted.slice(-50);
    }
    await s.setJSON(userKey, user);
    const { token, expiresAt } = await createSession(s, user.userId, user.username, meta);
    if (isNewDevice && user.security?.newDeviceEmail !== false && user.email && user.emailVerified === true) {
      sendNewDeviceAlertEmail(user.email, { ip: meta.ip, device: `${meta.device.type} · ${meta.device.os} · ${meta.device.browser}`, at: Date.now() }).catch(() => {});
      await recordActivity(s, user.userId, 'new-device-email', { ip: meta.ip, device: meta.device });
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(token) },
      body: JSON.stringify({ ok: true, userId: user.userId, username: user.username, email: user.email || null, emailVerified: user.emailVerified === true, role: (user.role === 'admin' || String(user.username).toLowerCase() === String(process.env.ADMIN_USERNAME || '').trim().toLowerCase()) ? 'admin' : 'user', expiresAt })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
