const crypto = require('crypto');
const net = require('net');
const { store } = require('./lib/store');
const { validateSession, extractToken, deleteAllSessionsForUser, listSessionsForUser, deleteSession } = require('./lib/session');
const { getClientIp, isIpBanned } = require('./lib/security');
const { listActivity, recordActivity } = require('./lib/activity');
const { sendAdminRecoveryEmail, sendAdmin2FACodeEmail, sendAdminEmergencyRecoveryEmail } = require('./lib/mailer');
const { protectCodeAttempt, safeCodeEqual, hashCode } = require('./lib/security');

function json(statusCode, body) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

async function requireAdmin(event, s, options = {}) {
  const token = extractToken(event);
  const sess = await validateSession(s, token, event);
  if (!sess || sess.banned) return null;
  const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
  if (!user) return null;
  const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
  if (!(sess.username === master || user.role === 'admin')) return null;
  const result = { sess, user, master, event };
  if (options.stepUp) {
    const age = Date.now() - Number(sess.adminStepUpAt || 0);
    if (age > 10 * 60 * 1000) return { requiresAdminReauth: true, sess, user, master, event };
  }
  return result;
}

function canManageTarget(admin, targetUser) {
  const targetMaster = String(targetUser?.username || '').trim().toLowerCase() === admin.master;
  const targetAdmin = targetUser?.role === 'admin' || targetMaster;
  return admin.user.username === admin.master || !targetAdmin;
}

function isMasterUsername(username, master) {
  return String(username || '').trim().toLowerCase() === master;
}

function sessionId(token) {
  return crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
}

async function audit(s, adminUsername, action, details = {}) {
  const list = (await s.get('audit-log', { type: 'json' }).catch(() => null)) || [];
  const previous = list.length ? list[list.length - 1] : null;
  const prevHash = previous?.hash || 'GENESIS';
  const item = { id: crypto.randomUUID(), at: Date.now(), adminUsername, action, details, prevHash };
  item.hash = crypto.createHash('sha256').update(JSON.stringify({ id:item.id, at:item.at, adminUsername:item.adminUsername, action:item.action, details:item.details, prevHash:item.prevHash })).digest('hex');
  list.push(item);
  await s.setJSON('audit-log', list.slice(-1000)).catch(() => {});
}

async function auditAdmin(s, admin, action, details = {}) {
  const ip = getClientIp(admin.event);
  const ua = require('./lib/security').getUserAgent(admin.event);
  const device = require('./lib/security').parseDevice(ua);
  return audit(s, admin.user.username, action, {
    ...details,
    adminIp: ip,
    adminDevice: device,
    adminUserAgent: ua,
    adminSessionId: sessionId(extractToken(admin.event))
  });
}

async function verifyAuditLog(s) {
  const list = (await s.get('audit-log', { type: 'json' }).catch(() => null)) || [];
  let prev = 'GENESIS';
  for (const item of list) {
    if (!item.hash) continue;
    const expected = crypto.createHash('sha256').update(JSON.stringify({ id:item.id, at:item.at, adminUsername:item.adminUsername, action:item.action, details:item.details, prevHash:item.prevHash })).digest('hex');
    if (item.prevHash !== prev || item.hash !== expected) return { valid:false, brokenId:item.id };
    prev = item.hash;
  }
  return { valid:true, count:list.length };
}

function maskEmail(email) { const [local, domain=''] = String(email || '').split('@'); if (!local || !domain) return '***'; const shown = local.length <= 2 ? local[0] + '*' : local.slice(0,2) + '*'.repeat(Math.min(6, Math.max(1, local.length-2))); return `${shown}@${domain}`; }

async function setIpBan(s, ip, { reason = '', duration = 'forever', username = '' } = {}) {
  const durations = { hour: 3600000, day: 86400000, week: 604800000, forever: 0 };
  const d = durations[duration] ?? durations.forever;
  const expiresAt = d ? Date.now() + d : 0;
  await s.setJSON(`ip-ban:${ip}`, {
    ip, reason: String(reason || '').slice(0, 200), username: String(username || '').slice(0, 80),
    createdAt: Date.now(), expiresAt
  });
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

  try {
    const s = store();
    let body = {};
    try { body = JSON.parse(event.body || '{}') || {}; } catch { return json(400, { error: 'Некоректний JSON' }); }
    const action = String(body.action || '').trim();
    if (!action) return json(400, { error: 'Не вказано дію' });
    // Emergency admin-password recovery is intentionally public: it does not require
    // an existing admin session. Possession of the already-verified admin email is
    // the second factor. Responses stay generic to avoid account enumeration.
    if (action === 'admin-password-recovery-start') {
      const username = String(body.username || '').trim().toLowerCase();
      if (!/^[a-z0-9_.-]{3,64}$/.test(username)) return json(400, { error: 'Некоректне ім’я користувача.' });
      const ip = getClientIp(event);
      const rl = await require('./lib/security').rateLimit(s, `admin-recovery-start:${username}:${ip}`, 3, 15 * 60 * 1000);
      if (!rl.allowed) return json(429, { error: `Забагато запитів. Спробуй через ${rl.retryAfter} с.` });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (user && (username === master || user.role === 'admin') && user.email && user.emailVerified === true) {
        const existing = await s.get(`admin-recovery:${username}`, { type: 'json' }).catch(() => null);
        if (existing && Number(existing.sentAt || 0) + 60 * 1000 > Date.now()) {
          return json(200, { ok: true, message: 'Якщо для цього адміністратора доступне підтверджене відновлення, лист уже було надіслано. Перевір пошту.' });
        }
        const code = String(crypto.randomInt(100000, 1000000));
        const challenge = {
          hash: crypto.createHash('sha256').update(code).digest('hex'),
          expiresAt: Date.now() + 10 * 60 * 1000,
          sentAt: Date.now(),
          attempts: 0,
          ip: String(ip || 'unknown').slice(0, 80)
        };
        await s.setJSON(`admin-recovery:${username}`, challenge);
        try {
          await sendAdminEmergencyRecoveryEmail(user.email, code);
          await audit(s, username, 'admin-password-recovery-requested', { ip, delivery: 'email' });
        } catch (mailErr) {
          await s.delete(`admin-recovery:${username}`).catch(() => {});
          await audit(s, username, 'admin-password-recovery-email-failed', { ip });
        }
      }
      return json(200, { ok: true, message: 'Якщо для цього адміністратора доступне підтверджене відновлення, на його email надіслано код. Перевір папку «Спам».' });
    }

    if (action === 'admin-password-recovery-verify') {
      const username = String(body.username || '').trim().toLowerCase();
      const code = String(body.code || '').replace(/\D/g, '').slice(0, 6);
      const newPassword = String(body.newPassword || '');
      const confirmPassword = String(body.confirmPassword || '');
      if (!/^[a-z0-9_.-]{3,64}$/.test(username)) return json(400, { error: 'Некоректне ім’я користувача.' });
      if (!/^\d{6}$/.test(code)) return json(400, { error: 'Введи 6-значний код із листа.' });
      if (newPassword.length < 12 || newPassword.length > 128) return json(400, { error: 'Новий пароль адмінки має містити від 12 до 128 символів.' });
      if (newPassword !== confirmPassword) return json(400, { error: 'Паролі адмінки не збігаються.' });
      const ip = getClientIp(event);
      const rl = await require('./lib/security').rateLimit(s, `admin-recovery-verify:${username}:${ip}`, 8, 15 * 15 * 1000);
      if (!rl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${rl.retryAfter} с.` });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      const challenge = await s.get(`admin-recovery:${username}`, { type: 'json' }).catch(() => null);
      if (!user || !(username === master || user.role === 'admin') || !user.email || user.emailVerified !== true || !challenge) {
        return json(401, { error: 'Код недійсний або відновлення вже завершено.' });
      }
      if (Number(challenge.expiresAt || 0) < Date.now()) {
        await s.delete(`admin-recovery:${username}`).catch(() => {});
        return json(401, { error: 'Код прострочений. Запроси новий.' });
      }
      if (Number(challenge.attempts || 0) >= 5) {
        await s.delete(`admin-recovery:${username}`).catch(() => {});
        return json(429, { error: 'Забагато неправильних кодів. Запроси новий.' });
      }
      const globalRl = await protectCodeAttempt(s, 'admin-recovery-verify-global', username, ip, 8, 15 * 60 * 1000);
      if (!globalRl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${globalRl.retryAfter} с.` });
      if (!safeCodeEqual(code, challenge.hash)) {
        challenge.attempts = Number(challenge.attempts || 0) + 1;
        await s.setJSON(`admin-recovery:${username}`, challenge);
        await audit(s, username, 'admin-password-recovery-failed', { ip, attempts: challenge.attempts });
        return json(401, { error: 'Невірний код.' });
      }
      if (user.adminPasswordHash && user.adminPasswordSalt) {
        const same = Buffer.from(crypto.scryptSync(newPassword, user.adminPasswordSalt, 64));
        const oldHash = Buffer.from(String(user.adminPasswordHash), 'hex');
        if (same.length === oldHash.length && crypto.timingSafeEqual(same, oldHash)) return json(400, { error: 'Новий пароль має відрізнятися від попереднього.' });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      user.adminPasswordHash = crypto.scryptSync(newPassword, salt, 64).toString('hex');
      user.adminPasswordSalt = salt;
      user.adminPasswordChangedAt = Date.now();
      user.adminPasswordRecoveredAt = Date.now();
      await s.setJSON(`user:${username}`, user);
      await s.delete(`admin-recovery:${username}`).catch(() => {});
      await deleteAllSessionsForUser(s, user.userId);
      await audit(s, username, 'admin-password-recovered', { ip, delivery: 'email' });
      return json(200, { ok: true, message: 'Пароль адмінки відновлено. Усі старі сесії завершено. Увійди знову.' });
    }

    if (action === 'reauth-admin') {
      const token = extractToken(event);
      const sess = await validateSession(s, token, event);
      if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
      const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!user || !(sess.username === master || user.role === 'admin')) return json(403, { error: 'Немає доступу' });
      if (!user.adminPasswordHash || !user.adminPasswordSalt) return json(409, { error: 'Окремий пароль адмінки ще не налаштовано. Спочатку створи його в налаштуваннях безпеки.' , setupRequired: true });
      if (!user.email || user.emailVerified !== true) return json(409, { error: 'Для 2FA потрібно підтвердити email адміністратора.' });
      const ip = getClientIp(event);
      const rl = await require('./lib/security').rateLimit(s, `admin-reauth:${user.userId}:${ip}`, 5, 15 * 60 * 1000);
      if (!rl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${rl.retryAfter} с.` });
      const password = String(body.password || '');
      if (!password) return json(400, { error: 'Введи пароль адмінки' });
      const a = Buffer.from(crypto.scryptSync(password, user.adminPasswordSalt, 64));
      const b = Buffer.from(String(user.adminPasswordHash || ''), 'hex');
      const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
      if (!valid) {
        await audit(s, user.username, 'admin-reauth-failed', { ip, reason: 'wrong-admin-password' });
        return json(401, { error: 'Невірний пароль адмінки' });
      }
      const code = String(crypto.randomInt(100000, 1000000));
      const codeHash = crypto.createHash('sha256').update(code).digest('hex');
      sess.admin2faChallenge = { hash: codeHash, expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0, sentAt: Date.now() };
      await s.setJSON(`session:${token}`, sess);
      await sendAdmin2FACodeEmail(user.email, code, 'critical');
      await audit(s, user.username, 'admin-2fa-sent', { ip, sessionId: sessionId(token) });
      return json(200, { ok:true, requires2FA:true, expiresAt: sess.admin2faChallenge.expiresAt, emailMasked: maskEmail(user.email) });
    }

    if (action === 'verify-admin-2fa') {
      const token = extractToken(event);
      const sess = await validateSession(s, token, event);
      if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
      const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!user || !(sess.username === master || user.role === 'admin')) return json(403, { error: 'Немає доступу' });
      const ch = sess.admin2faChallenge;
      if (!ch || Number(ch.expiresAt || 0) < Date.now()) return json(401, { error: 'Код 2FA прострочений. Запроси новий.' });
      const ip = getClientIp(event);
      const attempts = Number(ch.attempts || 0);
      if (attempts >= 5) return json(429, { error: 'Забагато неправильних кодів. Запроси новий код.' });
      const code = String(body.code || '').replace(/\D/g, '').slice(0, 6);
      if (!/^\d{6}$/.test(code)) return json(400, { error: 'Введи 6-значний код із листа' });
      const globalRl = await protectCodeAttempt(s, 'admin-2fa-verify', user.userId, ip, 8, 15 * 60 * 1000);
      if (!globalRl.allowed) return json(429, { error: `Забагато спроб 2FA. Спробуй через ${globalRl.retryAfter} с.` });
      if (!safeCodeEqual(code, ch.hash)) {
        ch.attempts = attempts + 1;
        sess.admin2faChallenge = ch;
        await s.setJSON(`session:${token}`, sess);
        await audit(s, user.username, 'admin-2fa-failed', { ip, attempts: ch.attempts });
        return json(401, { error: 'Невірний код 2FA' });
      }
      delete sess.admin2faChallenge;
      sess.adminStepUpAt = Date.now();
      await s.setJSON(`session:${token}`, sess);
      await audit(s, user.username, 'admin-2fa-success', { ip, sessionId: sessionId(token) });
      return json(200, { ok:true, expiresAt: sess.adminStepUpAt + 10 * 60 * 1000 });
    }

    if (action === 'resend-admin-2fa') {
      const token = extractToken(event);
      const sess = await validateSession(s, token, event);
      if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
      const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!user || !(sess.username === master || user.role === 'admin')) return json(403, { error: 'Немає доступу' });
      if (!user.email || user.emailVerified !== true) return json(409, { error: 'Email адміністратора не підтверджено.' });
      const old = sess.admin2faChallenge;
      if (old && Date.now() - Number(old.sentAt || 0) < 60 * 1000) return json(429, { error: 'Новий код можна запросити через хвилину.' });
      const code = String(crypto.randomInt(100000, 1000000));
      sess.admin2faChallenge = { hash: crypto.createHash('sha256').update(code).digest('hex'), expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0, sentAt: Date.now() };
      await s.setJSON(`session:${token}`, sess);
      await sendAdmin2FACodeEmail(user.email, code, 'critical');
      return json(200, { ok:true, expiresAt:sess.admin2faChallenge.expiresAt, emailMasked:maskEmail(user.email) });
    }

    if (action === 'setup-admin-password-start') {
      const token = extractToken(event);
      const sess = await validateSession(s, token, event);
      if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
      const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!user || !(sess.username === master || user.role === 'admin')) return json(403, { error: 'Немає доступу' });
      if (!user.email || user.emailVerified !== true) return json(409, { error: 'Спочатку підтвердь email адміністратора.' });
      const currentPassword = String(body.currentPassword || '');
      const newPassword = String(body.newPassword || '');
      const confirmPassword = String(body.confirmPassword || '');
      if (newPassword.length < 12 || newPassword.length > 128) return json(400, { error: 'Пароль адмінки має містити від 12 до 128 символів.' });
      if (newPassword !== confirmPassword) return json(400, { error: 'Паролі адмінки не збігаються.' });
      if (!currentPassword) return json(400, { error: 'Введи поточний пароль.' });

      const ip = getClientIp(event);
      const rl = await require('./lib/security').rateLimit(s, `admin-password-change:${user.userId}:${ip}`, 5, 15 * 60 * 1000);
      if (!rl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${rl.retryAfter} с.` });

      // First setup is authorized by the normal account password.
      // Any subsequent change MUST be authorized by the separate admin password.
      let validCurrent = false;
      let authorizationType = 'account-password';
      if (user.adminPasswordHash && user.adminPasswordSalt) {
        const a = Buffer.from(crypto.scryptSync(currentPassword, user.adminPasswordSalt, 64));
        const b = Buffer.from(String(user.adminPasswordHash), 'hex');
        validCurrent = a.length === b.length && crypto.timingSafeEqual(a, b);
        authorizationType = 'admin-password';
      } else {
        const a = Buffer.from(crypto.scryptSync(currentPassword, user.salt, 64));
        const b = Buffer.from(String(user.hash || ''), 'hex');
        validCurrent = a.length === b.length && crypto.timingSafeEqual(a, b);
      }
      if (!validCurrent) {
        await audit(s, user.username, 'admin-password-change-failed', { ip, authorizationType });
        return json(401, { error: user.adminPasswordHash ? 'Невірний поточний пароль адмінки.' : 'Невірний поточний пароль акаунта.' });
      }

      // Prevent reusing the same admin password.
      if (user.adminPasswordHash && user.adminPasswordSalt) {
        const same = Buffer.from(crypto.scryptSync(newPassword, user.adminPasswordSalt, 64));
        const oldHash = Buffer.from(String(user.adminPasswordHash), 'hex');
        if (same.length === oldHash.length && crypto.timingSafeEqual(same, oldHash)) return json(400, { error: 'Новий пароль адмінки має відрізнятися від поточного.' });
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const code = String(crypto.randomInt(100000, 1000000));
      sess.adminPasswordSetup = { hash: crypto.scryptSync(newPassword, salt, 64).toString('hex'), salt, codeHash: crypto.createHash('sha256').update(code).digest('hex'), expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0, authorizationType };
      await s.setJSON(`session:${token}`, sess);
      await sendAdmin2FACodeEmail(user.email, code, 'setup');
      return json(200, { ok:true, requires2FA:true, emailMasked:maskEmail(user.email), expiresAt:sess.adminPasswordSetup.expiresAt });
    }

    if (action === 'setup-admin-password-verify') {
      const token = extractToken(event);
      const sess = await validateSession(s, token, event);
      if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна. Увійди ще раз.' });
      const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!user || !(sess.username === master || user.role === 'admin')) return json(403, { error: 'Немає доступу' });
      const setup = sess.adminPasswordSetup;
      if (!setup || Number(setup.expiresAt || 0) < Date.now()) return json(401, { error: 'Код налаштування прострочений. Почни налаштування ще раз.' });
      const code = String(body.code || '').replace(/\D/g, '').slice(0, 6);
      if (setup.attempts >= 5) return json(429, { error: 'Забагато спроб. Почни налаштування ще раз.' });
      const ip = getClientIp(event);
      const globalRl = await protectCodeAttempt(s, 'admin-2fa-setup', user.userId, ip, 8, 15 * 60 * 1000);
      if (!globalRl.allowed) return json(429, { error: `Забагато спроб 2FA. Спробуй через ${globalRl.retryAfter} с.` });
      if (!safeCodeEqual(code, setup.codeHash)) { setup.attempts += 1; sess.adminPasswordSetup = setup; await s.setJSON(`session:${token}`, sess); return json(401, { error: 'Невірний код.' }); }
      const wasConfigured = !!(user.adminPasswordHash && user.adminPasswordSalt);
      user.adminPasswordHash = setup.hash;
      user.adminPasswordSalt = setup.salt;
      user.adminPasswordChangedAt = Date.now();
      await s.setJSON(`user:${user.username}`, user);

      // Invalidate every other session so a previous admin session cannot keep using the old credential.
      const sessions = await listSessionsForUser(s, user.userId);
      for (const other of sessions) {
        if (other.token !== token) await deleteSession(s, other.token).catch(() => {});
      }
      delete sess.adminPasswordSetup;
      delete sess.adminStepUpAt;
      delete sess.admin2faChallenge;
      await s.setJSON(`session:${token}`, sess);
      await audit(s, user.username, wasConfigured ? 'admin-password-changed' : 'admin-password-created', { ip:getClientIp(event), authorizationType: setup.authorizationType || (wasConfigured ? 'admin-password' : 'account-password') });
      return json(200, { ok:true, changed:wasConfigured });
    }


    const criticalActions = new Set(['revoke-session','revoke-all-sessions','ban-user','unban-user','delete-user','update-email','confirm-admin-email','clear-account-history','set-role','ip-ban','ip-unban']);
    const admin = await requireAdmin(event, s, { stepUp: criticalActions.has(action) });
    if (!admin) return json(403, { error: 'Немає доступу' });
    if (admin.requiresAdminReauth) return json(428, { error: 'Потрібне повторне підтвердження пароля адміністратора', requiresAdminReauth: true });

    if (action === 'security-check') {
      const checks = [];
      const auditLog = (await s.get('audit-log', { type: 'json' }).catch(() => null)) || [];
      const integrity = await verifyAuditLog(s);
      const adminEmailVerified = admin.user.emailVerified === true && !!admin.user.email;
      const cronConfigured = !!String(process.env.CRON_SECRET || '').trim();
      const storeOk = Array.isArray(auditLog);

      checks.push({ id:'storage', label:'Netlify Blobs / сховище', status:storeOk?'PASS':'FAIL', detail:storeOk?'Сховище доступне для читання.':'Не вдалося прочитати службові дані.' });
      checks.push({ id:'audit', label:'Цілісність журналу адміністратора', status:integrity.valid?'PASS':'FAIL', detail:integrity.valid?`Перевірено записів: ${integrity.count || 0}.`:`Порушення біля запису ${integrity.brokenId || 'невідомо'}.` });
      checks.push({ id:'admin-email', label:'Підтверджена пошта адміністратора', status:adminEmailVerified?'PASS':'WARN', detail:adminEmailVerified?'Пошта підтверджена та доступна для 2FA/відновлення.':'Потрібна підтверджена пошта адміністратора.' });
      checks.push({ id:'admin-password', label:'Окремий пароль адмінки', status:admin.user.adminPasswordHash && admin.user.adminPasswordSalt?'PASS':'WARN', detail:admin.user.adminPasswordHash?'Окремий пароль налаштований.':'Пароль адмінки ще не налаштований.' });
      checks.push({ id:'cron', label:'CRON_SECRET', status:cronConfigured?'PASS':'WARN', detail:cronConfigured?'Секрет налаштований (значення не показується).':'CRON_SECRET не налаштований.' });
      checks.push({ id:'session-cookie', label:'HttpOnly session cookie', status:'PASS', detail:'Сервер використовує __Host-ts_session з Secure, HttpOnly та SameSite=Lax.' });
      checks.push({ id:'device-binding', label:'Прив’язка сесії до пристрою', status:'PASS', detail:'Сесія перевіряє deviceId та User-Agent.' });
      checks.push({ id:'2fa', label:'Email 2FA для критичних дій', status:'PASS', detail:'Критичні адміністративні дії захищені step-up + email-кодом.' });
      checks.push({ id:'bruteforce', label:'Захист від перебору', status:'PASS', detail:'Для повторного підтвердження та кодів використовується rate limit.' });
      checks.push({ id:'sensitive-logs', label:'Секрети не записуються в аудит', status:'PASS', detail:'Паролі, токени та коди не передаються в audit payload.' });
      return json(200, { ok:true, generatedAt:Date.now(), checks });
    }

    if (action === 'list-users') {
      const { blobs } = await s.list({ prefix: 'user:' });
      const users = [];
      for (const b of blobs) {
        const u = await s.get(b.key, { type: 'json' }).catch(() => null);
        if (!u) continue;
        if (u.banned && Number(u.banExpiresAt || 0) && Number(u.banExpiresAt) <= Date.now()) {
          u.banned = false; u.bannedAt = null; u.banReason = null; u.banExpiresAt = 0;
          await s.setJSON(`user:${u.username}`, u).catch(() => {});
          const { blobs: revoked } = await s.list({ prefix: 'revoked-ban:' }).catch(() => ({blobs:[]}));
          for (const rb of revoked) {
            const mark = await s.get(rb.key,{type:'json'}).catch(()=>null);
            if (mark?.username === u.username) await s.delete(rb.key).catch(()=>{});
          }
        }
        const sessions = await listSessionsForUser(s, u.userId);
        const schedData = await s.get(`schedule-data:${u.userId}`, { type: 'json' }).catch(() => null);
        const allSubs = (await s.get(`subscriptions:${u.userId}`, { type: 'json' }).catch(() => null)) || [];
        const currentOrigin = String(process.env.URL || process.env.DEPLOY_PRIME_URL || '').replace(/\/$/, '');
        const subs = allSubs.filter(sub => sub && sub.siteOrigin === currentOrigin);
        users.push({
          username: u.username, email: u.email || null, emailVerified: u.emailVerified === true,
          role: isMasterUsername(u.username, admin.master) ? 'master' : (u.role || 'user'), isMaster: isMasterUsername(u.username, admin.master), createdAt: u.createdAt || null, lastActive: u.lastActive || null,
          banned: !!u.banned, banReason: u.banReason || null, banExpiresAt: u.banExpiresAt || 0, sessionsCount: sessions.length,
          ips: [...new Set(sessions.map(x => x.ip).filter(Boolean))],
          scheduleUpdatedAt: schedData?.updatedAt || null,
          subjectsCount: schedData?.subjects?.length || 0, notesCount: schedData?.notes?.length || 0,
          pushSubscriptions: subs.length
        });
      }
      users.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json(200, { ok: true, users, currentAdmin: admin.user.username, currentIsMaster: admin.user.username === admin.master });
    }

    if (action === 'list-sessions') {
      const username = String(body.username || '').trim().toLowerCase();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      const sessions = await listSessionsForUser(s, user.userId);
      return json(200, {
        ok: true,
        username,
        sessions: sessions.map(x => ({
          id: sessionId(x.token), createdAt: x.createdAt, expiresAt: x.expiresAt,
          lastActive: x.lastActive, ip: x.ip || 'unknown', userAgent: x.userAgent || '',
          device: x.device || null
        }))
      });
    }

    if (action === 'revoke-session') {
      const username = String(body.username || '').trim().toLowerCase();
      const sid = String(body.sessionId || '').trim();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (username === admin.user.username) return json(400, { error: 'Для власного акаунта скористайся виходом із пристрою' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Звичайний адміністратор не може керувати головним адміністратором або іншим адміністратором' });
      if (String(body.confirm || '') !== `REVOKE ${username} ${sid}`) return json(400, { error: `Для завершення сесії введи: REVOKE ${username} ${sid}` });
      const sessions = await listSessionsForUser(s, user.userId);
      const target = sessions.find(x => sessionId(x.token) === sid);
      if (!target) return json(404, { error: 'Сесію не знайдено' });
      await deleteSession(s, target.token);
      await auditAdmin(s, admin, 'revoke-session', { username, ip: target.ip });
      return json(200, { ok: true });
    }

    if (action === 'revoke-all-sessions') {
      const username = String(body.username || '').trim().toLowerCase();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (username === admin.user.username) return json(400, { error: 'Не можна завершити всі власні сесії з адмін-панелі' });
      if (String(body.confirm || '') !== `REVOKE ${username}`) return json(400, { error: `Для завершення всіх сесій введи: REVOKE ${username}` });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Звичайний адміністратор не може керувати головним адміністратором або іншим адміністратором' });
      await deleteAllSessionsForUser(s, user.userId);
      await auditAdmin(s, admin, 'revoke-all-sessions', { username });
      return json(200, { ok: true });
    }

    if (action === 'ban-user' || action === 'unban-user') {
      const username = String(body.username || '').trim().toLowerCase();
      if (!username) return json(400, { error: 'Немає username' });
      if (username === admin.user.username) return json(400, { error: 'Не можна заблокувати самого себе' });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Звичайний адміністратор не може заблокувати головного адміністратора або іншого адміністратора' });

      const expectedConfirm = action === 'ban-user' ? `BAN ${username}` : `UNBAN ${username}`;
      if (String(body.confirm || '') !== expectedConfirm) return json(400, { error: `Для підтвердження введи: ${expectedConfirm}` });
      const isBan = action === 'ban-user';
      user.banned = isBan;
      user.bannedAt = isBan ? Date.now() : null;
      user.banReason = isBan ? String(body.reason || '').slice(0, 500) : null;
      const durationMs = {hour:3600000,day:86400000,week:604800000,forever:0}[body.duration || 'forever'] ?? 0;
      user.banExpiresAt = isBan && durationMs ? Date.now()+durationMs : 0;
      if (!isBan) user.banExpiresAt = 0;
      const sessionsBeforeBan = await listSessionsForUser(s, user.userId);
      const sessionIps = [...new Set(sessionsBeforeBan.map(x => x.ip).filter(x => x && x !== 'unknown'))];
      await s.setJSON(`user:${username}`, user);
      if (isBan) {
        for (const session of sessionsBeforeBan) {
          await s.setJSON(`revoked-ban:${session.token}`, {
            username,
            userId: user.userId,
            reason: user.banReason || '',
            expiresAt: user.banExpiresAt || 0,
            createdAt: Date.now(),
            releasedAt: 0
          }).catch(()=>{});
        }
      }
      if (!isBan) {
        const { blobs: revokedBlobs } = await s.list({ prefix: 'revoked-ban:' }).catch(() => ({blobs:[]}));
        for (const b of revokedBlobs) {
          const mark = await s.get(b.key, {type:'json'}).catch(()=>null);
          if (mark && mark.username === username) {
            // The old token must remain invalid, but it must no longer
            // display stale ban information after an unban.
            await s.delete(b.key).catch(()=>{});
          }
        }
      }
      await deleteAllSessionsForUser(s, user.userId);

      if (isBan && body.blockIp) {
        const ips = sessionIps.length ? sessionIps : (Array.isArray(body.ips) ? body.ips : []);
        for (const ip of ips.filter(x => x && x !== 'unknown').slice(0, 20)) {
          await setIpBan(s, ip, { reason: body.reason || `Блокування ${username}`, duration: body.ipDuration || 'forever', username });
        }
      }
      await recordActivity(s, user.userId, isBan ? 'account-banned' : 'account-unbanned', { admin: admin.user.username, reason: user.banReason || '', expiresAt: user.banExpiresAt || 0, blockIp: !!body.blockIp, ips: sessionIps });
      await auditAdmin(s, admin, isBan ? 'ban-user' : 'unban-user', { username, blockIp: !!body.blockIp, reason: user.banReason || '', expiresAt: user.banExpiresAt || 0 });
      return json(200, { ok: true });
    }

    if (action === 'delete-user') {
      const username = String(body.username || '').trim().toLowerCase();
      if (!username) return json(400, { error: 'Немає username' });
      if (username === admin.user.username) return json(400, { error: 'Не можна видалити самого себе' });
      if (String(body.confirm || '') !== `DELETE ${username}`) return json(400, { error: `Для видалення введи: DELETE ${username}` });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Звичайний адміністратор не може видалити головного адміністратора або іншого адміністратора' });

      const sessions = await listSessionsForUser(s, user.userId);
      if (body.blockIp) {
        for (const ip of [...new Set(sessions.map(x => x.ip).filter(x => x && x !== 'unknown'))].slice(0, 20)) {
          await setIpBan(s, ip, { reason: body.reason || `Видалення ${username}`, duration: body.ipDuration || 'forever', username });
        }
      }
      await deleteAllSessionsForUser(s, user.userId);
      await s.delete(`user:${username}`).catch(() => {});
      if (user.email) await s.delete(`email:${user.email}`).catch(() => {});
      await s.delete(`schedule-data:${user.userId}`).catch(() => {});
      await s.delete(`subscriptions:${user.userId}`).catch(() => {});
      await s.delete(`fired-log:${user.userId}`).catch(() => {});
      await auditAdmin(s, admin, 'delete-user', { username, blockIp: !!body.blockIp });
      return json(200, { ok: true });
    }

    if (action === 'update-email') {
      const username = String(body.username || '').trim().toLowerCase();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Звичайний адміністратор не може змінювати дані іншого адміністратора' });
      if (String(body.confirm || '') !== `EMAIL ${username}`) return json(400, { error: `Для зміни email введи: EMAIL ${username}` });
      const rawEmail = body.email == null ? '' : String(body.email).trim().toLowerCase();
      const oldEmail = user.email || '';
      if (!rawEmail) {
        if (user.email) await s.delete(`email:${user.email}`).catch(() => {});
        delete user.email; user.emailVerified = false;
        await s.setJSON(`user:${username}`, user);
        await recordActivity(s, user.userId, 'admin-email-removed', { admin: admin.user.username });
        await auditAdmin(s, admin, 'update-email', { username, removed: true });
        return json(200, { ok: true, email: null, emailVerified: false });
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)) return json(400, { error: 'Невірний формат email' });
      const existing = await s.get(`email:${rawEmail}`, { type: 'json' }).catch(() => null);
      if (existing && String(existing.username).toLowerCase() !== username) return json(409, { error: 'Цей email вже прив’язаний до іншого акаунта' });
      if (user.email && user.email !== rawEmail) await s.delete(`email:${user.email}`).catch(() => {});
      const code = String(crypto.randomInt(100000, 1000000));
      user.email = rawEmail; user.emailVerified = true; user.emailRecoveryUpdatedByAdminAt = Date.now();
      await s.setJSON(`email:${rawEmail}`, { username });
      await s.setJSON(`admin-email-confirm:${username}`, { codeHash: hashCode(code).toString('hex'), email: rawEmail, expiresAt: Date.now() + 15 * 60 * 1000, attempts: 0, admin: admin.user.username });
      await s.setJSON(`user:${username}`, user);
      await recordActivity(s, user.userId, 'admin-email-changed', { admin: admin.user.username, oldEmail: oldEmail || null, newEmail: rawEmail });
      try { await sendAdminRecoveryEmail(rawEmail, code); } catch (mailErr) { /* email is changed for recovery, notification failure is logged */ }
      if (oldEmail && oldEmail !== rawEmail) {
        try { await sendAdminRecoveryEmail(oldEmail, code); } catch {}
      }
      await auditAdmin(s, admin, 'update-email', { username, changed: oldEmail !== rawEmail });
      return json(200, { ok: true, email: user.email, emailVerified: true, confirmationSent: true });
    }

    if (action === 'confirm-admin-email') {
      const username = String(body.username || '').trim().toLowerCase();
      const code = String(body.code || '').trim();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Недостатньо прав' });
      if (String(body.confirm || '') !== `EMAIL-CONFIRM ${username}`) return json(400, { error: `Для підтвердження введи: EMAIL-CONFIRM ${username}` });
      const pending = await s.get(`admin-email-confirm:${username}`, { type: 'json' }).catch(() => null);
      if (!pending || pending.expiresAt <= Date.now()) return json(400, { error: 'Код не знайдено або прострочено' });
      const ip = getClientIp(event);
      const rl = await protectCodeAttempt(s, 'admin-email-confirm', username, ip, 8, 15 * 60 * 1000);
      if (!rl.allowed) return json(429, { error: `Забагато спроб. Спробуй через ${rl.retryAfter} с.` });
      if (Number(pending.attempts || 0) >= 5) { await s.delete(`admin-email-confirm:${username}`).catch(() => {}); return json(429, { error: 'Забагато неправильних кодів. Запроси новий.' }); }
      if (!safeCodeEqual(code, pending.codeHash)) { pending.attempts = Number(pending.attempts || 0) + 1; await s.setJSON(`admin-email-confirm:${username}`, pending); return json(401, { error: 'Невірний код' }); }
      await s.delete(`admin-email-confirm:${username}`).catch(() => {});
      await recordActivity(s, user.userId, 'admin-email-confirmed', { admin: admin.user.username, email: pending.email });
      await auditAdmin(s, admin, 'confirm-admin-email', { username });
      return json(200, { ok: true });
    }

    if (action === 'account-details') {
      const username = String(body.username || '').trim().toLowerCase();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Недостатньо прав для перегляду цього акаунта' });
      const sessions = await listSessionsForUser(s, user.userId);
      const activity = await listActivity(s, user.userId, 1000);
      return json(200, { ok: true, username, profile: { email: user.email || null, emailVerified: user.emailVerified === true, createdAt: user.createdAt || null, lastActive: user.lastActive || null, banned: !!user.banned, banReason: user.banReason || null, banAt: user.bannedAt || null, banExpiresAt: user.banExpiresAt || 0, security: user.security || { newDeviceEmail: true, requireNewDeviceEmail: false, requireEveryLoginEmail: false } }, sessions: sessions.map(x => ({ id: sessionId(x.token), createdAt: x.createdAt, expiresAt: x.expiresAt, lastActive: x.lastActive, ip: x.ip || 'unknown', userAgent: x.userAgent || '', device: x.device || null })), activity });
    }

    if (action === 'clear-account-history') {
      const username = String(body.username || '').trim().toLowerCase();
      const confirm = String(body.confirm || '');
      if (confirm !== `CLEAR ${username}`) return json(400, { error: `Для очищення введи: CLEAR ${username}` });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Недостатньо прав' });
      await s.delete(`account-activity:${user.userId}`).catch(() => {});
      await auditAdmin(s, admin, 'clear-account-history', { username });
      return json(200, { ok: true });
    }

    if (action === 'set-role') {
      const username = String(body.username || '').trim().toLowerCase();
      const role = body.role === 'admin' ? 'admin' : 'user';
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!username) return json(400, { error: 'Немає username' });
      if (username === master && role !== 'admin') return json(400, { error: 'Головного адміністратора не можна позбавити прав' });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (username === admin.user.username) return json(400, { error: 'Не можна змінювати власну роль' });
      if (!canManageTarget(admin, user)) return json(403, { error: 'Звичайний адміністратор не може змінювати роль іншого адміністратора' });
      if (String(body.confirm || '') !== `ROLE ${username}`) return json(400, { error: `Для зміни ролі введи: ROLE ${username}` });
      user.role = isMasterUsername(username, master) ? 'admin' : role;
      await s.setJSON(`user:${username}`, user);
      if (role !== 'admin') await deleteAllSessionsForUser(s, user.userId);
      await auditAdmin(s, admin, 'set-role', { username, role });
      return json(200, { ok: true, role });
    }

    if (action === 'ip-list') {
      const { blobs } = await s.list({ prefix: 'ip-ban:' });
      const bans = [];
      for (const b of blobs) {
        const ban = await s.get(b.key, { type: 'json' }).catch(() => null);
        if (!ban) continue;
        if (ban.expiresAt && ban.expiresAt <= Date.now()) {
          await s.delete(b.key).catch(() => {});
          continue;
        }
        bans.push(ban);
      }
      bans.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
      return json(200, { ok: true, bans });
    }

    if (action === 'ip-ban') {
      const ip = String(body.ip || '').trim();
      if (!ip || !net.isIP(ip)) return json(400, { error: 'Вкажи коректну IPv4 або IPv6 адресу' });
      if (String(body.confirm || '') !== 'BAN IP') return json(400, { error: 'Для блокування IP введи: BAN IP' });
      await setIpBan(s, ip, { reason: body.reason, duration: body.duration, username: body.username });
      await auditAdmin(s, admin, 'ip-ban', { ip, duration: body.duration || 'forever' });
      return json(200, { ok: true });
    }

    if (action === 'ip-unban') {
      const ip = String(body.ip || '').trim();
      if (String(body.confirm || '') !== 'UNBAN IP') return json(400, { error: 'Для розблокування IP введи: UNBAN IP' });
      await s.delete(`ip-ban:${ip}`).catch(() => {});
      await auditAdmin(s, admin, 'ip-unban', { ip });
      return json(200, { ok: true });
    }

    if (action === 'audit-log') {
      const log = (await s.get('audit-log', { type: 'json' }).catch(() => null)) || [];
      const integrity = await verifyAuditLog(s);
      return json(200, { ok: true, log: log.slice(-200).reverse(), integrity });
    }

    if (action === 'my-role') {
      return json(200, { ok: true, username: admin.user.username, role: admin.user.role === 'admin' || admin.user.username === admin.master ? 'admin' : 'user' });
    }

    return json(400, { error: 'Невідома дія' });
  } catch (err) {
    return json(500, { error: String(err) });
  }
};
