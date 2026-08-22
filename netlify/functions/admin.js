const crypto = require('crypto');
const net = require('net');
const { store } = require('./lib/store');
const { validateSession, extractToken, deleteAllSessionsForUser, listSessionsForUser, deleteSession } = require('./lib/session');
const { getClientIp, isIpBanned } = require('./lib/security');

function json(statusCode, body) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

async function requireAdmin(event, s) {
  const token = extractToken(event);
  const sess = await validateSession(s, token);
  if (!sess || sess.banned) return null;
  const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
  if (!user) return null;
  const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
  if (sess.username === master || user.role === 'admin') return { sess, user, master };
  return null;
}

function sessionId(token) {
  return crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
}

async function audit(s, adminUsername, action, details = {}) {
  const item = { id: crypto.randomUUID(), at: Date.now(), adminUsername, action, details };
  const list = (await s.get('audit-log', { type: 'json' }).catch(() => null)) || [];
  list.push(item);
  await s.setJSON('audit-log', list.slice(-500)).catch(() => {});
}

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
    const admin = await requireAdmin(event, s);
    if (!admin) return json(403, { error: 'Немає доступу' });

    const body = JSON.parse(event.body || '{}');
    const { action } = body;

    if (action === 'list-users') {
      const { blobs } = await s.list({ prefix: 'user:' });
      const users = [];
      for (const b of blobs) {
        const u = await s.get(b.key, { type: 'json' }).catch(() => null);
        if (!u) continue;
        const sessions = await listSessionsForUser(s, u.userId);
        const schedData = await s.get(`schedule-data:${u.userId}`, { type: 'json' }).catch(() => null);
        const subs = (await s.get(`subscriptions:${u.userId}`, { type: 'json' }).catch(() => null)) || [];
        users.push({
          username: u.username, email: u.email || null, emailVerified: u.emailVerified === true,
          role: u.role || 'user', createdAt: u.createdAt || null, lastActive: u.lastActive || null,
          banned: !!u.banned, sessionsCount: sessions.length,
          ips: [...new Set(sessions.map(x => x.ip).filter(Boolean))],
          scheduleUpdatedAt: schedData?.updatedAt || null,
          subjectsCount: schedData?.subjects?.length || 0, notesCount: schedData?.notes?.length || 0,
          pushSubscriptions: subs.length
        });
      }
      users.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json(200, { ok: true, users, currentAdmin: admin.user.username });
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
      const sessions = await listSessionsForUser(s, user.userId);
      const target = sessions.find(x => sessionId(x.token) === sid);
      if (!target) return json(404, { error: 'Сесію не знайдено' });
      await deleteSession(s, target.token);
      await audit(s, admin.user.username, 'revoke-session', { username, ip: target.ip });
      return json(200, { ok: true });
    }

    if (action === 'revoke-all-sessions') {
      const username = String(body.username || '').trim().toLowerCase();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      if (username === admin.user.username) return json(400, { error: 'Не можна завершити всі власні сесії з адмін-панелі' });
      await deleteAllSessionsForUser(s, user.userId);
      await audit(s, admin.user.username, 'revoke-all-sessions', { username });
      return json(200, { ok: true });
    }

    if (action === 'ban-user' || action === 'unban-user') {
      const username = String(body.username || '').trim().toLowerCase();
      if (!username) return json(400, { error: 'Немає username' });
      if (username === admin.user.username) return json(400, { error: 'Не можна заблокувати самого себе' });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });

      const isBan = action === 'ban-user';
      user.banned = isBan;
      user.bannedAt = isBan ? Date.now() : null;
      user.banReason = isBan ? String(body.reason || '').slice(0, 200) : null;
      const sessionsBeforeBan = await listSessionsForUser(s, user.userId);
      const sessionIps = [...new Set(sessionsBeforeBan.map(x => x.ip).filter(x => x && x !== 'unknown'))];
      await s.setJSON(`user:${username}`, user);
      await deleteAllSessionsForUser(s, user.userId);

      if (isBan && body.blockIp) {
        const ips = sessionIps.length ? sessionIps : (Array.isArray(body.ips) ? body.ips : []);
        for (const ip of ips.filter(x => x && x !== 'unknown').slice(0, 20)) {
          await setIpBan(s, ip, { reason: body.reason || `Блокування ${username}`, duration: body.ipDuration || 'forever', username });
        }
      }
      await audit(s, admin.user.username, isBan ? 'ban-user' : 'unban-user', { username, blockIp: !!body.blockIp });
      return json(200, { ok: true });
    }

    if (action === 'delete-user') {
      const username = String(body.username || '').trim().toLowerCase();
      if (!username) return json(400, { error: 'Немає username' });
      if (username === admin.user.username) return json(400, { error: 'Не можна видалити самого себе' });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });

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
      await audit(s, admin.user.username, 'delete-user', { username, blockIp: !!body.blockIp });
      return json(200, { ok: true });
    }

    if (action === 'update-email') {
      const username = String(body.username || '').trim().toLowerCase();
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      const rawEmail = body.email == null ? '' : String(body.email).trim().toLowerCase();
      if (!rawEmail) {
        if (user.email) await s.delete(`email:${user.email}`).catch(() => {});
        delete user.email; user.emailVerified = false;
      } else {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)) return json(400, { error: 'Невірний формат email' });
        const existing = await s.get(`email:${rawEmail}`, { type: 'json' }).catch(() => null);
        if (existing && String(existing.username).toLowerCase() !== username) return json(409, { error: 'Цей email вже прив’язаний до іншого акаунта' });
        if (user.email && user.email !== rawEmail) await s.delete(`email:${user.email}`).catch(() => {});
        user.email = rawEmail; user.emailVerified = true;
        await s.setJSON(`email:${rawEmail}`, { username });
      }
      await s.setJSON(`user:${username}`, user);
      await audit(s, admin.user.username, 'update-email', { username });
      return json(200, { ok: true, email: user.email || null, emailVerified: user.emailVerified === true });
    }

    if (action === 'set-role') {
      const username = String(body.username || '').trim().toLowerCase();
      const role = body.role === 'admin' ? 'admin' : 'user';
      const master = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
      if (!username) return json(400, { error: 'Немає username' });
      if (username === master && role !== 'admin') return json(400, { error: 'Головного адміністратора не можна позбавити прав' });
      const user = await s.get(`user:${username}`, { type: 'json' }).catch(() => null);
      if (!user) return json(404, { error: 'Користувача не знайдено' });
      user.role = role;
      await s.setJSON(`user:${username}`, user);
      if (role !== 'admin') await deleteAllSessionsForUser(s, user.userId);
      await audit(s, admin.user.username, 'set-role', { username, role });
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
      await setIpBan(s, ip, { reason: body.reason, duration: body.duration, username: body.username });
      await audit(s, admin.user.username, 'ip-ban', { ip, duration: body.duration || 'forever' });
      return json(200, { ok: true });
    }

    if (action === 'ip-unban') {
      const ip = String(body.ip || '').trim();
      await s.delete(`ip-ban:${ip}`).catch(() => {});
      await audit(s, admin.user.username, 'ip-unban', { ip });
      return json(200, { ok: true });
    }

    if (action === 'audit-log') {
      const log = (await s.get('audit-log', { type: 'json' }).catch(() => null)) || [];
      return json(200, { ok: true, log: log.slice(-200).reverse() });
    }

    if (action === 'my-role') {
      return json(200, { ok: true, username: admin.user.username, role: admin.user.role === 'admin' || admin.user.username === admin.master ? 'admin' : 'user' });
    }

    return json(400, { error: 'Невідома дія' });
  } catch (err) {
    return json(500, { error: String(err) });
  }
};
