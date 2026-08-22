const crypto = require('crypto');

const SESSION_DAYS = 90;
const SESSION_LIST_LIMIT = 50;

function sessionMeta(event) {
  const { getClientIp, getUserAgent, parseDevice } = require('./security');
  const ip = getClientIp(event);
  const userAgent = getUserAgent(event);
  return { ip, userAgent, device: parseDevice(userAgent) };
}

async function createSession(s, userId, username, meta = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const record = {
    userId, username, createdAt: now, expiresAt,
    ip: meta.ip || 'unknown',
    userAgent: String(meta.userAgent || '').slice(0, 500),
    device: meta.device || null,
    lastActive: now
  };
  await s.setJSON(`session:${token}`, record);

  const listKey = `user-sessions:${userId}`;
  const list = (await s.get(listKey, { type: 'json' })) || [];
  list.push(token);
  const kept = list.slice(-SESSION_LIST_LIMIT);
  if (kept.length !== list.length) {
    for (const oldToken of list.slice(0, -SESSION_LIST_LIMIT)) {
      await s.delete(`session:${oldToken}`).catch(() => {});
    }
  }
  await s.setJSON(listKey, kept);

  return { token, expiresAt };
}

async function validateSession(s, token) {
  if (!token) return null;
  let sess;
  try { sess = await s.get(`session:${token}`, { type: 'json' }); } catch { return null; }
  if (!sess) return null;
  if (sess.expiresAt < Date.now()) {
    await deleteSession(s, token);
    return null;
  }

  const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
  if (!user) {
    await deleteSession(s, token);
    return null;
  }
  if (user.banned) {
    return { ...sess, banned: true };
  }

  // Keep last-active data reasonably fresh without writing on every request.
  if (!sess.lastActive || Date.now() - sess.lastActive > 5 * 60 * 1000) {
    sess.lastActive = Date.now();
    await s.setJSON(`session:${token}`, sess).catch(() => {});
    user.lastActive = sess.lastActive;
    await s.setJSON(`user:${sess.username}`, user).catch(() => {});
  }
  return sess;
}

async function deleteSession(s, token) {
  if (!token) return;
  const sess = await s.get(`session:${token}`, { type: 'json' }).catch(() => null);
  await s.delete(`session:${token}`).catch(() => {});
  if (sess?.userId) {
    const key = `user-sessions:${sess.userId}`;
    const list = (await s.get(key, { type: 'json' }).catch(() => null)) || [];
    const next = list.filter(t => t !== token);
    if (next.length) await s.setJSON(key, next).catch(() => {});
    else await s.delete(key).catch(() => {});
  }
}

async function deleteAllSessionsForUser(s, userId) {
  const listKey = `user-sessions:${userId}`;
  const list = (await s.get(listKey, { type: 'json' })) || [];
  for (const token of list) await s.delete(`session:${token}`).catch(() => {});
  await s.delete(listKey).catch(() => {});
}

async function listSessionsForUser(s, userId) {
  const list = (await s.get(`user-sessions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  const sessions = [];
  const now = Date.now();
  for (const token of list) {
    const sess = await s.get(`session:${token}`, { type: 'json' }).catch(() => null);
    if (!sess) continue;
    if (sess.expiresAt <= now) {
      await s.delete(`session:${token}`).catch(() => {});
      continue;
    }
    sessions.push({ token, ...sess });
  }
  const validTokens = sessions.map(x => x.token);
  if (validTokens.length) await s.setJSON(`user-sessions:${userId}`, validTokens).catch(() => {});
  else await s.delete(`user-sessions:${userId}`).catch(() => {});
  return sessions;
}

function extractToken(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}

module.exports = { createSession, validateSession, deleteSession, deleteAllSessionsForUser, listSessionsForUser, extractToken, sessionMeta };
