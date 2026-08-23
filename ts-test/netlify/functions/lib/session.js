const crypto = require('crypto');
const { recordActivity } = require('./activity');

const SESSION_DAYS = 90;
const SESSION_LIST_LIMIT = 50;
const SESSION_BINDING_VERSION = 1;

function sessionMeta(event) {
  const { getClientIp, getUserAgent, parseDevice } = require('./security');
  const ip = getClientIp(event);
  const userAgent = getUserAgent(event);
  return { ip, userAgent, device: parseDevice(userAgent) };
}

async function createSession(s, userId, username, meta = {}, opts = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_DAYS * 24 * 60 * 60 * 1000;
  const record = {
    userId, username, createdAt: now, expiresAt,
    ip: meta.ip || 'unknown',
    userAgent: String(meta.userAgent || '').slice(0, 500),
    device: meta.device || null,
    lastActive: now,
    deviceId: String(meta.deviceId || '').slice(0, 128),
    authMethod: opts.authMethod || 'password',
    bindingVersion: SESSION_BINDING_VERSION,
    fingerprint: crypto.createHash('sha256').update(`${String(meta.deviceId || '')}|${String(meta.userAgent || '')}`).digest('hex'),
    sessionId: crypto.createHash('sha256').update(token).digest('hex').slice(0, 16),
    ipLastSeen: meta.ip || 'unknown',
    ipChanges: 0
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
  await recordActivity(s, userId, 'login', { ip: record.ip, device: record.device, sessionId: token.slice(0, 12), authMethod: record.authMethod, deviceId: record.deviceId || null });

  return { token, expiresAt };
}

async function validateSession(s, token, event = null) {
  if (!token) return null;
  let sess;
  try { sess = await s.get(`session:${token}`, { type: 'json' }); } catch { return null; }
  if (!sess) return null;
  const revoked = await s.get(`revoked-ban:${token}`, { type: 'json' }).catch(() => null);
  if (revoked) return null;
  if (sess.expiresAt < Date.now()) {
    await deleteSession(s, token);
    return null;
  }

  // Bind authenticated sessions to the browser-generated device ID and User-Agent.
  // A stolen bearer token alone is therefore not sufficient to replay the session.
  if (event && sess.bindingVersion >= SESSION_BINDING_VERSION && sess.deviceId) {
    const { getClientIp, getUserAgent } = require('./security');
    const ip = getClientIp(event);
    const headers = event.headers || {};
    const presentedDeviceId = String(headers['x-ts-device-id'] || headers['X-TS-Device-ID'] || '').slice(0, 128);
    const presentedUa = getUserAgent(event);
    const presentedFingerprint = crypto.createHash('sha256').update(`${presentedDeviceId}|${presentedUa}`).digest('hex');
    if (!presentedDeviceId || presentedDeviceId !== sess.deviceId || presentedFingerprint !== sess.fingerprint) {
      await recordActivity(s, sess.userId, 'session-security-rejected', { ip, device: sess.device, sessionId: token.slice(0, 12), reason: 'device-or-user-agent-mismatch' }).catch(() => {});
      await deleteSession(s, token, 'session-security-revoked').catch(() => {});
      return null;
    }
    if (ip && ip !== 'unknown' && sess.ipLastSeen && ip !== sess.ipLastSeen) {
      const previousIp = sess.ipLastSeen;
      sess.ipChanges = Number(sess.ipChanges || 0) + 1;
      sess.ipLastSeen = ip;
      await recordActivity(s, sess.userId, 'session-ip-change', { ip, previousIp, device: sess.device, sessionId: token.slice(0, 12), changeCount: sess.ipChanges }).catch(() => {});
    }
  }

  const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
  if (!user) {
    await deleteSession(s, token);
    return null;
  }
  if (user.banned) {
    const banExpiresAt = Number(user.banExpiresAt || 0);
    if (banExpiresAt && banExpiresAt <= Date.now()) {
      user.banned = false;
      user.bannedAt = null;
      user.banReason = null;
      user.banExpiresAt = 0;
      await s.setJSON(`user:${user.username}`, user).catch(() => {});
      await deleteSession(s, token);
      return null;
    }
    return { ...sess, banned: true, banReason: user.banReason || '', banExpiresAt };
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

async function deleteSession(s, token, reason = 'session-ended') {
  if (!token) return;
  const sess = await s.get(`session:${token}`, { type: 'json' }).catch(() => null);
  await s.delete(`session:${token}`).catch(() => {});
  if (sess?.userId) await recordActivity(s, sess.userId, reason, { ip: sess.ip, device: sess.device, sessionId: token.slice(0, 12) });
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

function getSessionPublicId(token, sess) {
  return sess?.sessionId || crypto.createHash('sha256').update(String(token)).digest('hex').slice(0, 16);
}

async function revokeSessionById(s, userId, sessionId, exceptToken = '') {
  const list = (await s.get(`user-sessions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  for (const token of list) {
    if (token === exceptToken) continue;
    const sess = await s.get(`session:${token}`, { type: 'json' }).catch(() => null);
    if (!sess) continue;
    if (getSessionPublicId(token, sess) === String(sessionId)) {
      await deleteSession(s, token, 'session-revoked-by-user');
      return true;
    }
  }
  return false;
}

async function revokeOtherSessions(s, userId, exceptToken) {
  const list = (await s.get(`user-sessions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  let count = 0;
  for (const token of list) {
    if (token === exceptToken) continue;
    if (await s.get(`session:${token}`, { type: 'json' }).catch(() => null)) {
      await deleteSession(s, token, 'session-revoked-by-user');
      count++;
    }
  }
  return count;
}

function parseCookies(event) {
  const raw = event?.headers?.cookie || event?.headers?.Cookie || '';
  const out = {};
  for (const part of String(raw).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function extractToken(event) {
  // Session credentials are HttpOnly cookies. Authorization headers are deliberately
  // not accepted, so a stolen bearer token cannot be replayed through this API.
  return parseCookies(event)['__Host-ts_session'] || null;
}

function sessionCookie(token, maxAgeSeconds = SESSION_DAYS * 24 * 60 * 60) {
  return `__Host-ts_session=${encodeURIComponent(token)}; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

function clearSessionCookie() {
  return '__Host-ts_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax';
}

module.exports = { createSession, validateSession, deleteSession, deleteAllSessionsForUser, listSessionsForUser, revokeSessionById, revokeOtherSessions, getSessionPublicId, extractToken, sessionMeta, sessionCookie, clearSessionCookie };
