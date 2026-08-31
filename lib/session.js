const crypto = require('crypto');
const { recordActivity } = require('./activity');
const { atomicUpdateJSON } = require('./store');

const SESSION_DAYS = 90;
const SESSION_LIST_LIMIT = 50;
const SESSION_BINDING_VERSION = 2;

function sessionKey(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}
function legacySessionKey(token) { return `session:${token}`; }
function secureSessionKey(token) { return `session:${sessionKey(token)}`; }

function sessionMeta(event) {
  const { getClientIp, getUserAgent, parseDevice } = require('./security');
  const ip = getClientIp(event);
  const userAgent = getUserAgent(event);
  return { ip, userAgent, device: parseDevice(userAgent) };
}

async function readSession(s, token) {
  if (!token) return { sess: null, key: null, legacy: false };
  const hashedKey = secureSessionKey(token);
  let sess = await s.get(hashedKey, { type: 'json' }).catch(() => null);
  if (sess) return { sess, key: hashedKey, legacy: false };
  // One-time compatibility path for sessions created by <=5.3.0.
  const oldKey = legacySessionKey(token);
  sess = await s.get(oldKey, { type: 'json' }).catch(() => null);
  if (sess) return { sess, key: hashedKey, legacy: true, oldKey };
  return { sess: null, key: null, legacy: false };
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
    sessionId: sessionKey(token).slice(0, 16),
    ipLastSeen: meta.ip || 'unknown',
    ipChanges: 0
  };
  const key = secureSessionKey(token);
  await s.setJSON(key, record);

  const listKey = `user-sessions:${userId}`;
  let removed = [];
  await atomicUpdateJSON(listKey, [], list => {
    const next = [...(Array.isArray(list) ? list : []), key];
    removed = next.slice(0, Math.max(0, next.length - SESSION_LIST_LIMIT));
    return next.slice(-SESSION_LIST_LIMIT);
  }, { store: s });
  for (const oldKey of removed) await s.delete(oldKey).catch(() => {});
  await recordActivity(s, userId, 'login', { ip: record.ip, device: record.device, sessionId: record.sessionId, authMethod: record.authMethod, deviceId: record.deviceId || null });
  return { token, expiresAt };
}

async function validateSession(s, token, event = null) {
  if (!token) return null;
  const read = await readSession(s, token);
  let sess = read.sess;
  if (!sess) return null;
  const revoked = await s.get(`revoked-ban:${sessionKey(token)}`, { type: 'json' }).catch(() => null) || await s.get(`revoked-ban:${token}`, { type: 'json' }).catch(() => null);
  if (revoked) return null;
  if (sess.expiresAt < Date.now()) { await deleteSession(s, token); return null; }

  if (event && sess.bindingVersion >= 1 && sess.deviceId) {
    const { getClientIp, getUserAgent } = require('./security');
    const ip = getClientIp(event);
    const headers = event.headers || {};
    const presentedDeviceId = String(headers['x-ts-device-id'] || headers['X-TS-Device-ID'] || '').slice(0, 128);
    const presentedUa = getUserAgent(event);
    const presentedFingerprint = crypto.createHash('sha256').update(`${presentedDeviceId}|${presentedUa}`).digest('hex');
    if (!presentedDeviceId || presentedDeviceId !== sess.deviceId || presentedFingerprint !== sess.fingerprint) {
      await recordActivity(s, sess.userId, 'session-security-rejected', { ip, device: sess.device, sessionId: sess.sessionId, reason: 'device-or-user-agent-mismatch' }).catch(() => {});
      await deleteSession(s, token, 'session-security-revoked').catch(() => {});
      return null;
    }
    if (ip && ip !== 'unknown' && sess.ipLastSeen && ip !== sess.ipLastSeen) {
      const previousIp = sess.ipLastSeen;
      sess.ipChanges = Number(sess.ipChanges || 0) + 1;
      sess.ipLastSeen = ip;
      await recordActivity(s, sess.userId, 'session-ip-change', { ip, previousIp, device: sess.device, sessionId: sess.sessionId, changeCount: sess.ipChanges }).catch(() => {});
    }
  }

  const user = await s.get(`user:${sess.username}`, { type: 'json' }).catch(() => null);
  if (!user) { await deleteSession(s, token); return null; }
  if (user.passwordChangedAt && Number(sess.createdAt || 0) < Number(user.passwordChangedAt || 0)) {
    await deleteSession(s, token, 'session-invalidated-by-password-change').catch(() => {});
    return null;
  }
  if (user.banned) {
    const banExpiresAt = Number(user.banExpiresAt || 0);
    if (banExpiresAt && banExpiresAt <= Date.now()) {
      user.banned = false; user.bannedAt = null; user.banReason = null; user.banExpiresAt = 0;
      await s.setJSON(`user:${user.username}`, user).catch(() => {}); await deleteSession(s, token); return null;
    }
    return { ...sess, banned: true, banReason: user.banReason || '', banExpiresAt };
  }

  // Migrate old plaintext-token storage after a successful validation.
  if (read.legacy) {
    await s.setJSON(read.key, sess).catch(() => {});
    await s.delete(read.oldKey).catch(() => {});
    const listKey = `user-sessions:${sess.userId}`;
    const list = (await s.get(listKey, { type: 'json' }).catch(() => null)) || [];
    const migrated = list.map(k => k === read.oldKey ? read.key : k);
    await s.setJSON(listKey, [...new Set(migrated)].slice(-SESSION_LIST_LIMIT)).catch(() => {});
  }
  if (!sess.lastActive || Date.now() - sess.lastActive > 5 * 60 * 1000 || sess.ipLastSeen !== sess.ip) {
    sess.lastActive = Date.now();
    if (sess.ipLastSeen !== sess.ip && sess.ip && sess.ip !== 'unknown') sess.ipLastSeen = sess.ip;
    await s.setJSON(read.key, sess).catch(() => {});
    user.lastActive = sess.lastActive; await s.setJSON(`user:${sess.username}`, user).catch(() => {});
  }
  return sess;
}

async function deleteSession(s, token, reason = 'session-ended') {
  if (!token) return;
  const read = await readSession(s, token);
  const sess = read.sess;
  await s.delete(secureSessionKey(token)).catch(() => {});
  await s.delete(legacySessionKey(token)).catch(() => {});
  if (sess?.userId) await recordActivity(s, sess.userId, reason, { ip: sess.ip, device: sess.device, sessionId: sess.sessionId || sessionKey(token).slice(0,16) });
  if (sess?.userId) {
    const key = `user-sessions:${sess.userId}`;
    const keys = new Set([secureSessionKey(token), legacySessionKey(token)]);
    await atomicUpdateJSON(key, [], list => {
      const next = (Array.isArray(list) ? list : []).filter(k => !keys.has(k));
      return next.length ? next : [];
    }, { store: s }).catch(() => {});
    const after = await s.get(key, { type: 'json' }).catch(() => null);
    if (!Array.isArray(after) || !after.length) await s.delete(key).catch(() => {});
  }
}

async function deleteAllSessionsForUser(s, userId) {
  const listKey = `user-sessions:${userId}`;
  const list = (await s.get(listKey, { type: 'json' })) || [];
  for (const key of list) await s.delete(key).catch(() => {});
  await s.delete(listKey).catch(() => {});
}

async function listSessionsForUser(s, userId) {
  const list = (await s.get(`user-sessions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  const sessions = []; const validKeys = []; const now = Date.now();
  for (const key of list) {
    const sess = await s.get(key, { type: 'json' }).catch(() => null);
    if (!sess) continue;
    if (sess.expiresAt <= now) { await s.delete(key).catch(() => {}); continue; }
    sessions.push({ ...sess, sessionKey: key }); validKeys.push(key);
  }
  if (validKeys.length) await s.setJSON(`user-sessions:${userId}`, validKeys).catch(() => {}); else await s.delete(`user-sessions:${userId}`).catch(() => {});
  return sessions;
}

function getSessionPublicId(token, sess) { return sess?.sessionId || sessionKey(token).slice(0, 16); }

async function revokeSessionById(s, userId, sessionId, exceptToken = '') {
  const list = (await s.get(`user-sessions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  const exceptKey = exceptToken ? secureSessionKey(exceptToken) : '';
  for (const key of list) {
    if (key === exceptKey) continue;
    const sess = await s.get(key, { type: 'json' }).catch(() => null); if (!sess) continue;
    if (String(sess.sessionId) === String(sessionId)) { const token = key.replace(/^session:/,''); /* key is hash, not token */
      await s.delete(key).catch(() => {});
      await recordActivity(s, userId, 'session-revoked-by-user', { targetSessionId: String(sessionId).slice(0,32), reason:'user-request' }).catch(()=>{});
      const next=list.filter(x=>x!==key); if(next.length) await s.setJSON(`user-sessions:${userId}`,next); else await s.delete(`user-sessions:${userId}`);
      return true;
    }
  }
  return false;
}

async function deleteSessionByKey(s, userId, key, reason = 'session-ended') {
  if (!key) return;
  const sess = await s.get(key, { type: 'json' }).catch(() => null);
  await s.delete(key).catch(() => {});
  if (sess?.userId) await recordActivity(s, sess.userId, reason, { ip: sess.ip, device: sess.device, sessionId: sess.sessionId || String(key).slice(-16) });
  const listKey = `user-sessions:${userId}`;
  await atomicUpdateJSON(listKey, [], list => {
    const next = (Array.isArray(list) ? list : []).filter(k => k !== key);
    return next;
  }, { store: s }).catch(() => {});
  const after = await s.get(listKey, { type: 'json' }).catch(() => null);
  if (!Array.isArray(after) || !after.length) await s.delete(listKey).catch(() => {});
}

async function revokeOtherSessions(s, userId, exceptToken) {
  const list = (await s.get(`user-sessions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  const exceptKey = secureSessionKey(exceptToken); let count = 0;
  for (const key of list) { if (key === exceptKey) continue; if (await s.get(key,{type:'json'}).catch(()=>null)) { await s.delete(key).catch(()=>{}); count++; } }
  const next=list.filter(k=>k===exceptKey); if(next.length) await s.setJSON(`user-sessions:${userId}`,next); else await s.delete(`user-sessions:${userId}`);
  return count;
}

function parseCookies(event) {
  const raw = event?.headers?.cookie || event?.headers?.Cookie || ''; const out={};
  for(const part of String(raw).split(';')){const i=part.indexOf('=');if(i<0)continue;const k=part.slice(0,i).trim(),v=part.slice(i+1).trim();if(k){try{out[k]=decodeURIComponent(v)}catch{out[k]=v}}} return out;
}
function extractToken(event){return parseCookies(event)['__Host-ts_session']||null;}
function sessionCookie(token,maxAgeSeconds=SESSION_DAYS*24*60*60){return `__Host-ts_session=${encodeURIComponent(token)}; Max-Age=${Math.max(0,Math.floor(maxAgeSeconds))}; Path=/; Secure; HttpOnly; SameSite=Lax`;}
function clearSessionCookie(){return '__Host-ts_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax';}
module.exports={createSession,validateSession,deleteSession,deleteSessionByKey,deleteAllSessionsForUser,listSessionsForUser,revokeSessionById,revokeOtherSessions,getSessionPublicId,extractToken,sessionMeta,sessionCookie,clearSessionCookie,sessionKey};
