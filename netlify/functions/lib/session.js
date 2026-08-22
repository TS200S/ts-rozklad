const crypto = require('crypto');

const SESSION_DAYS = 90;

async function createSession(s, userId, username) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await s.setJSON(`session:${token}`, { userId, username, createdAt: now, expiresAt });

  // Track tokens per user so we can revoke all of them at once (password
  // reset, ban, account deletion) without having to scan every session key.
  const listKey = `user-sessions:${userId}`;
  const list = (await s.get(listKey, { type: 'json' })) || [];
  list.push(token);
  await s.setJSON(listKey, list);

  return { token, expiresAt };
}

async function validateSession(s, token) {
  if (!token) return null;
  let sess;
  try {
    sess = await s.get(`session:${token}`, { type: 'json' });
  } catch {
    return null;
  }
  if (!sess) return null;
  if (sess.expiresAt < Date.now()) {
    await s.delete(`session:${token}`).catch(() => {});
    return null;
  }
  return sess; // { userId, username, createdAt, expiresAt }
}

async function deleteSession(s, token) {
  if (!token) return;
  await s.delete(`session:${token}`).catch(() => {});
}

async function deleteAllSessionsForUser(s, userId) {
  const listKey = `user-sessions:${userId}`;
  const list = (await s.get(listKey, { type: 'json' })) || [];
  for (const token of list) {
    await s.delete(`session:${token}`).catch(() => {});
  }
  await s.delete(listKey).catch(() => {});
}

function extractToken(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}

module.exports = { createSession, validateSession, deleteSession, deleteAllSessionsForUser, extractToken };
