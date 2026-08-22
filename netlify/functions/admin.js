const { store } = require('./lib/store');
const { validateSession, extractToken, deleteAllSessionsForUser } = require('./lib/session');

async function requireAdmin(event, s) {
  const token = extractToken(event);
  const sess = await validateSession(s, token);
  if (!sess) return null;
  const adminUsername = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
  if (!adminUsername || sess.username !== adminUsername) return null;
  return sess;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  try {
    const s = store();
    const sess = await requireAdmin(event, s);
    if (!sess) {
      return { statusCode: 403, body: JSON.stringify({ error: 'Немає доступу' }) };
    }

    const body = JSON.parse(event.body || '{}');
    const { action, username } = body;

    if (action === 'list-users') {
      const { blobs } = await s.list({ prefix: 'user:' });
      const users = [];
      for (const b of blobs) {
        const u = await s.get(b.key, { type: 'json' }).catch(() => null);
        if (!u) continue;
        const schedData = await s.get(`schedule-data:${u.userId}`, { type: 'json' }).catch(() => null);
        const subs = (await s.get(`subscriptions:${u.userId}`, { type: 'json' }).catch(() => null)) || [];
        users.push({
          username: u.username,
          email: u.email || null,
          createdAt: u.createdAt || null,
          lastActive: u.lastActive || null,
          banned: !!u.banned,
          scheduleUpdatedAt: schedData?.updatedAt || null,
          subjectsCount: schedData?.subjects?.length || 0,
          notesCount: schedData?.notes?.length || 0,
          pushSubscriptions: subs.length
        });
      }
      users.sort((a, b2) => (b2.createdAt || 0) - (a.createdAt || 0));
      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true, users }) };
    }

    if (action === 'ban-user' || action === 'unban-user') {
      if (!username) return { statusCode: 400, body: JSON.stringify({ error: 'Немає username' }) };
      const uname = String(username).trim().toLowerCase();
      if (uname === sess.username) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Не можна забанити самого себе' }) };
      }
      const user = await s.get(`user:${uname}`, { type: 'json' }).catch(() => null);
      if (!user) return { statusCode: 404, body: JSON.stringify({ error: 'Користувача не знайдено' }) };
      user.banned = action === 'ban-user';
      await s.setJSON(`user:${uname}`, user);
      if (user.banned) await deleteAllSessionsForUser(s, user.userId);
      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true }) };
    }

    if (action === 'delete-user') {
      if (!username) return { statusCode: 400, body: JSON.stringify({ error: 'Немає username' }) };
      const uname = String(username).trim().toLowerCase();
      if (uname === sess.username) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Не можна видалити самого себе' }) };
      }
      const user = await s.get(`user:${uname}`, { type: 'json' }).catch(() => null);
      if (!user) return { statusCode: 404, body: JSON.stringify({ error: 'Користувача не знайдено' }) };

      await deleteAllSessionsForUser(s, user.userId);
      await s.delete(`user:${uname}`).catch(() => {});
      if (user.email) await s.delete(`email:${user.email}`).catch(() => {});
      await s.delete(`schedule-data:${user.userId}`).catch(() => {});
      await s.delete(`subscriptions:${user.userId}`).catch(() => {});
      await s.delete(`fired-log:${user.userId}`).catch(() => {});

      return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true }) };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'Невідома дія' }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
