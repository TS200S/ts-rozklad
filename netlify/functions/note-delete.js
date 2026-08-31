const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { rateLimit, isSameOriginRequest } = require('./lib/security');
const { recordActivity } = require('./lib/activity');

exports.handler = async event => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return { statusCode: 403, body: JSON.stringify({ error: 'Недозволене походження запиту' }) };
  try {
    const s = store();
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess || sess.banned) return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна' }) };
    const rl = await rateLimit(s, `note-delete:${sess.userId}`, 60, 60 * 60 * 1000);
    if (!rl.allowed) return { statusCode: 429, body: JSON.stringify({ error: 'Забагато операцій. Спробуй пізніше.' }) };
    const body = JSON.parse(event.body || '{}');
    const noteId = String(body.noteId || '');
    if (!/^[A-Za-z0-9_-]{1,120}$/.test(noteId)) return { statusCode: 400, body: JSON.stringify({ error: 'Некоректний ID нотатки' }) };

    const scheduleKey = `schedule-data:${sess.userId}`;
    const data = await s.get(scheduleKey, { type: 'json', consistency: 'strong' });
    if (!data || !Array.isArray(data.notes)) return { statusCode: 404, body: JSON.stringify({ error: 'Нотатку не знайдено' }) };
    const note = data.notes.find(n => n && n.id === noteId);
    if (!note) return { statusCode: 404, body: JSON.stringify({ error: 'Нотатку не знайдено' }) };

    const attachments = Array.isArray(note.attachments) ? note.attachments : [];
    const ids = new Set(attachments.map(a => a && a.id).filter(Boolean));
    await atomicUpdateJSON(scheduleKey, data, current => {
      const notes = Array.isArray(current?.notes) ? current.notes : [];
      if (!notes.some(n => n && n.id === noteId)) {
        const err = new Error('NOTE_GONE'); err.code = 'NOTE_GONE'; throw err;
      }
      return { ...(current || data), notes: notes.filter(n => n.id !== noteId), updatedAt: Date.now() };
    });

    if (ids.size) {
      const beforeMeta = (await s.get(`file-meta:${sess.userId}`, { type: 'json' }).catch(() => null)) || [];
      const removable = Array.isArray(beforeMeta) ? beforeMeta.filter(meta => ids.has(meta?.id)) : [];
      await atomicUpdateJSON(`file-meta:${sess.userId}`, [], list => {
        const all = Array.isArray(list) ? list : [];
        return all.filter(meta => !ids.has(meta.id));
      });
      // Physical deletion happens after references are removed. If a blob delete
      // temporarily fails, it is now an orphan and the protected admin cleanup
      // can remove it without leaving a live attachment reference behind.
      for (const meta of removable) if (meta?.blobKey) await s.delete(meta.blobKey).catch(() => {});
    }

    await recordActivity(s, sess.userId, 'note-deleted', { noteId, attachments: attachments.length });
    return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ ok: true, deletedFiles: attachments.length }) };
  } catch (err) {
    if (err.code === 'NOTE_GONE') return { statusCode: 404, body: JSON.stringify({ error: 'Нотатку вже видалено' }) };
    return { statusCode: 500, body: JSON.stringify({ error: 'Не вдалося видалити нотатку' }) };
  }
};
