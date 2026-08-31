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
    const rl = await rateLimit(s, `file-delete:${sess.userId}`, 30, 60 * 60 * 1000);
    if (!rl.allowed) return { statusCode: 429, body: JSON.stringify({ error: 'Забагато операцій з файлами. Спробуй пізніше.' }) };
    const { id } = JSON.parse(event.body || '{}');
    const fileId = String(id || '');
    if (!/^[0-9a-f-]{20,80}$/i.test(fileId)) return { statusCode: 400, body: JSON.stringify({ error: 'Некоректний файл' }) };

    const claimKey = `file-delete-claim:${sess.userId}:${fileId}`;
    const claim = await s.set(claimKey, JSON.stringify({ at: Date.now() }), { onlyIfNew: true });
    if (!claim.modified) return { statusCode: 409, body: JSON.stringify({ error: 'Файл уже обробляється' }) };

    try {
      const metaResult = await s.getWithMetadata(`file-meta:${sess.userId}`, { type: 'json', consistency: 'strong' });
      const all = Array.isArray(metaResult.data) ? metaResult.data : [];
      const meta = all.find(x => x.id === fileId);
      if (!meta) return { statusCode: 404, body: JSON.stringify({ error: 'Файл не знайдено' }) };
      const d = await s.get(`schedule-data:${sess.userId}`, { type: 'json', consistency: 'strong' });
      if (!(d?.notes || []).some(n => (n.attachments || []).some(a => a.id === meta.id))) return { statusCode: 403, body: JSON.stringify({ error: 'Немає доступу' }) };

      // Remove references first. If physical blob deletion fails afterwards,
      // the orphan-cleanup job can safely remove the unreferenced blob.
      await atomicUpdateJSON(`file-meta:${sess.userId}`, all, current => (Array.isArray(current) ? current : []).filter(x => x.id !== meta.id));
      await atomicUpdateJSON(`schedule-data:${sess.userId}`, d, current => {
        const next = current || d;
        const notes = Array.isArray(next.notes) ? next.notes : [];
        const updatedNotes = notes.map(n => ({ ...n, attachments: (n.attachments || []).filter(a => a.id !== meta.id) }));
        return { ...next, notes: updatedNotes, updatedAt: Date.now() };
      });
      await s.delete(meta.blobKey).catch(() => {});
      await recordActivity(s, sess.userId, 'note-file-deleted', { fileId: meta.id, noteId: meta.noteId, name: meta.name, size: meta.size });
      return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ ok: true }) };
    } finally {
      await s.delete(claimKey).catch(() => {});
    }
  } catch {
    return { statusCode: 500, body: JSON.stringify({ error: 'Не вдалося видалити файл' }) };
  }
};
