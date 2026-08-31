const crypto = require('crypto');
const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, rateLimit, isSameOriginRequest } = require('./lib/security');

const MAX_FILE = 4 * 1024 * 1024;
const MAX_TOTAL = 1024 * 1024 * 1024;
const MAX_FILES = 100;
const ALLOWED = new Set([
  'application/pdf','text/plain','image/jpeg','image/png','image/webp',
  'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/zip'
]);

function safeName(n) {
  return String(n || 'file').replace(/[\\/\0<>:"|?*\x00-\x1f]/g, '_').slice(0, 120) || 'file';
}

function hasMagic(bytes, mime) {
  if (mime === 'image/png') return bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
  if (mime === 'image/jpeg') return bytes.length >= 3 && bytes.subarray(0, 3).equals(Buffer.from([255,216,255]));
  if (mime === 'image/webp') return bytes.length >= 12 && bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP';
  if (mime === 'application/pdf') return bytes.subarray(0, 5).toString('ascii') === '%PDF-';
  if (mime === 'application/zip' || /openxmlformats/.test(mime)) return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;
  if (/^application\/ms(?:word|excel|powerpoint)$/.test(mime)) return bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1]));
  if (mime === 'text/plain') return !bytes.subarray(0, 1024).includes(0);
  return false;
}

exports.handler = async event => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return { statusCode: 403, body: JSON.stringify({ error: 'Недозволене походження запиту' }) };
  try {
    const s = store();
    const ban = await enforceIpBan(s, event);
    if (ban) return { statusCode: 403, body: JSON.stringify({ error: 'IP заблоковано' }) };
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess) return { statusCode: 401, body: JSON.stringify({ error: 'Сесія недійсна' }) };
    const rl = await rateLimit(s, `file-upload:${sess.userId}`, 20, 60 * 60 * 1000);
    if (!rl.allowed) return { statusCode: 429, body: JSON.stringify({ error: 'Забагато завантажень. Спробуй пізніше.' }) };

    const noteId = String(event.queryStringParameters?.noteId || '');
    if (!/^[A-Za-z0-9_-]{1,120}$/.test(noteId)) return { statusCode: 400, body: JSON.stringify({ error: 'Некоректний ID нотатки' }) };
    const data = await s.get(`schedule-data:${sess.userId}`, { type: 'json', consistency: 'strong' });
    const note = (data?.notes || []).find(n => n.id === noteId);
    if (!note) return { statusCode: 404, body: JSON.stringify({ error: 'Нотатку не знайдено' }) };

    let rawName = event.headers?.['x-file-name'] || event.headers?.['X-File-Name'] || 'file';
    try { rawName = decodeURIComponent(rawName); } catch {}
    const name = safeName(rawName);
    const mime = String(event.headers?.['content-type'] || event.headers?.['Content-Type'] || '').split(';')[0].toLowerCase();
    const bytes = Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8');
    if (!bytes.length || bytes.length > MAX_FILE) return { statusCode: 413, body: JSON.stringify({ error: 'Файл завеликий. Максимум 4 МБ.' }) };
    if (!ALLOWED.has(mime)) return { statusCode: 415, body: JSON.stringify({ error: 'Тип файлу не дозволений.' }) };
    if (!hasMagic(bytes, mime)) return { statusCode: 415, body: JSON.stringify({ error: 'Вміст файлу не відповідає заявленому типу.' }) };

    const id = crypto.randomUUID();
    const blobKey = `file:${sess.userId}:${id}`;
    const meta = { id, noteId, name, mime, size: bytes.length, createdAt: Date.now(), blobKey };
    await s.set(blobKey, bytes, { metadata: { userId: sess.userId, noteId, name, mime, size: bytes.length, createdAt: meta.createdAt } });

    try {
      const metaResult = await atomicUpdateJSON(`file-meta:${sess.userId}`, [], current => {
        const list = Array.isArray(current) ? current : [];
        const total = list.reduce((sum, x) => sum + Number(x.size || 0), 0);
        if (list.length >= MAX_FILES || total + bytes.length > MAX_TOTAL) {
          const err = new Error('STORAGE_LIMIT');
          err.code = 'STORAGE_LIMIT';
          throw err;
        }
        return [...list, meta];
      });

      await atomicUpdateJSON(`schedule-data:${sess.userId}`, data, current => {
        const next = current || data;
        const notes = Array.isArray(next.notes) ? next.notes : [];
        const idx = notes.findIndex(n => n.id === noteId);
        if (idx < 0) { const err = new Error('NOTE_GONE'); err.code = 'NOTE_GONE'; throw err; }
        const updated = { ...notes[idx], attachments: [...(notes[idx].attachments || []), { id, name, mime, size: bytes.length }] };
        const nextNotes = [...notes];
        nextNotes[idx] = updated;
        return { ...next, notes: nextNotes, updatedAt: Date.now() };
      });

      return { statusCode: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify({ ok: true, file: { id, name, mime, size: bytes.length } }) };
    } catch (err) {
      await s.delete(blobKey).catch(() => {});
      if (err.code === 'STORAGE_LIMIT') return { statusCode: 413, body: JSON.stringify({ error: 'Ліміт сховища користувача вичерпано.' }) };
      return { statusCode: 409, body: JSON.stringify({ error: 'Нотатку або файл одночасно змінили. Спробуй ще раз.' }) };
    }
  } catch {
    return { statusCode: 500, body: JSON.stringify({ error: 'Не вдалося завантажити файл' }) };
  }
};
