const crypto = require('crypto');
const { store, atomicUpdateJSON } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, rateLimit, isSameOriginRequest } = require('./lib/security');

// Netlify Functions buffer request bodies and binary requests are base64 encoded.
// Keep each HTTP chunk comfortably below the platform payload limit.
const CHUNK_SIZE = 3 * 1024 * 1024;
const MAX_FILE = 25 * 1024 * 1024;
const MAX_TOTAL = 1024 * 1024 * 1024;
const MAX_FILES = 100;
const MAX_CHUNKS = Math.ceil(MAX_FILE / CHUNK_SIZE);
const UPLOAD_TTL = 2 * 60 * 60 * 1000;
const ALLOWED = new Set([
  'application/pdf','text/plain','image/jpeg','image/png','image/webp',
  'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/zip'
]);

function json(statusCode, body) {
  return { statusCode, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) };
}
function safeName(n) { return String(n || 'file').replace(/[\\/\0<>:"|?*\x00-\x1f]/g, '_').slice(0, 120) || 'file'; }
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
function bodyBytes(event) {
  if (!event.body) return Buffer.alloc(0);
  return event.isBase64Encoded ? Buffer.from(event.body, 'base64') : Buffer.from(event.body, 'utf8');
}
function mimeFromEvent(event) { return String(event.headers?.['content-type'] || event.headers?.['Content-Type'] || '').split(';')[0].toLowerCase(); }
function fileNameFromEvent(event) {
  let raw = event.headers?.['x-file-name'] || event.headers?.['X-File-Name'] || 'file';
  try { raw = decodeURIComponent(raw); } catch {}
  return safeName(raw);
}
function validUploadId(id) { return /^[0-9a-f-]{20,80}$/i.test(String(id || '')); }

async function getSession(event) {
  const s = store();
  const ban = await enforceIpBan(s, event);
  if (ban) return { error: json(403, { error: 'IP заблоковано' }) };
  const sess = await validateSession(s, extractToken(event), event);
  if (!sess || sess.banned) return { error: json(401, { error: 'Сесія недійсна' }) };
  return { s, sess };
}

async function initUpload(s, sess, event) {
  let input;
  try { input = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Некоректні дані завантаження' }); }
  const noteId = String(input.noteId || '');
  const size = Number(input.size);
  const mime = String(input.mime || '').split(';')[0].toLowerCase();
  const name = safeName(input.name);
  if (!/^[A-Za-z0-9_-]{1,120}$/.test(noteId)) return json(400, { error: 'Некоректний ID нотатки' });
  if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_FILE) return json(413, { error: 'Файл завеликий. Максимум 25 МБ.' });
  if (!ALLOWED.has(mime)) return json(415, { error: 'Тип файлу не дозволений.' });

  const data = await s.get(`schedule-data:${sess.userId}`, { type: 'json', consistency: 'strong' });
  const note = (data?.notes || []).find(n => n && n.id === noteId);
  if (!note) return json(404, { error: 'Нотатку не знайдено' });
  const attachmentCount = Array.isArray(note.attachments) ? note.attachments.length : 0;
  if (attachmentCount >= 20) return json(413, { error: 'Для однієї нотатки можна прикріпити максимум 20 файлів.' });

  const allMeta = (await s.get(`file-meta:${sess.userId}`, { type: 'json', consistency: 'strong' }).catch(() => null)) || [];
  const total = Array.isArray(allMeta) ? allMeta.reduce((sum, x) => sum + Number(x?.size || 0), 0) : 0;
  if (allMeta.length >= MAX_FILES || total + size > MAX_TOTAL) return json(413, { error: 'Ліміт сховища користувача вичерпано.' });

  const uploadId = crypto.randomUUID();
  const chunks = Math.ceil(size / CHUNK_SIZE);
  const state = { uploadId, userId: sess.userId, noteId, name, mime, size, chunks, received: [], createdAt: Date.now(), status: 'uploading' };
  await s.setJSON(`file-upload:${sess.userId}:${uploadId}`, state, { onlyIfNew: true });
  return json(200, { ok: true, uploadId, chunkSize: CHUNK_SIZE, chunks, maxFileSize: MAX_FILE });
}

async function receiveChunk(s, sess, event) {
  const q = event.queryStringParameters || {};
  const uploadId = String(q.uploadId || '');
  const index = Number(q.index);
  if (!validUploadId(uploadId) || !Number.isInteger(index) || index < 0 || index >= MAX_CHUNKS) return json(400, { error: 'Некоректний chunk' });

  const key = `file-upload:${sess.userId}:${uploadId}`;
  const state = await s.get(key, { type: 'json', consistency: 'strong' });
  if (!state || state.status !== 'uploading') return json(404, { error: 'Сесію завантаження не знайдено або вона завершена.' });
  if (state.createdAt + UPLOAD_TTL < Date.now()) return json(410, { error: 'Час завантаження вичерпано. Почни знову.' });

  const bytes = bodyBytes(event);
  const expectedSize = index === state.chunks - 1 ? state.size - (CHUNK_SIZE * (state.chunks - 1)) : CHUNK_SIZE;
  if (!bytes.length || bytes.length !== expectedSize || bytes.length > CHUNK_SIZE) return json(413, { error: 'Некоректний розмір частини файлу.' });

  const chunkKey = `file-upload-chunk:${sess.userId}:${uploadId}:${index}`;
  const written = await s.set(chunkKey, bytes, { onlyIfNew: true });
  if (!written.modified) return json(200, { ok: true, alreadyReceived: true, index });

  await atomicUpdateJSON(key, state, current => {
    if (!current || current.status !== 'uploading') return current;
    const received = Array.isArray(current.received) ? current.received : [];
    if (received.includes(index)) return current;
    return { ...current, received: [...received, index].sort((a, b) => a - b), updatedAt: Date.now() };
  }, { store: s });
  return json(200, { ok: true, index });
}

async function finalizeUpload(s, sess, event) {
  let input;
  try { input = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Некоректні дані завершення завантаження' }); }
  const uploadId = String(input.uploadId || '');
  if (!validUploadId(uploadId)) return json(400, { error: 'Некоректний uploadId' });
  const key = `file-upload:${sess.userId}:${uploadId}`;
  const state = await s.get(key, { type: 'json', consistency: 'strong' });
  if (!state) return json(404, { error: 'Сесію завантаження не знайдено' });
  if (state.status === 'completed' && state.file) return json(200, { ok: true, file: state.file });
  if (state.status !== 'uploading' || state.createdAt + UPLOAD_TTL < Date.now()) return json(410, { error: 'Завантаження прострочене.' });

  const received = new Set(Array.isArray(state.received) ? state.received : []);
  if (received.size !== state.chunks || [...Array(state.chunks).keys()].some(i => !received.has(i))) return json(409, { error: 'Не всі частини файлу завантажені.' });

  const claimKey = `file-upload-finalize:${sess.userId}:${uploadId}`;
  const claim = await s.set(claimKey, JSON.stringify({ at: Date.now() }), { onlyIfNew: true });
  if (!claim.modified) return json(409, { error: 'Файл уже обробляється.' });

  try {
    const parts = [];
    for (let i = 0; i < state.chunks; i++) {
      const part = await s.get(`file-upload-chunk:${sess.userId}:${uploadId}:${i}`, { type: 'blob', consistency: 'strong' });
      if (!part) return json(409, { error: `Відсутня частина ${i + 1}.` });
      parts.push(Buffer.from(await part.arrayBuffer()));
    }
    const bytes = Buffer.concat(parts, state.size);
    if (bytes.length !== state.size || !hasMagic(bytes, state.mime)) return json(415, { error: 'Вміст файлу не відповідає заявленому типу.' });

    const id = crypto.randomUUID();
    const blobKey = `file:${sess.userId}:${id}`;
    const meta = { id, noteId: state.noteId, name: state.name, mime: state.mime, size: bytes.length, createdAt: Date.now(), blobKey };
    await s.set(blobKey, bytes, { metadata: { userId: sess.userId, noteId: state.noteId, name: state.name, mime: state.mime, size: bytes.length, createdAt: meta.createdAt } });

    let metaAdded = false;
    try {
      await atomicUpdateJSON(`file-meta:${sess.userId}`, [], current => {
        const list = Array.isArray(current) ? current : [];
        const total = list.reduce((sum, x) => sum + Number(x?.size || 0), 0);
        if (list.length >= MAX_FILES || total + bytes.length > MAX_TOTAL) { const e = new Error('STORAGE_LIMIT'); e.code = 'STORAGE_LIMIT'; throw e; }
        return [...list, meta];
      }, { store: s });
      metaAdded = true;

      await atomicUpdateJSON(`schedule-data:${sess.userId}`, null, current => {
        const next = current || {};
        const notes = Array.isArray(next.notes) ? next.notes : [];
        const idx = notes.findIndex(n => n && n.id === state.noteId);
        if (idx < 0) { const e = new Error('NOTE_GONE'); e.code = 'NOTE_GONE'; throw e; }
        const currentAttachments = Array.isArray(notes[idx].attachments) ? notes[idx].attachments : [];
        if (currentAttachments.length >= 20) { const e = new Error('NOTE_FILE_LIMIT'); e.code = 'NOTE_FILE_LIMIT'; throw e; }
        const nextNotes = [...notes];
        nextNotes[idx] = { ...notes[idx], attachments: [...currentAttachments, { id, name: state.name, mime: state.mime, size: bytes.length }] };
        return { ...next, notes: nextNotes, updatedAt: Date.now() };
      }, { store: s });
    } catch (err) {
      await s.delete(blobKey).catch(() => {});
      if (metaAdded) await atomicUpdateJSON(`file-meta:${sess.userId}`, [], current => (Array.isArray(current) ? current : []).filter(x => x.id !== id), { store: s }).catch(() => {});
      if (err.code === 'STORAGE_LIMIT') return json(413, { error: 'Ліміт сховища користувача вичерпано.' });
      if (err.code === 'NOTE_FILE_LIMIT') return json(413, { error: 'Для однієї нотатки можна прикріпити максимум 20 файлів.' });
      if (err.code === 'NOTE_GONE') return json(404, { error: 'Нотатку вже видалено.' });
      return json(409, { error: 'Нотатку або файл одночасно змінили. Спробуй ще раз.' });
    }

    const file = { id, name: state.name, mime: state.mime, size: bytes.length };
    await s.setJSON(key, { ...state, status: 'completed', completedAt: Date.now(), file }, { onlyIfMatch: (await s.getWithMetadata(key, { type: 'json', consistency: 'strong' }))?.etag }).catch(() => {});
    for (let i = 0; i < state.chunks; i++) await s.delete(`file-upload-chunk:${sess.userId}:${uploadId}:${i}`).catch(() => {});
    return json(200, { ok: true, file });
  } finally {
    await s.delete(claimKey).catch(() => {});
  }
}

exports.handler = async event => {
  if (!['POST'].includes(event.httpMethod)) return { statusCode: 405, body: 'Method Not Allowed' };
  if (!isSameOriginRequest(event)) return json(403, { error: 'Недозволене походження запиту' });
  try {
    const auth = await getSession(event);
    if (auth.error) return auth.error;
    const { s, sess } = auth;
    const action = String(event.queryStringParameters?.action || 'direct');
    const rl = await rateLimit(s, `file-upload:${sess.userId}`, action === 'chunk' ? 120 : 30, 60 * 60 * 1000);
    if (!rl.allowed) return json(429, { error: 'Забагато операцій з файлами. Спробуй пізніше.' });

    if (action === 'init') return await initUpload(s, sess, event);
    if (action === 'chunk') return await receiveChunk(s, sess, event);
    if (action === 'finalize') return await finalizeUpload(s, sess, event);

    // Small files keep the old one-request path; larger files use chunks.
    const bytes = bodyBytes(event);
    if (bytes.length > 0 && bytes.length <= CHUNK_SIZE) {
      const fakeInit = { body: JSON.stringify({ noteId: event.queryStringParameters?.noteId, size: bytes.length, mime: mimeFromEvent(event), name: fileNameFromEvent(event) }) };
      const init = await initUpload(s, sess, fakeInit);
      const initData = JSON.parse(init.body);
      if (!initData.uploadId) return init;
      const chunkEvent = { ...event, queryStringParameters: { uploadId: initData.uploadId, index: '0' } };
      const chunkResult = await receiveChunk(s, sess, chunkEvent);
      if (chunkResult.statusCode !== 200) return chunkResult;
      return finalizeUpload(s, sess, { ...event, body: JSON.stringify({ uploadId: initData.uploadId }) });
    }
    return json(413, { error: 'Файл завеликий для прямого завантаження. Використовуй chunked upload.' });
  } catch (err) {
    console.error('[note-files-upload]', err?.code || err?.message || err);
    return json(500, { error: 'Не вдалося завантажити файл' });
  }
};

exports.constants = { CHUNK_SIZE, MAX_FILE, MAX_TOTAL, MAX_FILES, MAX_CHUNKS, UPLOAD_TTL };
