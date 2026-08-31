const crypto = require('crypto');
const { store, atomicUpdateJSON } = require('./store');
const PRIORITY = { critical: 0, high: 1, normal: 2 };
const MAX_QUEUE_ITEMS = 1000;
function safe(s) { return String(s ?? '').slice(0, 5000); }
function dedupeHash(key) { return crypto.createHash('sha256').update(String(key)).digest('hex'); }

async function enqueueEmail({ to, subject, html, priority = 'normal', dedupeKey = '' }) {
  const s = store();
  const normalized = safe(dedupeKey);
  if (normalized) {
    const claim = await s.set(`email-dedupe:${dedupeHash(normalized)}`, JSON.stringify({ at: Date.now() }), { onlyIfNew: true });
    if (!claim.modified) return { queued: false, deduped: true };
  }

  try {
    await atomicUpdateJSON('email-queue-meta', { count: 0 }, current => {
      const count = Number(current.count || 0);
      if (count >= MAX_QUEUE_ITEMS) {
        const err = new Error('EMAIL_QUEUE_FULL');
        err.code = 'EMAIL_QUEUE_FULL';
        throw err;
      }
      return { count: count + 1 };
    });

    const id = crypto.randomUUID();
    const item = {
      id,
      to: safe(to),
      subject: safe(subject),
      html: safe(html),
      priority: Object.prototype.hasOwnProperty.call(PRIORITY, priority) ? priority : 'normal',
      dedupeKey: normalized,
      createdAt: Date.now(),
      status: 'queued',
      attempts: 0,
      nextAt: Date.now()
    };
    const result = await s.setJSON(`email-item:${id}`, item, { onlyIfNew: true });
    if (!result.modified) throw new Error('EMAIL_QUEUE_WRITE_FAILED');
    return { queued: true, id };
  } catch (err) {
    await atomicUpdateJSON('email-queue-meta', { count: 0 }, current => ({ count: Math.max(0, Number(current.count || 0) - 1) })).catch(() => {});
    if (normalized) await s.delete(`email-dedupe:${dedupeHash(normalized)}`).catch(() => {});
    throw err;
  }
}

async function listItems() {
  const s = store();
  const { blobs } = await s.list({ prefix: 'email-item:' });
  const items = [];
  for (const blob of blobs) {
    const current = await s.getWithMetadata(blob.key, { type: 'json', consistency: 'strong' }).catch(() => ({ data: null, etag: null }));
    if (current.data) items.push({ ...current.data, _etag: current.etag });
  }
  return items;
}

async function queueStats() {
  const items = await listItems();
  items.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
  return {
    queued: items.filter(x => x.status === 'queued').length,
    processing: items.filter(x => x.status === 'processing').length,
    failed: items.filter(x => x.status === 'failed').length,
    sent: items.filter(x => x.status === 'sent').length,
    items: items.slice(0, 20).map(x => ({ id: x.id, priority: x.priority, status: x.status, attempts: x.attempts, createdAt: x.createdAt, nextAt: x.nextAt }))
  };
}

async function claimItem(s, item, now) {
  const claimKey = `email-claim:${item.id}`;
  const claim = await s.set(claimKey, JSON.stringify({ at: now }), { onlyIfNew: true });
  if (!claim.modified) return false;
  const updated = { ...item };
  delete updated._etag;
  updated.status = 'processing';
  updated.processingAt = now;
  const result = await s.setJSON(`email-item:${item.id}`, updated, { onlyIfMatch: item._etag });
  if (!result.modified) {
    await s.delete(claimKey).catch(() => {});
    return false;
  }
  return true;
}

async function processEmailQueue(limit = 5) {
  const s = store();
  const items = await listItems();
  const now = Date.now();
  const max = Math.max(1, Math.min(20, Number(limit) || 5));
  const candidates = items
    .filter(x => (x.status === 'queued' && Number(x.nextAt || 0) <= now) || (x.status === 'processing' && now - Number(x.processingAt || 0) > 10 * 60 * 1000))
    .sort((a, b) => (PRIORITY[a.priority] ?? 2) - (PRIORITY[b.priority] ?? 2) || Number(a.createdAt || 0) - Number(b.createdAt || 0))
    .slice(0, max);

  const { sendRawMail } = require('./mailer');
  let sent = 0, failed = 0;
  for (const candidate of candidates) {
    const fresh = await s.getWithMetadata(`email-item:${candidate.id}`, { type: 'json', consistency: 'strong' });
    if (!fresh.data) continue;
    const item = { ...fresh.data, _etag: fresh.etag };
    if (item.status === 'processing' && now - Number(item.processingAt || 0) <= 10 * 60 * 1000) continue;
    if (item.status === 'processing') await s.delete(`email-claim:${item.id}`).catch(() => {});
    if (!(await claimItem(s, item, now))) continue;

    try {
      await sendRawMail(item.to, item.subject, item.html, item.priority);
      const after = await s.getWithMetadata(`email-item:${item.id}`, { type: 'json', consistency: 'strong' });
      if (after.data) {
        const next = { ...after.data, status: 'sent', sentAt: Date.now() };
        delete next.processingAt;
        delete next._etag;
        await s.setJSON(`email-item:${item.id}`, next, { onlyIfMatch: after.etag }).catch(() => {});
      }
      sent++;
    } catch (e) {
      const after = await s.getWithMetadata(`email-item:${item.id}`, { type: 'json', consistency: 'strong' });
      if (after.data) {
        const attempts = Number(after.data.attempts || 0) + 1;
        const next = attempts >= 5
          ? { ...after.data, attempts, status: 'failed', failedAt: Date.now(), error: String(e).slice(0, 300) }
          : { ...after.data, attempts, status: 'queued', nextAt: Date.now() + Math.min(60 * 60 * 1000, Math.pow(2, attempts) * 60 * 1000) };
        delete next.processingAt;
        delete next._etag;
        await s.setJSON(`email-item:${item.id}`, next, { onlyIfMatch: after.etag }).catch(() => {});
      }
      failed++;
    } finally {
      await s.delete(`email-claim:${item.id}`).catch(() => {});
    }
  }

  const afterAll = await listItems();
  let removed = 0;
  for (const item of afterAll) {
    const expiredSent = item.status === 'sent' && Date.now() - Number(item.sentAt || 0) > 24 * 60 * 60 * 1000;
    const expiredFailed = item.status === 'failed' && Date.now() - Number(item.failedAt || 0) > 7 * 24 * 60 * 60 * 1000;
    if (expiredSent || expiredFailed) {
      const cleanupClaim = await s.set(`email-cleanup-claim:${item.id}`, JSON.stringify({ at: Date.now() }), { onlyIfNew: true }).catch(() => ({ modified:false }));
      if (!cleanupClaim.modified) continue;
      await s.delete(`email-item:${item.id}`).catch(() => {});
      if (item.dedupeKey) await s.delete(`email-dedupe:${dedupeHash(item.dedupeKey)}`).catch(() => {});
      removed++;
    }
  }
  if (removed) await atomicUpdateJSON('email-queue-meta', { count: 0 }, current => ({ count: Math.max(0, Number(current.count || 0) - removed) })).catch(() => {});
  return { sent, failed, queued: afterAll.filter(x => x.status === 'queued').length };
}

module.exports = { enqueueEmail, queueStats, processEmailQueue };
