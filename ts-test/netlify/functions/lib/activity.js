const crypto = require('crypto');

const ACTIVITY_LIMIT = 1000;

async function recordActivity(s, userId, type, details = {}) {
  if (!userId) return;
  const key = `account-activity:${userId}`;
  const list = (await s.get(key, { type: 'json' }).catch(() => null)) || [];
  list.push({
    id: crypto.randomUUID(),
    at: Date.now(),
    type: String(type || 'unknown').slice(0, 80),
    details: sanitize(details)
  });
  await s.setJSON(key, list.slice(-ACTIVITY_LIMIT)).catch(() => {});
}

function sanitize(value) {
  if (!value || typeof value !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (/password|hash|salt|token|code|secret/i.test(k)) continue;
    if (typeof v === 'string') out[k] = v.slice(0, 1000);
    else if (typeof v === 'number' || typeof v === 'boolean' || v === null) out[k] = v;
    else if (Array.isArray(v)) out[k] = v.slice(0, 50).map(x => typeof x === 'string' ? x.slice(0, 300) : x);
    else if (typeof v === 'object') out[k] = sanitize(v);
  }
  return out;
}

async function listActivity(s, userId, limit = 500) {
  const list = (await s.get(`account-activity:${userId}`, { type: 'json' }).catch(() => null)) || [];
  return list.slice(-Math.min(Math.max(Number(limit) || 500, 1), 1000)).reverse();
}

module.exports = { recordActivity, listActivity };
