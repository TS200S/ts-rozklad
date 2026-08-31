const { getStore } = require('@netlify/blobs');

function store() {
  return getStore({
    name: 'ts-app',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });
}

/**
 * Optimistic-concurrency helper for Netlify Blobs.
 * Netlify Blobs is last-write-wins, so all read/modify/write operations on
 * shared JSON state must use ETags. The helper retries when another request
 * wins the race.
 */
async function atomicUpdateJSON(key, initialValue, updater, options = {}) {
  const s = options.store || store();
  const retries = Math.max(1, Math.min(12, Number(options.retries || 8)));
  for (let attempt = 0; attempt < retries; attempt++) {
    const current = await s.getWithMetadata(key, { type: 'json', consistency: 'strong' });
    const exists = current?.data !== null && current?.data !== undefined;
    const value = exists ? current.data : structuredClone(initialValue);
    const next = await updater(value, { exists, etag: current?.etag || null, attempt });
    if (next === undefined) return { modified: false, value };
    const result = exists
      ? await s.setJSON(key, next, { onlyIfMatch: current.etag })
      : await s.setJSON(key, next, { onlyIfNew: true });
    if (result.modified) return { modified: true, value: next };
  }
  const err = new Error(`ATOMIC_UPDATE_CONFLICT:${key}`);
  err.code = 'ATOMIC_UPDATE_CONFLICT';
  throw err;
}

module.exports = { store, atomicUpdateJSON };
