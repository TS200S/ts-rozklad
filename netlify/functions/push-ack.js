const { store } = require('./lib/store');

function json(statusCode, body) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

// Fire-and-forget receipt: the service worker calls this the instant ANY
// push arrives (ban-check, lesson reminder, note deadline), so the server
// knows the push actually reached the device. check-notifications.js uses
// this to decide whether to resend a reminder on its next run instead of
// assuming a "sent" push was actually seen.
const ALLOWED_PREFIXES = ['ban-check:', 'push-claim:'];

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };
  try {
    const body = JSON.parse(event.body || '{}');
    const ackKey = String(body.ackKey || '').trim();
    if (!ackKey || ackKey.length > 200 || !ALLOWED_PREFIXES.some(p => ackKey.startsWith(p))) {
      return json(400, { error: 'bad key' });
    }

    const s = store();
    const rec = await s.get(ackKey, { type: 'json' }).catch(() => null);
    if (rec) {
      rec.acked = true;
      rec.ackedAt = Date.now();
      await s.setJSON(ackKey, rec).catch(() => {});
    }
    return json(200, { ok: true });
  } catch (err) {
    return json(500, { error: 'Внутрішня помилка сервера' });
  }
};
