const webpush = require('web-push');
const crypto = require('crypto');

const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:example@example.com';

// Sends an urgent "check your session" push to a banned user and tracks
// delivery via the shared push-ack system (see push-ack.js). Best-effort
// only - the regular 60s session poll is still the guaranteed fallback if
// the push never arrives (permissions revoked, no network, browser closed).
async function sendBanPush(s, userId) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return { sent: 0, reason: 'no-vapid' };
  const subs = (await s.get(`subscriptions:${userId}`, { type: 'json' }).catch(() => null)) || [];
  if (!Array.isArray(subs) || !subs.length) return { sent: 0, reason: 'no-subscriptions' };

  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);

  let sent = 0;
  const results = [];
  for (const sub of subs) {
    const ackKey = `ban-check:${userId}:${crypto.randomBytes(12).toString('hex')}`;
    await s.setJSON(ackKey, { userId, sentAt: Date.now(), acked: false }).catch(() => {});
    try {
      await webpush.sendNotification(sub, JSON.stringify({
        type: 'ban-check',
        ackKey,
        title: '🔒 Оновлення акаунта',
        body: 'Статус вашого акаунта змінився.'
      }));
      sent++;
      results.push({ ackKey, ok: true });
    } catch (err) {
      results.push({ ackKey, ok: false, error: err && err.statusCode });
    }
  }
  return { sent, results };
}

module.exports = { sendBanPush };
