const webpush = require('web-push');
const { getStore } = require('@netlify/blobs');

const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:example@example.com';
const CRON_SECRET = process.env.CRON_SECRET; // optional shared secret

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);

function kyivParts() {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Europe/Kyiv',
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const parts = {};
  fmt.formatToParts(new Date()).forEach(p => { parts[p.type] = p.value; });
  const weekdayMap = { Sun: 6, Mon: 0, Tue: 1, Wed: 2, Thu: 3, Fri: 4, Sat: 5 };
  const dayIdx = weekdayMap[parts.weekday];
  const hour = parseInt(parts.hour, 10) % 24;
  const minute = parseInt(parts.minute, 10);
  const dateKey = `${parts.year}-${parts.month}-${parts.day}`;
  return { dayIdx, minutes: hour * 60 + minute, dateKey };
}

exports.handler = async (event) => {
  if (CRON_SECRET) {
    const provided = event.queryStringParameters?.secret;
    if (provided !== CRON_SECRET) {
      return { statusCode: 401, body: 'Unauthorized' };
    }
  }

  if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
    return { statusCode: 500, body: 'VAPID keys not configured' };
  }

  try {
    const store = getStore('ts-app');
    const data = await store.get('schedule-data', { type: 'json' });
    const subscriptions = (await store.get('subscriptions', { type: 'json' })) || [];

    if (!data || !subscriptions.length) {
      return { statusCode: 200, body: JSON.stringify({ ok: true, skipped: 'no data or no subscriptions' }) };
    }

    const { dayIdx, minutes: curMins, dateKey } = kyivParts();
    const slots = data.schedule[dayIdx] || data.schedule[String(dayIdx)] || [];

    let firedLog = (await store.get('fired-log', { type: 'json' })) || { dateKey: '', fired: [] };
    if (firedLog.dateKey !== dateKey) firedLog = { dateKey, fired: [] };

    const toSend = [];
    for (const sl of slots) {
      const [h, m] = sl.time.split(':').map(Number);
      const slotMins = h * 60 + m;
      const diff = slotMins - curMins;
      const subj = (data.subjects || []).find(s => s.id === sl.subjId) || { name: 'Пара' };

      if (data.notif10 && diff === 10) {
        const key = `${sl.time}_10`;
        if (!firedLog.fired.includes(key)) {
          firedLog.fired.push(key);
          toSend.push({
            title: '⏰ ' + subj.name,
            body: `За 10 хвилин · Початок о ${sl.time}${subj.teacher ? ' · ' + subj.teacher : ''}`
          });
        }
      }
      if (data.notif5 && diff === 5) {
        const key = `${sl.time}_5`;
        if (!firedLog.fired.includes(key)) {
          firedLog.fired.push(key);
          toSend.push({
            title: '📚 ' + subj.name,
            body: `За 5 хвилин · Готуйся!${subj.teacher ? ' · ' + subj.teacher : ''}`
          });
        }
      }
    }

    if (toSend.length) {
      await store.setJSON('fired-log', firedLog);

      const stillValid = [];
      for (const sub of subscriptions) {
        let ok = true;
        for (const msg of toSend) {
          try {
            await webpush.sendNotification(sub, JSON.stringify(msg));
          } catch (err) {
            if (err.statusCode === 404 || err.statusCode === 410) {
              ok = false;
            }
          }
        }
        if (ok) stillValid.push(sub);
      }
      if (stillValid.length !== subscriptions.length) {
        await store.setJSON('subscriptions', stillValid);
      }
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, sent: toSend.length, dayIdx, curMins })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
