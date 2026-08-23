const webpush = require('web-push');
const { getStore } = require('@netlify/blobs');

function store() {
  return getStore({
    name: 'ts-app',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });
}

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

// Runs the full reminder check for a single user's data. Nothing here is
// ever shared across users - every key it touches is namespaced by userId.
async function processUser(s, userId, dayIdx, curMins, dateKey) {
  const data = await s.get(`schedule-data:${userId}`, { type: 'json' });
  const subscriptions = (await s.get(`subscriptions:${userId}`, { type: 'json' })) || [];

  if (!data || !subscriptions.length) return { sent: 0 };

  const slots = data.schedule[dayIdx] || data.schedule[String(dayIdx)] || [];

  let firedLog = (await s.get(`fired-log:${userId}`, { type: 'json' })) || { dateKey: '', fired: [] };
  if (firedLog.dateKey !== dateKey) firedLog = { dateKey, fired: [] };

  const toSend = [];
  for (const sl of slots) {
    const [h, m] = sl.time.split(':').map(Number);
    const slotMins = h * 60 + m;
    const diff = slotMins - curMins;
    const subj = (data.subjects || []).find(x => x.id === sl.subjId) || { name: 'Пара' };

    // Windows instead of exact-minute equality: cron-job.org occasionally
    // fires a minute or two late, and an exact "diff === 10" check would
    // silently skip that reminder forever if the tick landed on diff === 9.
    if (data.notif10 && diff <= 10 && diff >= 8) {
      const key = `${sl.time}_10`;
      if (!firedLog.fired.includes(key)) {
        firedLog.fired.push(key);
        toSend.push({ title: '⏰ ' + subj.name, body: `За 10 хвилин · Початок о ${sl.time}${subj.teacher ? ' · ' + subj.teacher : ''}` });
      }
    }
    if (data.notif5 && diff <= 5 && diff >= 3) {
      const key = `${sl.time}_5`;
      if (!firedLog.fired.includes(key)) {
        firedLog.fired.push(key);
        toSend.push({ title: '📚 ' + subj.name, body: `За 5 хвилин · Готуйся!${subj.teacher ? ' · ' + subj.teacher : ''}` });
      }
    }
  }

  if (Array.isArray(data.notes)) {
    const [ny, nmo, nd] = dateKey.split('-').map(Number);
    const nowWallTs = Date.UTC(ny, nmo - 1, nd, 0, 0) + curMins * 60000;

    for (const note of data.notes) {
      if (note.done || !note.deadline) continue;
      const [dPart, tPart] = note.deadline.split('T');
      const [dy, dmo, dd] = dPart.split('-').map(Number);
      const [dh, dmi] = (tPart || '23:59').split(':').map(Number);
      const deadlineWallTs = Date.UTC(dy, dmo - 1, dd, dh, dmi);
      const diffMin = Math.round((deadlineWallTs - nowWallTs) / 60000);
      const shortText = (note.text || 'Нотатка').slice(0, 60);

      // Same reasoning as above: a ±10-minute window (±5 for the 1h ping)
      // instead of an exact match, so a delayed or skipped cron tick doesn't
      // permanently swallow a deadline reminder.
      if (diffMin <= 1440 && diffMin > 1430) {
        const key = `note_${note.id}_24h`;
        if (!firedLog.fired.includes(key)) { firedLog.fired.push(key); toSend.push({ title: '🔔 Дедлайн завтра', body: shortText }); }
      } else if (diffMin <= 180 && diffMin > 170) {
        const key = `note_${note.id}_3h`;
        if (!firedLog.fired.includes(key)) { firedLog.fired.push(key); toSend.push({ title: '⏳ Дедлайн наближається — 3 години', body: shortText }); }
      } else if (diffMin <= 60 && diffMin > 50) {
        const key = `note_${note.id}_1h`;
        if (!firedLog.fired.includes(key)) { firedLog.fired.push(key); toSend.push({ title: '🚨 Залишилась 1 година! Роби швидше', body: shortText }); }
      } else if (diffMin <= 0) {
        const key = `note_${note.id}_overdue_${dateKey}`;
        if (!firedLog.fired.includes(key)) { firedLog.fired.push(key); toSend.push({ title: '⚠️ Прострочено!', body: shortText }); }
      }
    }
  }

  if (toSend.length) {
    await s.setJSON(`fired-log:${userId}`, firedLog);

    const stillValid = [];
    for (const sub of subscriptions) {
      let ok = true;
      for (const msg of toSend) {
        try {
          await webpush.sendNotification(sub, JSON.stringify(msg));
        } catch (err) {
          if (err.statusCode === 404 || err.statusCode === 410) ok = false;
        }
      }
      if (ok) stillValid.push(sub);
    }
    if (stillValid.length !== subscriptions.length) {
      await s.setJSON(`subscriptions:${userId}`, stillValid);
    }
  }

  return { sent: toSend.length };
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
    const s = store();
    const { dayIdx, minutes: curMins, dateKey } = kyivParts();

    const { blobs } = await s.list({ prefix: 'schedule-data:' });
    let totalSent = 0, users = 0;

    for (const blob of blobs) {
      const userId = blob.key.slice('schedule-data:'.length);
      if (!userId) continue;
      const result = await processUser(s, userId, dayIdx, curMins, dateKey);
      totalSent += result.sent;
      users++;
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, users, sent: totalSent, dayIdx, curMins })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
