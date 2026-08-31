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
const CRON_SECRET = String(process.env.CRON_SECRET || '').trim();
const CURRENT_ORIGIN = String(process.env.URL || process.env.DEPLOY_PRIME_URL || '').replace(/\/$/, '');
const { processEmailQueue } = require('./lib/email-queue');
const { atomicUpdateJSON } = require('./lib/store');
const crypto = require('crypto');

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
async function claimPush(s, key) {
  const result = await s.set(key, JSON.stringify({ claimedAt: Date.now() }), { onlyIfNew: true });
  return !!result.modified;
}

function pushClaimKey(userId, dateKey, reminderKey, endpoint) {
  const digest = crypto.createHash('sha256').update(String(endpoint)).digest('hex').slice(0, 24);
  return `push-claim:${userId}:${dateKey}:${crypto.createHash('sha256').update(String(reminderKey)).digest('hex').slice(0, 24)}:${digest}`;
}

async function processUser(s, userId, dayIdx, curMins, dateKey) {
  const data = await s.get(`schedule-data:${userId}`, { type: 'json', consistency: 'strong' });
  const allSubscriptions = (await s.get(`subscriptions:${userId}`, { type: 'json', consistency: 'strong' })) || [];
  const subscriptions = allSubscriptions.filter(sub => sub && sub.siteOrigin === CURRENT_ORIGIN);
  if (!data || !subscriptions.length) return { sent: 0 };

  let slots = data.schedule?.[dayIdx] || data.schedule?.[String(dayIdx)] || [];
  const oneOff = Array.isArray(data.oneOffLessons) ? data.oneOffLessons.filter(x => x && x.date === dateKey) : [];
  slots = slots.concat(oneOff.map(x => ({ ...x, _oneOff: true })));

  const reminders = [];
  for (const sl of slots) {
    if (!sl || typeof sl.time !== 'string' || !/^\d{1,2}:\d{2}$/.test(sl.time)) continue;
    const [h, m] = sl.time.split(':').map(Number);
    if (h > 23 || m > 59) continue;
    const slotMins = h * 60 + m;
    const diff = slotMins - curMins;
    const subj = (data.subjects || []).find(x => x.id === sl.subjId) || { name: 'Пара' };
    const lessonIdentity = String(sl.id || sl.lessonId || sl.subjId || `${sl.time}:${subj.name}`);

    if (data.notif10 && diff <= 10 && diff >= 8) {
      reminders.push({
        key: `lesson:${lessonIdentity}:${sl.time}:10`,
        title: '⏰ ' + subj.name,
        body: `За 10 хвилин · Початок о ${sl.time}${subj.teacher ? ' · ' + subj.teacher : ''}`
      });
    }
    if (data.notif5 && diff <= 5 && diff >= 3) {
      reminders.push({
        key: `lesson:${lessonIdentity}:${sl.time}:5`,
        title: '📚 ' + subj.name,
        body: `За 5 хвилин · Готуйся!${subj.teacher ? ' · ' + subj.teacher : ''}`
      });
    }
  }

  if (Array.isArray(data.notes)) {
    const [ny, nmo, nd] = dateKey.split('-').map(Number);
    const nowWallTs = Date.UTC(ny, nmo - 1, nd, 0, 0) + curMins * 60000;
    for (const note of data.notes) {
      if (note.done || !note.deadline) continue;
      const [dPart, tPart] = String(note.deadline).split('T');
      const [dy, dmo, dd] = String(dPart || '').split('-').map(Number);
      const [dh, dmi] = String(tPart || '23:59').split(':').map(Number);
      if (![dy, dmo, dd, dh, dmi].every(Number.isFinite)) continue;
      const deadlineWallTs = Date.UTC(dy, dmo - 1, dd, dh, dmi);
      const diffMin = Math.round((deadlineWallTs - nowWallTs) / 60000);
      const shortText = String(note.text || 'Нотатка').slice(0, 60);
      if (diffMin <= 1440 && diffMin > 1430) reminders.push({ key: `note:${note.id}:24h`, title: '🔔 Дедлайн завтра', body: shortText });
      else if (diffMin <= 180 && diffMin > 170) reminders.push({ key: `note:${note.id}:3h`, title: '⏳ Дедлайн наближається — 3 години', body: shortText });
      else if (diffMin <= 60 && diffMin > 50) reminders.push({ key: `note:${note.id}:1h`, title: '🚨 Залишилась 1 година! Роби швидше', body: shortText });
      else if (diffMin <= 0) reminders.push({ key: `note:${note.id}:overdue:${dateKey}`, title: '⚠️ Прострочено!', body: shortText });
    }
  }

  let sent = 0;
  const validSubscriptions = [];
  for (const sub of subscriptions) {
    let keep = true;
    for (const msg of reminders) {
      const claimKey = pushClaimKey(userId, dateKey, msg.key, sub.endpoint);
      const claimed = await claimPush(s, claimKey);
      if (!claimed) continue;
      try {
        await webpush.sendNotification(sub, JSON.stringify({ title: msg.title, body: msg.body }));
        sent++;
        await atomicUpdateJSON(`fired-log:${userId}`, { dateKey, fired: [] }, current => {
          const next = current.dateKey === dateKey ? current : { dateKey, fired: [] };
          if (!next.fired.includes(msg.key)) next.fired.push(msg.key);
          return { dateKey, fired: next.fired.slice(-1000) };
        }).catch(() => {});
      } catch (err) {
        if (err.statusCode === 404 || err.statusCode === 410) {
          keep = false;
        } else {
          // Temporary failure: release this subscription/message claim so the
          // next cron tick can retry it. Successful subscriptions remain claimed.
          await s.delete(claimKey).catch(() => {});
        }
      }
    }
    if (keep) validSubscriptions.push(sub);
  }

  if (validSubscriptions.length !== allSubscriptions.length) {
    await atomicUpdateJSON(`subscriptions:${userId}`, allSubscriptions, current => {
      const currentList = Array.isArray(current) ? current : [];
      const bad = new Set(allSubscriptions.filter(x => !validSubscriptions.includes(x)).map(x => x.endpoint));
      return currentList.filter(x => !bad.has(x.endpoint));
    }).catch(() => {});
  }
  return { sent };
}

exports.handler = async (event) => {
  if (!CRON_SECRET) return { statusCode: 503, body: 'Cron secret is not configured' };
  const provided = String(event.headers?.['x-cron-secret'] || event.headers?.['X-Cron-Secret'] || '');
  if (!provided || Buffer.byteLength(provided) !== Buffer.byteLength(CRON_SECRET) || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(CRON_SECRET))) {
    return { statusCode: 401, body: 'Unauthorized' };
  }
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
    return { statusCode: 503, body: 'VAPID keys not configured' };
  }
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
    const s = store();
    const { dayIdx, minutes: curMins, dateKey } = kyivParts();

    const { blobs } = await s.list({ prefix: 'schedule-data:' });
    let totalSent = 0, users = 0;

    for (const blob of blobs) {
      const userId = blob.key.slice('schedule-data:'.length);
      if (!userId) continue;
      try {
        const result = await processUser(s, userId, dayIdx, curMins, dateKey);
        totalSent += result.sent;
        users++;
      } catch (userErr) {
        console.error('[check-notifications:user]', userId, userErr?.message || userErr);
      }
    }

    const emailQueue = await processEmailQueue(5).catch(() => ({ sent:0, failed:0, queued:0 }));
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, users, sent: totalSent, dayIdx, curMins, emailQueue })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Внутрішня помилка сервера' }) };
  }
};
