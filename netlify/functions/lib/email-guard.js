const crypto = require('crypto');
const { store, atomicUpdateJSON } = require('./store');
const { rateLimit } = require('./security');

const DEFAULT_DAILY = Math.max(1, Number(process.env.EMAIL_SAFE_DAILY_LIMIT || 400));
const DEFAULT_HOURLY = Math.max(1, Number(process.env.EMAIL_SAFE_HOURLY_LIMIT || 60));
const DEFAULT_MINUTE = Math.max(1, Number(process.env.EMAIL_SAFE_MINUTE_LIMIT || 8));
const CRITICAL_RESERVE = Math.max(0, Math.min(DEFAULT_DAILY - 1, Number(process.env.EMAIL_CRITICAL_RESERVE || 50)));

function stamp(d = new Date()) {
  const day = d.toISOString().slice(0, 10);
  const hour = `${day}:${String(d.getUTCHours()).padStart(2, '0')}`;
  const minute = `${hour}:${String(d.getUTCMinutes()).padStart(2, '0')}`;
  return { day, hour, minute };
}

async function checkAndRecord(to, purpose = 'normal', opts = {}) {
  const s = store();
  const now = new Date();
  const keys = stamp(now);
  const dailyLimit = Math.max(1, Number(opts.dailyLimit || DEFAULT_DAILY));
  const hourlyLimit = Math.max(1, Number(opts.hourlyLimit || DEFAULT_HOURLY));
  const minuteLimit = Math.max(1, Number(opts.minuteLimit || DEFAULT_MINUTE));
  const critical = /critical|2fa|reset|recovery|login|verify|security|admin/i.test(String(purpose));

  const perRecipient = await rateLimit(
    s,
    `email-recipient:${String(to || '').trim().toLowerCase()}`,
    critical ? 8 : 4,
    critical ? 15 * 60 * 1000 : 60 * 60 * 1000
  );
  if (!perRecipient.allowed) throw new Error(`EMAIL_GUARD_RECIPIENT_RATE:${perRecipient.retryAfter}`);

  const state = await atomicUpdateJSON('email-guard-state', {
    day: keys.day,
    hour: keys.hour,
    minute: keys.minute,
    daily: 0,
    hourly: 0,
    minuteCount: 0
  }, (current) => {
    const next = { ...current };
    if (next.day !== keys.day) { next.day = keys.day; next.daily = 0; }
    if (next.hour !== keys.hour) { next.hour = keys.hour; next.hourly = 0; }
    if (next.minute !== keys.minute) { next.minute = keys.minute; next.minuteCount = 0; }

    const normalDailyLimit = Math.max(0, dailyLimit - Math.min(CRITICAL_RESERVE, Math.max(0, dailyLimit - 1)));
    const normalHourlyLimit = Math.max(0, hourlyLimit - Math.min(CRITICAL_RESERVE, Math.max(0, hourlyLimit - 1)));
    if (next.minuteCount >= minuteLimit) throw Object.assign(new Error('EMAIL_GUARD_MINUTE_LIMIT'), { code: 'EMAIL_GUARD_LIMIT' });
    if (next.hourly >= (critical ? hourlyLimit : normalHourlyLimit)) throw Object.assign(new Error('EMAIL_GUARD_HOURLY_LIMIT'), { code: 'EMAIL_GUARD_LIMIT' });
    if (next.daily >= (critical ? dailyLimit : normalDailyLimit)) throw Object.assign(new Error('EMAIL_GUARD_DAILY_LIMIT'), { code: 'EMAIL_GUARD_LIMIT' });

    next.daily += 1;
    next.hourly += 1;
    next.minuteCount += 1;
    return next;
  });

  const logEntry = {
    at: Date.now(),
    toHash: crypto.createHash('sha256').update(String(to)).digest('hex').slice(0, 12),
    purpose: String(purpose).slice(0, 50),
    critical
  };
  await atomicUpdateJSON('email-guard-log', [], (log) => [...(Array.isArray(log) ? log : []), logEntry].slice(-500));

  return {
    daily: state.value.daily,
    hourly: state.value.hourly,
    minute: state.value.minuteCount,
    dailyLimit,
    hourlyLimit,
    minuteLimit,
    criticalReserve: CRITICAL_RESERVE
  };
}

async function getStats() {
  const s = store();
  const now = stamp(new Date());
  const state = await s.get('email-guard-state', { type: 'json', consistency: 'strong' }).catch(() => null) || {};
  return {
    daily: state.day === now.day ? Number(state.daily || 0) : 0,
    hourly: state.hour === now.hour ? Number(state.hourly || 0) : 0,
    minute: state.minute === now.minute ? Number(state.minuteCount || 0) : 0,
    dailyLimit: DEFAULT_DAILY,
    hourlyLimit: DEFAULT_HOURLY,
    minuteLimit: DEFAULT_MINUTE,
    criticalReserve: CRITICAL_RESERVE,
    remainingDaily: Math.max(0, DEFAULT_DAILY - (state.day === now.day ? Number(state.daily || 0) : 0)),
    remainingNormalDaily: Math.max(0, DEFAULT_DAILY - CRITICAL_RESERVE - (state.day === now.day ? Number(state.daily || 0) : 0))
  };
}

module.exports = { checkAndRecord, getStats };
