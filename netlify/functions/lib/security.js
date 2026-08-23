const crypto = require('crypto');

function getClientIp(event) {
  const h = event.headers || {};
  const direct = h['x-nf-client-connection-ip'] || h['X-Nf-Client-Connection-Ip'];
  if (direct) return String(direct).trim();
  const forwarded = h['x-forwarded-for'] || h['X-Forwarded-For'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return 'unknown';
}

function getUserAgent(event) {
  const h = event.headers || {};
  return String(h['user-agent'] || h['User-Agent'] || '').slice(0, 500);
}

function parseDevice(userAgent) {
  const ua = String(userAgent || '');
  let os = 'Невідомий пристрій';
  if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';
  else if (/Mac OS X/i.test(ua)) os = 'macOS';
  else if (/Linux/i.test(ua)) os = 'Linux';

  let browser = 'Інший браузер';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/Chrome\//i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';

  let type = '💻 Комп’ютер';
  if (/iPhone|Android.*Mobile|Mobile/i.test(ua)) type = '📱 Телефон';
  else if (/iPad|Tablet/i.test(ua)) type = '📱 Планшет';

  return { os, browser, type };
}

async function isIpBanned(s, ip) {
  if (!ip || ip === 'unknown') return null;
  const ban = await s.get(`ip-ban:${ip}`, { type: 'json' }).catch(() => null);
  if (!ban) return null;
  if (ban.expiresAt && ban.expiresAt <= Date.now()) {
    await s.delete(`ip-ban:${ip}`).catch(() => {});
    return null;
  }
  return ban;
}

async function enforceIpBan(s, event) {
  const ip = getClientIp(event);
  return await isIpBanned(s, ip);
}

async function rateLimit(s, key, limit, windowMs) {
  const now = Date.now();
  const rec = (await s.get(`rate:${key}`, { type: 'json' }).catch(() => null)) || { hits: [] };
  rec.hits = (Array.isArray(rec.hits) ? rec.hits : []).filter(t => now - t < windowMs);
  if (rec.hits.length >= limit) {
    const retryAfter = Math.max(1, Math.ceil((windowMs - (now - rec.hits[0])) / 1000));
    await s.setJSON(`rate:${key}`, rec);
    return { allowed: false, retryAfter };
  }
  rec.hits.push(now);
  await s.setJSON(`rate:${key}`, rec);
  return { allowed: true, retryAfter: 0 };
}

function hashCode(code) {
  return crypto.createHash('sha256').update(String(code)).digest();
}

function safeCodeEqual(code, expectedHashHex) {
  try {
    const a = hashCode(code);
    const b = Buffer.from(String(expectedHashHex || ''), 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

async function protectCodeAttempt(s, namespace, subject, ip, limit = 5, windowMs = 15 * 60 * 1000) {
  const key = `${namespace}:${String(subject).slice(0, 160)}:${String(ip).slice(0, 160)}`;
  return rateLimit(s, key, limit, windowMs);
}

function hashIpForLog(ip) {
  return crypto.createHash('sha256').update(String(ip)).digest('hex').slice(0, 16);
}

module.exports = { getClientIp, getUserAgent, parseDevice, isIpBanned, enforceIpBan, rateLimit, protectCodeAttempt, hashCode, safeCodeEqual, hashIpForLog };
