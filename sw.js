const CACHE = 'ts-daily-v5.3.10-stable';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/admin.html',
  '/admin-recovery.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    // Do not let one optional/missing asset make the whole Service Worker fail.
    await Promise.all(STATIC_ASSETS.map(async url => {
      try {
        const response = await fetch(url, { cache: 'no-store' });
        if (response.ok) await cache.put(url, response);
      } catch (_) { /* optional asset; network may be unavailable during install */ }
    }));
  })());
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE && k !== 'ts-notif-log').map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

function isAppStatic(url) {
  return STATIC_ASSETS.includes(url.pathname) && url.origin === self.location.origin;
}

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);

  // Never intercept API calls, POST/PUT/PATCH/DELETE requests, or third-party
  // resources. This is critical: authenticated schedule data must never be
  // served from a shared Cache Storage entry, and external fonts must not be
  // routed through the Service Worker CSP context.
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/.netlify/functions/')) {
    return;
  }

  if (!isAppStatic(url)) return;

  // HTML navigations are network-first so a deploy is visible immediately;
  // cached HTML is only the offline fallback. This prevents stale schedules
  // and stale authentication UI after a deployment.
  if (request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')) {
    event.respondWith((async () => {
      try {
        const response = await fetch(request, { cache: 'no-store' });
        if (response.ok) {
          const clone = response.clone();
          event.waitUntil(caches.open(CACHE).then(c => c.put(request, clone)).catch(() => {}));
        }
        return response;
      } catch (_) {
        return (await caches.match(request)) || (await caches.match('/index.html')) || Response.error();
      }
    })());
    return;
  }

  // Small static assets can use cache-first with a network fallback.
  event.respondWith((async () => {
    const cached = await caches.match(request);
    if (cached) return cached;
    try {
      const response = await fetch(request);
      if (response.ok) {
        const clone = response.clone();
        event.waitUntil(caches.open(CACHE).then(c => c.put(request, clone)).catch(() => {}));
      }
      return response;
    } catch (_) {
      return Response.error();
    }
  })());
});

// ===== SCHEDULE =====
let todaySlots = [];
let firedToday = new Set();
let pushActive = false;

self.addEventListener('message', e => {
  if (!e.data) return;
  if (e.data.type === 'SCHEDULE') {
    todaySlots = Array.isArray(e.data.slots) ? e.data.slots : [];
    pushActive = !!e.data.pushActive;
    firedToday = new Set();
    if (pushActive) stopTicker();
    else startTicker();
  }
  if (e.data.type === 'PUSH_STATUS') {
    pushActive = !!e.data.pushActive;
    if (pushActive) stopTicker();
  }
});

let tickerStarted = false;
let tickerInterval = null;

function stopTicker() {
  if (tickerInterval) { clearInterval(tickerInterval); tickerInterval = null; }
  tickerStarted = false;
}

function startTicker() {
  if (tickerStarted) return;
  tickerStarted = true;
  const now = new Date();
  const msToNextMinute = (60 - now.getSeconds()) * 1000 - now.getMilliseconds();
  setTimeout(() => {
    if (pushActive) { tickerStarted = false; return; }
    checkNotifications();
    tickerInterval = setInterval(() => {
      if (pushActive) { stopTicker(); return; }
      checkNotifications();
    }, 60 * 1000);
  }, msToNextMinute);
}

function checkNotifications() {
  const now = new Date();
  const curMins = now.getHours() * 60 + now.getMinutes();
  todaySlots.forEach(slot => {
    if (!slot || typeof slot.time !== 'string') return;
    const [h, m] = slot.time.split(':').map(Number);
    if (!Number.isFinite(h) || !Number.isFinite(m)) return;
    const slotMins = h * 60 + m;
    const diff = slotMins - curMins;
    if (slot.notif10 !== false && diff === 10) {
      const key = slot.time + '_10';
      if (!firedToday.has(key)) {
        firedToday.add(key);
        fire('⏰ ' + slot.name, `За 10 хвилин · Початок о ${slot.time}${slot.teacher ? ' · ' + slot.teacher : ''}`, key, [100, 50, 100]);
      }
    }
    if (slot.notif5 !== false && diff === 5) {
      const key = slot.time + '_5';
      if (!firedToday.has(key)) {
        firedToday.add(key);
        fire('📚 ' + slot.name, `За 5 хвилин · Готуйся!${slot.teacher ? ' · ' + slot.teacher : ''}`, key, [200, 100, 200, 100, 200]);
      }
    }
  });
}

function fire(title, body, tag, vibrate) {
  self.registration.showNotification(title, { body, icon: '/icon-192.png', badge: '/icon-192.png', tag, vibrate, renotify: true, data: { url: '/' } });
  self.clients.matchAll({ includeUncontrolled: true }).then(clients => clients.forEach(c => c.postMessage({ type: 'NOTIF_FIRED', title, body })));
}

self.addEventListener('push', e => {
  let data = { title: '📚 Нагадування', body: 'Скоро пара' };
  try { if (e.data) data = e.data.json(); } catch (_) {}
  const tag = data.title + '_' + (data.body || '').slice(0, 20);
  e.waitUntil(self.registration.showNotification(data.title, { body: data.body, icon: '/icon-192.png', badge: '/icon-192.png', tag, vibrate: [150, 60, 150], renotify: true, data: { url: '/' } }));
  e.waitUntil(self.clients.matchAll({ includeUncontrolled: true }).then(clients => clients.forEach(c => c.postMessage({ type: 'NOTIF_FIRED', title: data.title, body: data.body }))));
  e.waitUntil(logNotifToCache(data.title, data.body));
});

async function logNotifToCache(title, body) {
  try {
    const cache = await caches.open('ts-notif-log');
    const req = new Request('/__notif-log__');
    let list = [];
    const existing = await cache.match(req);
    if (existing) list = await existing.json();
    list.unshift({ id: Date.now(), title, body, time: new Date().toLocaleTimeString('uk-UA', { hour: '2-digit', minute: '2-digit' }) });
    list = list.slice(0, 50);
    await cache.put(req, new Response(JSON.stringify(list), { headers: { 'Content-Type': 'application/json' } }));
  } catch (_) {}
}

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window' }).then(cls => {
    if (cls.length > 0) { cls[0].focus(); return; }
    return clients.openWindow('/');
  }));
});
