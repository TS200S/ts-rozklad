const CACHE = 'ts-rozklad-v5';

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(['/', '/index.html', '/manifest.json', '/icon-192.png', '/icon-512.png']))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  e.respondWith(
    caches.match(e.request).then(cached => {
      const net = fetch(e.request).then(res => {
        if (res.ok && e.request.url.startsWith(self.location.origin)) {
          caches.open(CACHE).then(c => c.put(e.request, res.clone()));
        }
        return res;
      }).catch(() => cached);
      return cached || net;
    })
  );
});

// ===== SCHEDULE =====
let todaySlots = [];
let firedToday = new Set();

self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SCHEDULE') {
    todaySlots = e.data.slots || [];
    firedToday = new Set();
    // Start tick aligned to next minute
    startTicker();
  }
});

let tickerStarted = false;

function startTicker() {
  if (tickerStarted) return;
  tickerStarted = true;

  // Wait until start of next minute, then tick every 60s exactly
  const now = new Date();
  const msToNextMinute = (60 - now.getSeconds()) * 1000 - now.getMilliseconds();

  setTimeout(() => {
    checkNotifications(); // fire at exact minute start
    setInterval(checkNotifications, 60 * 1000);
  }, msToNextMinute);
}

function checkNotifications() {
  const now = new Date();
  const curMins = now.getHours() * 60 + now.getMinutes();

  todaySlots.forEach(slot => {
    const [h, m] = slot.time.split(':').map(Number);
    const slotMins = h * 60 + m;
    const diff = slotMins - curMins;

    if (slot.notif10 !== false && diff === 10) {
      const key = slot.time + '_10';
      if (!firedToday.has(key)) {
        firedToday.add(key);
        fire(
          '⏰ ' + slot.name,
          `За 10 хвилин · Початок о ${slot.time}${slot.teacher ? ' · ' + slot.teacher : ''}`,
          key, [100, 50, 100]
        );
      }
    }

    if (slot.notif5 !== false && diff === 5) {
      const key = slot.time + '_5';
      if (!firedToday.has(key)) {
        firedToday.add(key);
        fire(
          '📚 ' + slot.name,
          `За 5 хвилин · Готуйся!${slot.teacher ? ' · ' + slot.teacher : ''}`,
          key, [200, 100, 200, 100, 200]
        );
      }
    }
  });
}

function fire(title, body, tag, vibrate) {
  self.registration.showNotification(title, {
    body, icon: '/icon-192.png', badge: '/icon-192.png',
    tag, vibrate, renotify: true, data: { url: '/' }
  });
  self.clients.matchAll({ includeUncontrolled: true }).then(clients =>
    clients.forEach(c => c.postMessage({ type: 'NOTIF_FIRED', title, body }))
  );
}

// ===== REAL WEB PUSH (fires even if the app is fully closed) =====
self.addEventListener('push', e => {
  let data = { title: '📚 Нагадування', body: 'Скоро пара' };
  try { if (e.data) data = e.data.json(); } catch (err) { /* fallback to default */ }

  const tag = data.title + '_' + (data.body || '').slice(0, 20);
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag,
      vibrate: [150, 60, 150],
      renotify: true,
      data: { url: '/' }
    })
  );

  e.waitUntil(
    self.clients.matchAll({ includeUncontrolled: true }).then(clients =>
      clients.forEach(c => c.postMessage({ type: 'NOTIF_FIRED', title: data.title, body: data.body }))
    )
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window' }).then(cls => {
      if (cls.length > 0) { cls[0].focus(); return; }
      return clients.openWindow('/');
    })
  );
});
