const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest, rateLimit } = require('./lib/security');

const json = (statusCode, body) => ({
  statusCode,
  headers: {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  },
  body: JSON.stringify(body),
});

const check = (id, label, status, detail, meta = {}) => ({ id, label, status, detail, ...meta });

const criticalFunctions = [
  'auth.js', 'register.js', 'verify-login.js', 'session-status.js',
  'save-schedule.js', 'load-schedule.js', 'admin.js',
  'note-files-list.js', 'note-files-upload.js', 'note-files-get.js',
  'note-files-delete.js', 'check-notifications.js',
];

function envStatus(names, label) {
  const missing = names.filter(name => !String(process.env[name] || '').trim());
  return check(
    label,
    label,
    missing.length ? 'FAIL' : 'PASS',
    missing.length ? `Відсутні: ${missing.join(', ')}` : 'Усі необхідні змінні налаштовані.',
  );
}

exports.handler = async event => {
  if (event.httpMethod !== 'GET') return json(405, { error: 'Method Not Allowed' });
  if (!isSameOriginRequest(event)) return json(403, { error: 'Недозволене походження запиту' });

  const requestId = String(
    event.headers?.['x-nf-request-id'] ||
    event.headers?.['X-Nf-Request-Id'] ||
    crypto.randomUUID(),
  ).slice(0, 80);

  try {
    const s = store();

    if (await enforceIpBan(s, event)) return json(403, { error: 'IP заблоковано' });

    const sess = await validateSession(s, extractToken(event), event);
    if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна' });

    const user = await s.get(`user:${sess.username}`, {
      type: 'json',
      consistency: 'strong',
    }).catch(() => null);

    if (!user || (user.role !== 'admin' && !user.isMaster)) {
      return json(403, { error: 'Недостатньо прав' });
    }

    const rl = await rateLimit(s, `system-diagnostics:${sess.userId}`, 6, 10 * 60 * 1000);
    if (!rl.allowed) return json(429, { error: 'Забагато перевірок. Спробуй пізніше.' });

    const checks = [];

    checks.push(check(
      'diagnostics-version',
      'Версія самодіагностики',
      'PASS',
      'diagnostics-v2',
      { value: 'diagnostics-v2' },
    ));

    checks.push(check(
      'runtime-node',
      'Node.js runtime',
      process.versions.node ? 'PASS' : 'FAIL',
      process.versions.node ? `Node ${process.versions.node}` : 'Node.js runtime недоступний.',
    ));

    checks.push(envStatus(['CRON_SECRET'], 'CRON_SECRET'));
    checks.push(envStatus(['ADMIN_USERNAME'], 'ADMIN_USERNAME'));

    checks.push(check(
      'env-gmail',
      'Email configuration',
      process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD ? 'PASS' : 'WARN',
      process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD
        ? 'Gmail налаштований.'
        : 'Gmail не повністю налаштований; email-функції можуть бути недоступні.',
    ));

    checks.push(check(
      'env-vapid',
      'Push configuration',
      process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT ? 'PASS' : 'WARN',
      process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT
        ? 'VAPID налаштований.'
        : 'VAPID не повністю налаштований; push-сповіщення можуть бути недоступні.',
    ));

    // Verify that the critical Function source files exist and can be loaded.
    // This does not execute handlers or mutate user data.
    const fnDir = __dirname;
    const missingFunctions = criticalFunctions.filter(name => !fs.existsSync(path.join(fnDir, name)));
    const moduleErrors = [];

    for (const name of criticalFunctions) {
      if (missingFunctions.includes(name)) continue;
      try {
        const modulePath = path.join(fnDir, name);
        delete require.cache[require.resolve(modulePath)];
        const mod = require(modulePath);
        if (!mod || typeof mod.handler !== 'function') moduleErrors.push(`${name}: handler missing`);
      } catch (e) {
        moduleErrors.push(`${name}: ${e.name || 'Error'}${e.code ? ` (${e.code})` : ''}`);
      }
    }

    checks.push(check(
      'critical-functions',
      'Критичні Netlify Functions',
      missingFunctions.length || moduleErrors.length ? 'FAIL' : 'PASS',
      missingFunctions.length || moduleErrors.length
        ? `Відсутні: ${missingFunctions.join(', ') || '—'}; помилки: ${moduleErrors.join('; ') || '—'}`.slice(0, 1000)
        : `${criticalFunctions.length} критичних Function-модулів існують і експортують handler.`,
    ));

    // Safe Blobs probe: write/read/conditional-update/delete only under a random diagnostic key.
    const probeKey = `__diagnostic__:system:${sess.userId}:${crypto.randomUUID()}`;
    try {
      await s.setJSON(probeKey, { v: 1, at: Date.now() }, { onlyIfNew: true });
      const first = await s.getWithMetadata(probeKey, { type: 'json', consistency: 'strong' });
      if (!first?.etag) throw Object.assign(new Error('NO_ETAG'), { code: 'NO_ETAG' });

      const upd = await s.setJSON(
        probeKey,
        { v: 2, at: Date.now() },
        { onlyIfMatch: first.etag },
      );
      if (!upd?.modified) throw Object.assign(new Error('CONDITIONAL_WRITE_REJECTED'), { code: 'CONDITIONAL_WRITE_REJECTED' });

      const second = await s.get(probeKey, { type: 'json', consistency: 'strong' });
      if (second?.v !== 2) throw Object.assign(new Error('READ_AFTER_WRITE_MISMATCH'), { code: 'READ_AFTER_WRITE_MISMATCH' });

      checks.push(check(
        'blob-store',
        'Netlify Blobs read/write',
        'PASS',
        'Тестовий запис, conditional update, strong read та подальше видалення пройшли.',
      ));
    } catch (e) {
      checks.push(check(
        'blob-store',
        'Netlify Blobs read/write',
        'FAIL',
        `Сховище не пройшло тест: ${e.code || e.message || e.name}`,
      ));
    } finally {
      await s.delete(probeKey).catch(() => {});
    }

    const schedule = await s.get(`schedule-data:${sess.userId}`, {
      type: 'json',
      consistency: 'strong',
    }).catch(() => null);

    checks.push(check(
      'user-schedule',
      'Schedule data',
      schedule && typeof schedule === 'object' && !Array.isArray(schedule) ? 'PASS' : 'WARN',
      schedule
        ? 'Дані розкладу доступні.'
        : 'Для користувача ще немає збереженого розкладу.',
    ));

    if (schedule && typeof schedule === 'object' && !Array.isArray(schedule)) {
      const notesOk = !Array.isArray(schedule.notes) || schedule.notes.every(
        n => n && typeof n === 'object' && !Array.isArray(n),
      );
      const subjectsOk = !Array.isArray(schedule.subjects) || schedule.subjects.every(
        n => n && typeof n === 'object' && !Array.isArray(n),
      );
      const oneOffOk = !Array.isArray(schedule.oneOffLessons) || schedule.oneOffLessons.every(
        n => n && typeof n === 'object' && !Array.isArray(n),
      );
      const cfgOk = schedule.notif10 === undefined || typeof schedule.notif10 === 'boolean';

      checks.push(check(
        'schedule-notes-shape',
        'Notes data integrity',
        notesOk ? 'PASS' : 'FAIL',
        notesOk ? 'Структура нотаток коректна.' : 'Є некоректні елементи нотаток.',
      ));
      checks.push(check(
        'schedule-subjects-shape',
        'Subjects data integrity',
        subjectsOk ? 'PASS' : 'FAIL',
        subjectsOk ? 'Структура предметів коректна.' : 'Є некоректні елементи предметів.',
      ));
      checks.push(check(
        'schedule-oneoff-shape',
        'One-off lessons integrity',
        oneOffOk ? 'PASS' : 'FAIL',
        oneOffOk ? 'Структура одноразових пар коректна.' : 'Є некоректні одноразові пари.',
      ));
      checks.push(check(
        'schedule-config-shape',
        'Schedule config integrity',
        cfgOk ? 'PASS' : 'FAIL',
        cfgOk ? 'Типи налаштувань сповіщень коректні.' : 'Некоректний тип налаштування сповіщень.',
      ));
    }

    const summary = {
      pass: checks.filter(x => x.status === 'PASS').length,
      warn: checks.filter(x => x.status === 'WARN').length,
      fail: checks.filter(x => x.status === 'FAIL').length,
    };
    summary.total = checks.length;

    return json(200, {
      ok: summary.fail === 0,
      requestId,
      checkedAt: Date.now(),
      summary,
      checks,
    });
  } catch (err) {
    console.error('system-diagnostics failed', {
      requestId,
      code: err?.code || 'UNKNOWN',
      name: err?.name || 'Error',
    });
    return json(500, {
      error: 'Не вдалося виконати самодіагностику',
      requestId,
    });
  }
};
