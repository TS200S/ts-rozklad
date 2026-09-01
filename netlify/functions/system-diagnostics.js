const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { store } = require('./lib/store');
const { validateSession, extractToken } = require('./lib/session');
const { enforceIpBan, isSameOriginRequest, rateLimit } = require('./lib/security');

const json = (statusCode, body) => ({ statusCode, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) });
const check = (id, label, status, detail) => ({ id, label, status, detail });

exports.handler = async event => {
  if (event.httpMethod !== 'GET') return json(405, { error: 'Method Not Allowed' });
  if (!isSameOriginRequest(event)) return json(403, { error: 'Недозволене походження запиту' });
  const requestId = String(event.headers?.['x-nf-request-id'] || event.headers?.['X-Nf-Request-Id'] || crypto.randomUUID()).slice(0,80);
  try {
    const s = store();
    if (await enforceIpBan(s, event)) return json(403, { error: 'IP заблоковано' });
    const sess = await validateSession(s, extractToken(event), event);
    if (!sess || sess.banned) return json(401, { error: 'Сесія недійсна' });
    const user = await s.get(`user:${sess.username}`, { type: 'json', consistency: 'strong' }).catch(() => null);
    const master = String(process.env.ADMIN_USERNAME || '').trim().toLowerCase();
    if (!user || !(user.role === 'admin' || String(user.username || '').toLowerCase() === master)) return json(403, { error: 'Недостатньо прав' });
    const rl = await rateLimit(s, `system-diagnostics:${sess.userId}`, 6, 10 * 60 * 1000);
    if (!rl.allowed) return json(429, { error: 'Забагато перевірок. Спробуй пізніше.' });

    const checks = [];
    checks.push(check('runtime-node','Node.js runtime',process.versions.node?'PASS':'FAIL',`Node ${process.versions.node}`));
    checks.push(check('env-cron','CRON_SECRET',process.env.CRON_SECRET?'PASS':'FAIL',process.env.CRON_SECRET?'Налаштовано.':'Відсутній.'));
    checks.push(check('env-admin','ADMIN_USERNAME',process.env.ADMIN_USERNAME?'PASS':'FAIL',process.env.ADMIN_USERNAME?'Налаштовано.':'Відсутній.'));
    checks.push(check('env-gmail','Email configuration',process.env.GMAIL_USER&&process.env.GMAIL_APP_PASSWORD?'PASS':'WARN',process.env.GMAIL_USER&&process.env.GMAIL_APP_PASSWORD?'Gmail налаштований.':'Gmail не налаштований.'));
    checks.push(check('env-vapid','Push configuration',process.env.VAPID_PUBLIC_KEY&&process.env.VAPID_PRIVATE_KEY&&process.env.VAPID_SUBJECT?'PASS':'WARN',process.env.VAPID_PUBLIC_KEY&&process.env.VAPID_PRIVATE_KEY&&process.env.VAPID_SUBJECT?'VAPID налаштований.':'VAPID не повністю налаштований.'));

    const fnDir = __dirname; const moduleErrors=[];
    for (const name of fs.readdirSync(fnDir).filter(n=>n.endsWith('.js')&&n!=='system-diagnostics.js')) {
      try { delete require.cache[require.resolve(path.join(fnDir,name))]; require(path.join(fnDir,name)); } catch(e) { moduleErrors.push(`${name}: ${e.name||'Error'}`); }
    }
    checks.push(check('function-modules','Function modules',moduleErrors.length?'FAIL':'PASS',moduleErrors.length?moduleErrors.join('; ').slice(0,500):'Усі Function-модулі завантажуються.'));

    const probeKey=`__diagnostic__:system:${sess.userId}:${crypto.randomUUID()}`;
    try {
      await s.setJSON(probeKey,{v:1,at:Date.now()},{onlyIfNew:true});
      const first=await s.getWithMetadata(probeKey,{type:'json',consistency:'strong'});
      if(!first?.etag) throw new Error('NO_ETAG');
      const upd=await s.setJSON(probeKey,{v:2,at:Date.now()},{onlyIfMatch:first.etag});
      if(!upd?.modified) throw new Error('CONDITIONAL_WRITE_REJECTED');
      const second=await s.get(probeKey,{type:'json',consistency:'strong'});
      if(second?.v!==2) throw new Error('READ_AFTER_WRITE_MISMATCH');
      checks.push(check('blob-store','Netlify Blobs read/write','PASS','Тестовий запис, conditional update та читання пройшли.'));
    } catch(e) { checks.push(check('blob-store','Netlify Blobs read/write','FAIL',`Сховище не пройшло тест: ${e.code||e.message||e.name}`)); }
    finally { await s.delete(probeKey).catch(()=>{}); }

    const schedule=await s.get(`schedule-data:${sess.userId}`,{type:'json',consistency:'strong'}).catch(()=>null);
    checks.push(check('user-schedule','Schedule data',schedule&&typeof schedule==='object'?'PASS':'WARN',schedule?'Дані розкладу доступні.':'Для користувача ще немає збереженого розкладу.'));
    if(schedule){
      const notesOk=!Array.isArray(schedule.notes)||schedule.notes.every(n=>n&&typeof n==='object'&&!Array.isArray(n));
      const subjectsOk=!Array.isArray(schedule.subjects)||schedule.subjects.every(n=>n&&typeof n==='object'&&!Array.isArray(n));
      checks.push(check('schedule-notes-shape','Notes data integrity',notesOk?'PASS':'WARN',notesOk?'Структура нотаток коректна.':'Є некоректні елементи нотаток; вони будуть відфільтровані під час збереження.'));
      checks.push(check('schedule-subjects-shape','Subjects data integrity',subjectsOk?'PASS':'WARN',subjectsOk?'Структура предметів коректна.':'Є некоректні елементи предметів; вони будуть відфільтровані під час збереження.'));
    }
    const pass=checks.filter(x=>x.status==='PASS').length,warn=checks.filter(x=>x.status==='WARN').length,fail=checks.filter(x=>x.status==='FAIL').length;
    return json(200,{ok:fail===0,requestId,checkedAt:Date.now(),summary:{pass,warn,fail,total:checks.length},checks});
  } catch(err) {
    console.error('system-diagnostics failed',{requestId,code:err?.code||'UNKNOWN',name:err?.name||'Error'});
    return json(500,{error:'Не вдалося виконати самодіагностику',requestId});
  }
};
