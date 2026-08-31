'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const FUN = path.join(ROOT, 'netlify', 'functions');
const { rateLimit, protectCodeAttempt, hashCode, safeCodeEqual } = require(path.join(FUN, 'lib', 'security'));
const { sessionCookie, clearSessionCookie, extractToken, createSession, validateSession, getSessionPublicId } = require(path.join(FUN, 'lib', 'session'));
const { recordActivity, listActivity } = require(path.join(FUN, 'lib', 'activity'));

class MockStore {
  constructor(){ this.map = new Map(); }
  async get(key, opts){
    const v = this.map.get(key);
    if (v === undefined) return null;
    if (opts && opts.type === 'json') return JSON.parse(JSON.stringify(v.value ?? v));
    return v.value ?? v;
  }
  async getWithMetadata(key, opts){
    const v = this.map.get(key);
    if (v === undefined) return { data: null, etag: null };
    const value = JSON.parse(JSON.stringify(v.value ?? v));
    return { data: value, etag: String(v.etag || '1') };
  }
  async setJSON(key, value, options={}){
    const current = this.map.get(key);
    if (options.onlyIfNew && current !== undefined) return { modified:false };
    if (options.onlyIfMatch && (!current || String(current.etag) !== String(options.onlyIfMatch))) return { modified:false };
    const etag = String((Number(current?.etag || 0) + 1));
    this.map.set(key, { value: JSON.parse(JSON.stringify(value)), etag });
    return { modified:true };
  }
  async set(key, value, options={}){
    const current = this.map.get(key);
    if (options.onlyIfNew && current !== undefined) return { modified:false };
    if (options.onlyIfMatch && (!current || String(current.etag) !== String(options.onlyIfMatch))) return { modified:false };
    const etag = String((Number(current?.etag || 0) + 1));
    this.map.set(key, { value, etag });
    return { modified:true };
  }
  async delete(key){ this.map.delete(key); }
}

const tests = [];
function test(name, fn){ tests.push({name, fn}); }
function ok(condition, message){ assert.ok(condition, message); }

// Pure security primitives
test('6-digit codes are random-looking and valid', () => {
  const code = String(crypto.randomInt(100000, 1000000));
  ok(/^\d{6}$/.test(code), 'code must be exactly 6 digits');
  const hash = hashCode(code).toString('hex');
  ok(safeCodeEqual(code, hash), 'correct code must verify');
  ok(!safeCodeEqual('000000', hash), 'wrong code must fail');
});

test('code comparison rejects malformed hashes safely', () => {
  ok(!safeCodeEqual('123456', ''), 'empty hash must fail');
  ok(!safeCodeEqual('123456', 'zzzz'), 'malformed hash must fail');
});

test('rate limiter blocks after limit', async () => {
  const s = new MockStore();
  const key = 'test-rate';
  for (let i=0;i<3;i++) ok((await rateLimit(s,key,3,60000)).allowed, 'first 3 attempts allowed');
  ok(!(await rateLimit(s,key,3,60000)).allowed, '4th attempt blocked');
});

test('code attempt limiter is scoped by subject and IP', async () => {
  const s = new MockStore();
  for (let i=0;i<2;i++) ok((await protectCodeAttempt(s,'suite','user1','1.1.1.1',2,60000)).allowed, 'same subject/ip allowed until limit');
  ok(!(await protectCodeAttempt(s,'suite','user1','1.1.1.1',2,60000)).allowed, 'same subject/ip blocked');
  ok((await protectCodeAttempt(s,'suite','user1','2.2.2.2',2,60000)).allowed, 'different IP has separate bucket');
  ok((await protectCodeAttempt(s,'suite','user2','1.1.1.1',2,60000)).allowed, 'different subject has separate bucket');
});

// Cookie/session primitives
test('session cookie has required hardened attributes', () => {
  const c = sessionCookie('abc123', 3600);
  ok(c.includes('__Host-ts_session='), 'host cookie name');
  ok(c.includes('Path=/'), 'path');
  ok(c.includes('Secure'), 'secure');
  ok(c.includes('HttpOnly'), 'httponly');
  ok(c.includes('SameSite=Lax'), 'samesite');
  ok(!c.includes('Domain='), 'host cookie must not specify Domain');
  ok(clearSessionCookie().includes('Max-Age=0'), 'clear cookie expires immediately');
});

test('Authorization bearer is ignored', () => {
  const token = extractToken({ headers: { authorization: 'Bearer stolen-token' } });
  ok(token === null, 'bearer token must not authenticate');
});

test('HttpOnly cookie is extracted correctly', () => {
  const token = extractToken({ headers: { cookie: '__Host-ts_session=abc%20123; other=x' } });
  ok(token === 'abc 123', 'cookie token decoded');
});

test('session binding accepts matching device and UA', async () => {
  const s = new MockStore();
  await s.setJSON('user:demo', { userId:'u1', username:'demo', role:'user', banned:false });
  const meta = { ip:'1.1.1.1', userAgent:'Mozilla/5.0 Chrome/151.0 Windows NT 10.0', device:{os:'Windows',browser:'Chrome',type:'💻 Комп’ютер'}, deviceId:'device-a' };
  const created = await createSession(s,'u1','demo',meta);
  const event = { headers: { cookie: `__Host-ts_session=${created.token}`, 'x-ts-device-id':'device-a', 'user-agent':meta.userAgent, 'x-nf-client-connection-ip':'1.1.1.1' } };
  const sess = await validateSession(s, created.token, event);
  ok(sess && sess.username === 'demo', 'matching device should validate');
});

test('session binding rejects mismatched device and revokes session', async () => {
  const s = new MockStore();
  await s.setJSON('user:demo2', { userId:'u2', username:'demo2', role:'user', banned:false });
  const meta = { ip:'1.1.1.1', userAgent:'Mozilla/5.0 Chrome/151.0 Windows NT 10.0', device:{os:'Windows',browser:'Chrome',type:'💻 Комп’ютер'}, deviceId:'device-a' };
  const created = await createSession(s,'u2','demo2',meta);
  const event = { headers: { cookie: `__Host-ts_session=${created.token}`, 'x-ts-device-id':'device-b', 'user-agent':meta.userAgent, 'x-nf-client-connection-ip':'1.1.1.1' } };
  const sess = await validateSession(s, created.token, event);
  ok(sess === null, 'mismatched device must fail');
  ok((await s.get(`session:${require(path.join(FUN,'lib','session')).sessionKey(created.token)}`, {type:'json'})) === null, 'rejected session must be revoked');
});

test('session public id is not the raw session token', async () => {
  const token = crypto.randomBytes(32).toString('hex');
  const id = getSessionPublicId(token, {sessionId:'1234567890abcdef'});
  ok(id === '1234567890abcdef', 'public id uses stored opaque id');
  ok(id !== token, 'public id never equals raw token');
});

test('session records are stored under a one-way hashed key', async () => {
  const s = new MockStore();
  await s.setJSON('user:demo3', { userId:'u3', username:'demo3', role:'user', banned:false });
  const meta = { ip:'1.1.1.1', userAgent:'Mozilla/5.0 Chrome/151.0 Windows NT 10.0', device:{os:'Windows',browser:'Chrome',type:'💻 Комп’ютер'}, deviceId:'device-c' };
  const created = await createSession(s,'u3','demo3',meta);
  const { sessionKey } = require(path.join(FUN,'lib','session'));
  ok(await s.get(`session:${sessionKey(created.token)}`, {type:'json'}), 'hashed session record exists');
  ok((await s.get(`session:${created.token}`, {type:'json'})) === null, 'raw token key is not used for new sessions');
  const storedList = await s.get('user-sessions:u3',{type:'json'});
  ok(storedList.every(k => !k.includes(created.token)), 'session list does not contain raw token');
});

test('password changes invalidate older sessions at validation time', () => {
  const text = fs.readFileSync(path.join(FUN,'lib','session.js'),'utf8');
  ok(text.includes('passwordChangedAt') && text.includes('session-invalidated-by-password-change'), 'session validation must reject sessions created before password change');
});

test('registration verify source no longer references an undefined nickname', () => {
  const text = fs.readFileSync(path.join(FUN,'register.js'),'utf8');
  ok(!/if \(action === 'verify'[\s\S]*?const nick = String\(nickname\)/.test(text), 'verify flow must use pending.nickname');
  ok(text.includes('pending.nickname || pending.username'), 'verify flow uses stored pending nickname');
});

test('only one external notification scheduler is configured', () => {
  const netlify = fs.readFileSync(path.join(ROOT,'netlify.toml'),'utf8');
  ok(!/functions\.\"scheduled-notifications\"[\s\S]*schedule/.test(netlify), 'scheduled-notifications must not also run on a schedule');
});

test('file upload rejects generic octet-stream and checks signatures', () => {
  const text = fs.readFileSync(path.join(FUN,'note-files-upload.js'),'utf8');
  ok(!/application\/octet-stream'/.test(text), 'generic octet-stream must not be an allowed upload type');
  ok(text.includes('hasMagic'), 'upload must validate file signatures');
});

test('schedule save cleans file blobs that are no longer referenced', () => {
  const text = fs.readFileSync(path.join(FUN,'save-schedule.js'),'utf8');
  ok(text.includes('s.delete(meta.blobKey)'), 'unreferenced file blobs must be deleted');
  ok(text.includes('referenced'), 'attachment references must be reconciled server-side');
});

test('legacy storage deletion endpoint is removed', () => {
  const text = fs.readFileSync(path.join(FUN,'storage-admin.js'),'utf8');
  ok(!text.includes('legacy-delete-orphans-disabled'), 'legacy destructive endpoint must not exist');
  ok(text.includes("event.httpMethod!=='GET'"), 'storage-admin direct mutations must be disabled');
});

test('admin recovery rate-limit window is 15 minutes', () => {
  const text = fs.readFileSync(path.join(FUN,'admin.js'),'utf8');
  ok(text.includes('admin-recovery-verify:${username}:${ip}', 8, 15 * 60 * 1000), 'recovery verification uses a 15 minute rate-limit window');
});

// Activity log sanitization and retention
test('activity log strips secrets', async () => {
  const s = new MockStore();
  await recordActivity(s,'u3','test',{password:'x',hash:'h',salt:'s',token:'t',code:'123456',normal:'ok',nested:{secret:'x',device:'Chrome'}});
  const rows = await listActivity(s,'u3',10);
  const d = rows[0].details;
  ok(d.normal === 'ok', 'normal field retained');
  ok(!('password' in d) && !('hash' in d) && !('salt' in d) && !('token' in d) && !('code' in d), 'secrets removed');
  ok(d.nested && !('secret' in d.nested) && d.nested.device === 'Chrome', 'nested secrets removed');
});

test('activity log retains max 1000 events', async () => {
  const s = new MockStore();
  s.setJSON = async (key,value) => { s.map.set(key, {value:JSON.parse(JSON.stringify(value)), etag:String(Date.now())}); return {modified:true}; };
  for (let i=0;i<1005;i++) await recordActivity(s,'u4','event',{n:i});
  const rows = await listActivity(s,'u4',2000);
  ok(rows.length === 1000, 'exactly 1000 retained');
  ok(rows[0].details.n === 1004, 'newest event first');
});


test('state-changing browser requests enforce same-origin when Origin is present', () => {
  const text = fs.readFileSync(path.join(FUN,'lib','security.js'),'utf8');
  ok(text.includes('isSameOriginRequest'), 'same-origin helper exists');
  ok(text.includes('process.env.URL') && text.includes('Origin'), 'origin is checked against deployment origin');
});

// Static checks
test('all function files parse', () => {
  const { execFileSync } = require('child_process');
  const files = [];
  function walk(dir){ for(const name of fs.readdirSync(dir)){ const p=path.join(dir,name); const st=fs.statSync(p); if(st.isDirectory()) walk(p); else if(name.endsWith('.js')) files.push(p); } }
  walk(FUN);
  for(const file of files){ execFileSync(process.execPath,['--check',file],{stdio:'pipe'}); }
  ok(files.length > 0, 'functions discovered');
});

test('no function accepts Authorization header as session credential', () => {
  const files = [];
  function walk(dir){ for(const name of fs.readdirSync(dir)){ const p=path.join(dir,name); const st=fs.statSync(p); if(st.isDirectory()) walk(p); else if(name.endsWith('.js')) files.push(p); } }
  walk(FUN);
  for(const file of files){
    const text=fs.readFileSync(file,'utf8');
    ok(!/authorization.*bearer|bearer.*authorization/i.test(text), `legacy bearer auth reference in ${path.relative(ROOT,file)}`);
  }
});


test('all state-changing POST functions enforce same-origin', () => {
  const files = fs.readdirSync(FUN).filter(n => n.endsWith('.js'));
  for (const name of files) {
    const text = fs.readFileSync(path.join(FUN, name), 'utf8');
    if (/httpMethod[^\n]*POST|httpMethod\s*!==\s*['"]POST/.test(text)) {
      ok(text.includes('isSameOriginRequest'), `${name} must enforce same-origin for POST`);
    }
  }
});

test('email guard uses atomic shared state', () => {
  const text = fs.readFileSync(path.join(FUN,'lib','email-guard.js'),'utf8');
  ok(text.includes("atomicUpdateJSON('email-guard-state'"), 'email guard counters must use atomic CAS updates');
  ok(!/function inc\(|async function inc\(/.test(text), 'non-atomic counter helper must not remain');
});

test('email queue uses per-item records and atomic claims', () => {
  const text = fs.readFileSync(path.join(FUN,'lib','email-queue.js'),'utf8');
  ok(text.includes('email-item:'), 'queue items must be individually addressable');
  ok(text.includes('email-claim:'), 'queue items must have atomic claims');
  ok(!/s\.get\(['"]email-queue['"]/.test(text), 'legacy shared queue array must not remain');
});

test('push reminders use atomic per-subscription claims', () => {
  const text = fs.readFileSync(path.join(FUN,'check-notifications.js'),'utf8');
  ok(text.includes('push-claim:'), 'push sends must have atomic claims');
  ok(text.includes('onlyIfNew'), 'push claims must be conditional writes');
  ok(text.includes('delete(claimKey)'), 'temporary push failures must release their claims');
});

test('activity and audit logs use concurrency-safe updates', () => {
  const activity = fs.readFileSync(path.join(FUN,'lib','activity.js'),'utf8');
  const admin = fs.readFileSync(path.join(FUN,'admin.js'),'utf8');
  ok(activity.includes('atomicUpdateJSON'), 'activity log must use atomic updates');
  ok(admin.includes("atomicUpdateJSON('audit-log'"), 'audit log must use atomic updates');
});

test('public login uses dummy password hashing for missing users', () => {
  const text = fs.readFileSync(path.join(FUN,'auth.js'),'utf8');
  ok(text.includes('DUMMY_SALT') && text.includes('scryptSync'), 'missing-user path must burn password-hash work');
});

test('no obsolete historical V5 text reports remain in the release', () => {
  const files = [];
  function walk(dir){ for(const name of fs.readdirSync(dir)){ const p=path.join(dir,name); const st=fs.statSync(p); if(st.isDirectory()) walk(p); else files.push(path.relative(ROOT,p)); } }
  walk(ROOT);
  ok(!files.some(f => /^V5-.*\.txt$/i.test(path.basename(f))), 'old V5 text reports must be removed from release');
});


test('HTML inline JavaScript blocks parse', () => {
  const { execFileSync } = require('child_process');
  const htmlFiles = ['index.html','admin.html','admin-recovery.html','secret.html'];
  for (const name of htmlFiles) {
    const html = fs.readFileSync(path.join(ROOT,name),'utf8');
    const blocks = [...html.matchAll(/<script(?:[^>]*)>([\s\S]*?)<\/script>/gi)].map(m=>m[1]).filter(x=>x.trim());
    blocks.forEach((code, i) => {
      const tmp = path.join(require('os').tmpdir(), `tsdaily-${process.pid}-${i}.js`);
      fs.writeFileSync(tmp, code);
      try { execFileSync(process.execPath, ['--check', tmp], {stdio:'pipe'}); }
      finally { try { fs.unlinkSync(tmp); } catch {} }
    });
  }
});

test('release contains no obvious private-key or API-key literals', () => {
  const files = [];
  function walk(dir){ for(const name of fs.readdirSync(dir)){ const p=path.join(dir,name); const st=fs.statSync(p); if(st.isDirectory()) walk(p); else files.push(p); } }
  walk(ROOT);
  const patterns = [
    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/i,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bsk-[A-Za-z0-9_-]{20,}/,
    /GOCSPX-[A-Za-z0-9_-]{20,}/
  ];
  for (const file of files) {
    if (file.includes(`${path.sep}ts-test${path.sep}`)) continue;
    let text=''; try { text=fs.readFileSync(file,'utf8'); } catch { continue; }
    for (const pattern of patterns) ok(!pattern.test(text), `possible secret literal in ${path.relative(ROOT,file)}`);
  }
});

test('package version is 5.3.2', () => {
  const pkg = require(path.join(ROOT,'package.json'));
  ok(pkg.version === '5.3.2', `expected 5.3.2, got ${pkg.version}`);
});

test('Service Worker never intercepts authenticated API or non-GET requests', () => {
  const sw = fs.readFileSync(path.join(ROOT, 'sw.js'), 'utf8');
  ok(/request\.method !== 'GET'/.test(sw), 'non-GET requests must bypass SW');
  ok(/url\.pathname\.startsWith\('\/\.netlify\/functions\/'\)/.test(sw), 'Netlify Functions must bypass SW');
  ok(!/caches\.match\(e\.request\).*fetch\(e\.request\)/s.test(sw), 'unsafe catch-all cache strategy must not return');
});

test('CSP is delivered as an HTTP header, not meta with frame-ancestors', () => {
  const htmlFiles = ['index.html','admin.html','admin-recovery.html'];
  for (const name of htmlFiles) {
    const text = fs.readFileSync(path.join(ROOT, name), 'utf8');
    ok(!/http-equiv=["']Content-Security-Policy/i.test(text), `${name} must not define CSP via meta`);
  }
  const netlify = fs.readFileSync(path.join(ROOT, 'netlify.toml'), 'utf8');
  ok(/Content-Security-Policy\s*=/.test(netlify), 'CSP header must be configured in netlify.toml');
  ok(/frame-ancestors 'self'/.test(netlify), 'frame-ancestors must be in HTTP CSP');
  ok(/connect-src 'self'/.test(netlify), 'API connect-src must allow same-origin functions');
  ok(/fonts\.googleapis\.com/.test(netlify) && /fonts\.gstatic\.com/.test(netlify), 'Google Fonts must be allowed');
});

test('Session status and session management requests include device binding', () => {
  const text = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  ok(/session-status[\s\S]{0,220}authHeaders\(\)/.test(text), 'session-status must send device id');
  ok(/session-management.*cache:'no-store',headers:authHeaders\(\)/.test(text), 'session-management GET must send device id');
});

test('push subscriptions are bound to the current site origin', () => {
  const save = fs.readFileSync(path.join(ROOT, 'netlify/functions/save-subscription.js'), 'utf8');
  const check = fs.readFileSync(path.join(ROOT, 'netlify/functions/check-notifications.js'), 'utf8');
  ok(save.includes('siteOrigin') && save.includes('process.env.URL'), 'save-subscription records siteOrigin');
  ok(check.includes('CURRENT_ORIGIN') && check.includes('sub.siteOrigin === CURRENT_ORIGIN'), 'check-notifications filters by current origin');
});

test('Schedule endpoint is explicitly non-cacheable', () => {
  const text = fs.readFileSync(path.join(FUN, 'load-schedule.js'), 'utf8');
  ok(/Cache-Control['"]:\s*['"]no-store['"]/.test(text), 'load-schedule must set no-store');
});


test('private note file endpoints enforce ownership and size/type limits', () => {
  const up = fs.readFileSync(path.join(FUN,'note-files-upload.js'),'utf8');
  const get = fs.readFileSync(path.join(FUN,'note-files-get.js'),'utf8');
  const del = fs.readFileSync(path.join(FUN,'note-files-delete.js'),'utf8');
  ok(/MAX_FILE\s*=\s*4\s*\*\s*1024\s*\*\s*1024/.test(up), 'upload limit must be 4MB or less');
  ok(up.includes('ALLOWED') && up.includes('rateLimit'), 'upload must validate type and rate limit');
  ok(get.includes('validateSession') && get.includes('Forbidden'), 'download must authenticate and authorize');
  ok(del.includes('validateSession') && del.includes('await s.delete(meta.blobKey)'), 'delete must authenticate and delete the blob');
});

test('schedule supports configurable periods and one-off lessons', () => {
  const html = fs.readFileSync(path.join(ROOT,'index.html'),'utf8');
  const save = fs.readFileSync(path.join(FUN,'save-schedule.js'),'utf8');
  const notify = fs.readFileSync(path.join(FUN,'check-notifications.js'),'utf8');
  ok(html.includes('f-period') && html.includes('oneoff'), 'UI must expose period presets and one-off lessons');
  ok(save.includes('oneOffLessons'), 'server must persist one-off lessons');
  ok(notify.includes('oneOffLessons'), 'notifications must consider one-off lessons');
});

test('email guard is wired into mail delivery', () => {
  const mailer = fs.readFileSync(path.join(FUN,'lib','mailer.js'),'utf8');
  const guard = fs.readFileSync(path.join(FUN,'lib','email-guard.js'),'utf8');
  ok(mailer.includes("require('./email-guard')") && mailer.includes('checkAndRecord'), 'mailer must use Email Guard');
  ok(guard.includes('EMAIL_SAFE_DAILY_LIMIT') && guard.includes('EMAIL_SAFE_MINUTE_LIMIT'), 'email guard must have configurable limits');
});

test('CSP and uploaded files use browser-side hardening', () => {
  const netlify = fs.readFileSync(path.join(ROOT,'netlify.toml'),'utf8');
  const get = fs.readFileSync(path.join(FUN,'note-files-get.js'),'utf8');
  ok(/X-Content-Type-Options\s*=\s*["']nosniff["']/.test(netlify) || get.includes('X-Content-Type-Options'), 'nosniff must be configured');
  ok(get.includes('Cache-Control') && get.includes('no-store'), 'private files must not be cached');
});

(async()=>{
  let pass=0;
  console.log('TS Розклад Security Test Suite');
  console.log('='.repeat(40));
  for(const t of tests){
    try { await t.fn(); console.log(`PASS  ${t.name}`); pass++; }
    catch(err){ console.error(`FAIL  ${t.name}`); console.error('      '+err.message); process.exitCode=1; }
  }
  console.log('='.repeat(40));
  console.log(`${pass}/${tests.length} tests passed`);
  if(pass !== tests.length){ console.error('SECURITY TEST: FAIL'); process.exit(1); }
  console.log('SECURITY TEST: PASS');
})();
