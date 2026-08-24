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
    if (opts && opts.type === 'json') return JSON.parse(JSON.stringify(v));
    return v;
  }
  async setJSON(key, value){ this.map.set(key, JSON.parse(JSON.stringify(value))); }
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
  ok((await s.get(`session:${created.token}`, {type:'json'})) === null, 'rejected session must be revoked');
});

test('session public id is not the raw session token', async () => {
  const token = crypto.randomBytes(32).toString('hex');
  const id = getSessionPublicId(token, {sessionId:'1234567890abcdef'});
  ok(id === '1234567890abcdef', 'public id uses stored opaque id');
  ok(id !== token, 'public id never equals raw token');
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
  for (let i=0;i<1005;i++) await recordActivity(s,'u4','event',{n:i});
  const rows = await listActivity(s,'u4',2000);
  ok(rows.length === 1000, 'exactly 1000 retained');
  ok(rows[0].details.n === 1004, 'newest event first');
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

test('package version is 5.2.11', () => {
  const pkg = require(path.join(ROOT,'package.json'));
  ok(pkg.version === '5.2.11', `expected 5.2.11, got ${pkg.version}`);
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
