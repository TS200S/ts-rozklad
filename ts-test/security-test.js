const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const root = path.resolve(__dirname, '..');
let pass = 0, fail = 0;
function check(name, ok, detail='') {
  if (ok) { pass++; console.log(`PASS ${name}${detail ? ` — ${detail}` : ''}`); }
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ''}`); }
}
function read(rel) { return fs.readFileSync(path.join(root, rel), 'utf8'); }

const required = [
  'index.html','admin.html','admin-recovery.html','manifest.json','sw.js','netlify.toml','package.json',
  'icon-192.png','icon-512.png','netlify/functions/lib/store.js','netlify/functions/lib/security.js',
  'netlify/functions/lib/session.js','netlify/functions/lib/email-guard.js','netlify/functions/lib/email-queue.js',
  'netlify/functions/lib/mailer.js','netlify/functions/lib/activity.js','netlify/functions/note-delete.js'
];
for (const rel of required) check(`required:${rel}`, fs.existsSync(path.join(root, rel)));

const fnDir = path.join(root, 'netlify/functions');
const jsFiles = fs.readdirSync(fnDir).filter(x => x.endsWith('.js')).map(x => path.join(fnDir, x));
const libFiles = fs.readdirSync(path.join(fnDir, 'lib')).filter(x => x.endsWith('.js')).map(x => path.join(fnDir, 'lib', x));
for (const f of [...jsFiles, ...libFiles]) {
  const r = cp.spawnSync(process.execPath, ['--check', f], { encoding:'utf8' });
  check(`syntax:${path.relative(root,f)}`, r.status === 0, r.stderr.trim());
}

for (const rel of ['index.html','admin.html','admin-recovery.html','secret.html']) {
  const html = read(rel);
  const matches = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];
  for (let i=0;i<matches.length;i++) {
    const tmp = path.join('/tmp', `tsdaily-${process.pid}-${i}-${path.basename(rel)}.js`);
    fs.writeFileSync(tmp, matches[i][1]);
    const r = cp.spawnSync(process.execPath, ['--check', tmp], { encoding:'utf8' });
    check(`inline-js:${rel}#${i+1}`, r.status === 0, r.stderr.trim());
    try { fs.unlinkSync(tmp); } catch {}
  }
}

const pkg = JSON.parse(read('package.json'));
check('version', pkg.version === '5.3.8', pkg.version);
check('dependencies-pinned', Object.values(pkg.dependencies || {}).every(v => /^\d+\.\d+\.\d+$/.test(v)));
check('nodemailer-supported-major', /^9\./.test(String(pkg.dependencies?.nodemailer || '')));
check('blobs-pinned-current-8x', pkg.dependencies?.['@netlify/blobs'] === '8.1.2');
check('npm-security-test-script', pkg.scripts?.['security:test'] === 'node ts-test/security-test.js');

const netlify = read('netlify.toml');
check('single-scheduled-function', (netlify.match(/^\[functions\./gm) || []).length === 1);
check('scheduled-function-is-cleanup', netlify.includes('[functions."cleanup-bans"]'));
check('no-scheduled-notifications', !netlify.includes('scheduled-notifications'));

const checkCron = read('netlify/functions/check-notifications.js');
check('cron-secret-required', checkCron.includes("if (!CRON_SECRET) return { statusCode: 503"));
check('cron-header-only', !checkCron.includes('queryStringParameters?.secret') && !checkCron.includes('?secret='));
check('vapid-init-inside-handler', checkCron.includes('webpush.setVapidDetails') && checkCron.indexOf('webpush.setVapidDetails') > checkCron.indexOf('exports.handler'));

const session = read('netlify/functions/lib/session.js');
check('session-cookie-host-prefix', session.includes('__Host-ts_session='));
check('session-cookie-http-only', session.includes('HttpOnly'));
check('session-cookie-secure', session.includes('Secure'));
check('session-cookie-samesite', session.includes('SameSite=Lax'));
check('no-bearer-auth', ![read('index.html'), ...jsFiles.map(f=>fs.readFileSync(f,'utf8'))].join('\n').includes('Authorization: Bearer'));

const upload = read('netlify/functions/note-files-upload.js');
check('no-octet-stream-upload', !upload.includes("'application/octet-stream'"));
check('attachment-limit', upload.includes('attachmentCount >= 20') && upload.includes('NOTE_FILE_LIMIT'));
check('file-size-limit', upload.includes('4 * 1024 * 1024'));
check('file-magic-validation', upload.includes('hasMagic(bytes, mime)'));
check('file-private-storage', upload.includes('const blobKey = `file:${sess.userId}:${id}`'));
check('file-delete-origin', read('netlify/functions/note-files-delete.js').includes('isSameOriginRequest(event)'));
check('file-delete-removes-blob', read('netlify/functions/note-files-delete.js').includes('s.delete(meta.blobKey)'));
check('note-delete-removes-blobs', read('netlify/functions/note-delete.js').includes('s.delete(meta.blobKey)'));
check('file-get-owner-check', read('netlify/functions/note-files-get.js').includes('meta.noteId'));
check('file-list-no-blob-key', read('netlify/functions/note-files-list.js').includes('map(({blobKey,...x})=>x)'));

const bannedProtected = ['note-files-upload.js','note-files-delete.js','note-files-get.js','note-files-list.js','email-guard-stats.js','storage-admin.js','security-alerts.js'];
for (const rel of bannedProtected) {
  const s = read(`netlify/functions/${rel}`);
  check(`banned-block:${rel}`, /sess\.banned|sess\?\.banned|!sess\|\|sess\.banned/.test(s));
}

const admin = read('admin.html');
check('admin-audit-tab', admin.includes('function loadAudit()') && !admin.includes('renderAudit()'));
check('admin-ip-tab-safe', admin.includes('renderIps([])'));
check('admin-session-check', admin.includes('/.netlify/functions/session-status'));

const assets = ['icon-192.png','icon-512.png'];
for (const rel of assets) check(`asset:${rel}`, fs.statSync(path.join(root, rel)).size > 100);

const storageDoc = read('STORAGE-SECURITY.md');
check('storage-doc-no-generic-binary', !storageDoc.includes('generic binary'));

const secretScan = [];
for (const rel of required.filter(x => /\.(js|html|md|json|toml)$/.test(x))) {
  const s = read(rel);
  if (/BEGIN [A-Z ]*PRIVATE KEY|AIza[0-9A-Za-z_-]{20,}|\bsk-[A-Za-z0-9]{20,}|\bghp_[A-Za-z0-9]{20,}/.test(s)) secretScan.push(rel);
}
check('secret-pattern-scan', secretScan.length === 0, secretScan.join(', '));

const cleanup = read('netlify/functions/cleanup-bans.js');
check('orphan-cleanup-present', cleanup.includes("prefix: 'file-meta:'") && cleanup.includes('atomicUpdateJSON'));
check('orphan-cleanup-integrated', cleanup.includes('orphanedFiles') && cleanup.includes('orphanGraceMs'));
check('orphan-grace-period', cleanup.includes('60 * 60 * 1000'));
check('sw-cache-matches-release', read('sw.js').includes(`ts-daily-v${pkg.version}-stable`));
check('sw-does-not-cache-api', read('sw.js').includes("url.pathname.startsWith('/.netlify/functions/')"));
check('cron-no-query-secret', !checkCron.includes('queryStringParameters') && !checkCron.includes('?secret='));
check('cron-timing-safe-secret', checkCron.includes('crypto.timingSafeEqual'));
check('upload-no-generic-octet', !upload.includes('application/octet-stream'));
check('upload-cleans-blob-on-failure', upload.includes('await s.delete(blobKey)'));
check('delete-claim-protected', read('netlify/functions/note-files-delete.js').includes('onlyIfNew'));
check('note-delete-concurrency-protected', read('netlify/functions/note-delete.js').includes('NOTE_GONE'));

console.log(`\nSECURITY TEST: ${fail ? 'FAIL' : 'PASS'} — ${pass} PASS · ${fail} FAIL · ${pass+fail} TOTAL`);
process.exit(fail ? 1 : 0);
