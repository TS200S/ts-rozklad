# TS Rozklad — security/email update

## Changed existing files
- `index.html` — hidden admin button for non-admins, email setup for old accounts, Ukrainian spam notice, account/IP block overlay, 30-second session checks.
- `admin.html` — full user/session/IP/role/audit management UI.
- `netlify/functions/auth.js` — IP blocking/rate limiting, stronger password bounds, timing-safe hash comparison, session metadata, role in login response.
- `netlify/functions/register.js` — stricter password length, registration/IP/email rate limits, email cooldown, session metadata.
- `netlify/functions/reset.js` — stricter password length, IP/email rate limits and cooldowns.
- `netlify/functions/account-email.js` — IP blocking/rate limiting for email linking.
- `netlify/functions/admin.js` — roles, sessions, device/IP view, session revocation, account/IP bans, timed IP bans, email editing, audit log.
- `netlify/functions/lib/mailer.js` — Ukrainian spam-folder notice in email and email-linking subject/heading.
- `netlify/functions/lib/session.js` — session IP/device/user-agent metadata, cleanup, revocation improvements, banned-account detection.
- `netlify/functions/save-schedule.js` — blocks banned accounts/IPs.
- `netlify/functions/load-schedule.js` — blocks banned accounts/IPs.
- `netlify/functions/save-subscription.js` — blocks banned accounts/IPs.

## New files
- `netlify/functions/lib/security.js` — IP detection, IP bans, rate limiting, device parsing.
- `netlify/functions/session-status.js` — client heartbeat endpoint for immediate ban/IP-block detection.
- `EMAIL-SETUP.md` — Gmail/Netlify setup notes.

## Security behavior
- Passwords remain salted `scrypt` hashes; comparison is timing-safe.
- New/reset passwords: 8–128 characters.
- Login attempts retain the existing 6-failure/15-minute lock.
- Verification emails: 1-minute cooldown, 3 per 15 minutes per email, 5 per hour per IP.
- Registration has an additional 3-per-15-minutes IP limit.
- Account bans revoke all sessions; the browser checks status every 30 seconds and shows a Ukrainian block screen.
- IP bans support 1 hour / 1 day / 7 days / forever.
- Admin can manually ban/unban IPs.
- Admin roles are server-side; `ADMIN_USERNAME` remains the master admin.
- Admin can inspect session count, IP, OS, browser and last activity, and revoke individual/all sessions.
- Admin actions are recorded in an audit log.

Do not commit Gmail passwords or App Passwords to GitHub.


## V5.1.0 — журнал акаунта та додатковий захист

Додано серверний журнал `account-activity:<userId>` (до 1000 подій) без збереження паролів, хешів, salt, токенів або кодів. Адміністратор бачить активні сесії, IP, User-Agent, пристрій, час створення та останню активність, а також історію входів, виходів, email-запитів, змін пароля та банів.

Історія очищається тільки окремою адмін-операцією з подвійним підтвердженням `CLEAR username`. Адмінський аудит залишається окремо.

Додано зміну пароля тільки після перевірки старого пароля; після зміни всі сесії та довірені пристрої завершуються/скидаються.

Додано три налаштування безпеки: лист про новий пристрій, обов'язковий код для нового пристрою та обов'язковий код для кожного нового входу.
