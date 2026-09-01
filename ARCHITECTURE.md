# TS_Daily V5.3.9 — Architecture & Logic Map

## Request flow

Browser/PWA → Netlify Function → session/security middleware → domain logic → Netlify Blobs / email / push → JSON response → UI.

## Main domains

- **Auth:** register → email verification → login → optional login verification → session cookie + device binding → logout/reset/password change.
- **Schedule:** `load-schedule` reads per-user `schedule-data:<userId>`; `save-schedule` validates/sanitizes and uses optimistic concurrency with conditional Blob writes.
- **Notes:** notes live inside the per-user schedule document. File metadata is stored in `file-meta:<userId>` and binary files in `file:<userId>:<fileId>`.
- **Files:** upload validates ownership, size, MIME and magic bytes; writes blob + metadata + attachment reference; failures clean up the blob. Get/list/delete verify ownership.
- **Email:** mailer → email guard → queue/dedupe → Gmail transport.
- **Push:** browser Service Worker + VAPID subscription → `save-subscription`; notifications are triggered by `check-notifications`.
- **Cron:** cron-job.org calls `check-notifications` with `X-Cron-Secret`. `cleanup-bans` is the only Netlify scheduled function.
- **Admin:** `admin.html` → `admin` function → privileged operations; `security-alerts`, `storage-admin`, `email-guard-stats`, and `system-diagnostics` provide read/diagnostic views.
- **Security:** HttpOnly/Secure/SameSite session cookie, device binding, Origin check, IP bans/rate limits, 2FA/step-up, audit log, security alerts.

## Storage keys

- `user:<username>` — account record
- `email:<email>` — email → username index
- `session:<hash>` — active session
- `user-sessions:<userId>` — session index
- `schedule-data:<userId>` — schedule, subjects, notes, one-off lessons and notification settings
- `file-meta:<userId>` — attachment metadata and quota accounting
- `file:<userId>:<fileId>` — private binary blob
- `audit-log` / `audit-anchor` — admin audit chain
- `ip-ban:<ip>` — IP ban state
- `email-*` — queue, dedupe, claims and guard state

## Self-diagnostics

The admin **🧪 Самодіагностика системи** runs non-destructive checks: runtime, required environment configuration, function-module loading, real Netlify Blobs write/read/conditional-write/delete, current user's schedule shape, and returns PASS/WARN/FAIL plus a request ID. It never returns secret values.

## Error handling rule

A production error should identify the failing subsystem and return a request ID to the admin UI. User-facing responses remain generic; internal logs contain only the request ID and safe error code/name.

## Function dependency map

- `netlify/functions/account-email.js` → `./lib/store`, `./lib/session`, `./lib/mailer`, `./lib/security`, `./lib/activity`
- `netlify/functions/admin.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/activity`, `./lib/mailer`, `./lib/security`, `./lib/security`, `./lib/security`, `./lib/security`, `./lib/security`, `./lib/security`, `./lib/security`
- `netlify/functions/auth.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/mailer`, `./lib/activity`, `./lib/security`, `./lib/security`
- `netlify/functions/change-password.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/activity`
- `netlify/functions/check-notifications.js` → `./lib/email-queue`, `./lib/store`
- `netlify/functions/cleanup-bans.js` → `./lib/store`, `./lib/store`
- `netlify/functions/email-guard-stats.js` → `./lib/store`, `./lib/email-guard`, `./lib/email-queue`, `./lib/session`
- `netlify/functions/load-schedule.js` → `./lib/store`, `./lib/session`, `./lib/security`
- `netlify/functions/logout.js` → `./lib/store`, `./lib/security`, `./lib/session`
- `netlify/functions/note-delete.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/activity`
- `netlify/functions/note-files-delete.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/activity`
- `netlify/functions/note-files-get.js` → `./lib/store`, `./lib/session`
- `netlify/functions/note-files-list.js` → `./lib/store`, `./lib/session`
- `netlify/functions/note-files-upload.js` → `./lib/store`, `./lib/session`, `./lib/security`
- `netlify/functions/register.js` → `./lib/store`, `./lib/session`, `./lib/mailer`, `./lib/security`, `./lib/activity`
- `netlify/functions/reset.js` → `./lib/store`, `./lib/session`, `./lib/mailer`, `./lib/security`, `./lib/activity`
- `netlify/functions/save-schedule.js` → `./lib/store`, `./lib/session`, `./lib/security`
- `netlify/functions/save-subscription.js` → `./lib/store`, `./lib/session`, `./lib/security`
- `netlify/functions/security-alerts.js` → `./lib/store`, `./lib/session`
- `netlify/functions/session-management.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/activity`
- `netlify/functions/session-status.js` → `./lib/store`, `./lib/session`, `./lib/security`
- `netlify/functions/storage-admin.js` → `./lib/store`, `./lib/session`
- `netlify/functions/system-diagnostics.js` → `./lib/store`, `./lib/session`, `./lib/security`
- `netlify/functions/update-security.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/activity`
- `netlify/functions/verify-login.js` → `./lib/store`, `./lib/session`, `./lib/security`, `./lib/mailer`, `./lib/activity`

## File flow
Large files: init → 3 MB chunks → finalize → magic-byte validation → final Blob. Maximum file size: 25 MB. Abandoned uploads expire after 2 hours and are cleaned by cleanup-bans.
