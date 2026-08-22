# Email update

This version adds two email-management flows:

1. Old users without an email can add one after logging in.
   - The site sends a 6-digit verification code.
   - The email is saved only after the code is confirmed.
2. Admins can add/change/remove a user's email from `admin.html`.
   - Admin-assigned emails are marked verified.
   - Duplicate emails are rejected.

New registrations continue to require email verification.

## Netlify environment variables

The mailer requires:

- `GMAIL_USER` — the Gmail address used by the site to send mail.
- `GMAIL_APP_PASSWORD` — a Google App Password, not the normal Gmail password.

After replacing the project files in GitHub, let Netlify deploy the `main` branch.

Do not put the Gmail password or App Password in GitHub.
