const nodemailer = require('nodemailer');

let transporter = null;
function getTransporter() {
  if (transporter) return transporter;
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) {
    throw new Error('GMAIL_USER / GMAIL_APP_PASSWORD не налаштовані в змінних середовища');
  }
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass }
  });
  return transporter;
}

async function sendCodeEmail(to, code, purpose) {
  const t = getTransporter();
  const isReset = purpose === 'reset';
  const subject = isReset ? 'Відновлення паролю — TS Розклад' : 'Підтвердження email — TS Розклад';
  const heading = isReset ? 'Код для відновлення паролю' : (purpose === 'email' ? 'Підтвердження email' : 'Код підтвердження реєстрації');
  const html = `
    <div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px">
      <h2 style="color:#2563eb;margin:0 0 12px">${heading}</h2>
      <p style="color:#334155">Твій код:</p>
      <div style="font-size:32px;font-weight:900;letter-spacing:6px;background:#f0f4ff;padding:16px;border-radius:12px;text-align:center;color:#1e293b">${code}</div>
      <p style="color:#666;font-size:13px;margin-top:16px">Код дійсний 15 хвилин. Якщо листа немає у «Вхідних», обов’язково перевір папку «Спам» або «Небажана пошта». Якщо це був не ти — просто проігноруй цей лист.</p>
    </div>`;

  await t.sendMail({
    from: `"TS Розклад" <${process.env.GMAIL_USER}>`,
    to,
    subject,
    html
  });
}

module.exports = { sendCodeEmail };
