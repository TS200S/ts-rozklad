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
  const subject = isReset ? 'Відновлення паролю — TS_Daily' : 'Підтвердження email — TS_Daily';
  const heading = isReset ? 'Код для відновлення паролю' : (purpose === 'email' ? 'Підтвердження email' : 'Код підтвердження реєстрації');
  const html = `
    <div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px">
      <div style="font-size:11px;font-weight:900;letter-spacing:2px;color:#64748b;margin-bottom:8px">TS_Daily</div><h2 style="color:#2563eb;margin:0 0 12px">${heading}</h2>
      <p style="color:#334155">Твій код:</p>
      <div style="font-size:32px;font-weight:900;letter-spacing:6px;background:#f0f4ff;padding:16px;border-radius:12px;text-align:center;color:#1e293b">${code}</div>
      <p style="color:#666;font-size:13px;margin-top:16px">Код дійсний 15 хвилин. Якщо листа немає у «Вхідних», обов’язково перевір папку «Спам» або «Небажана пошта». Якщо це був не ти — просто проігноруй цей лист.</p>
    </div>`;

  await t.sendMail({
    from: `"TS_Daily" <${process.env.GMAIL_USER}>`,
    to,
    subject,
    html
  });
}

async function sendLoginCodeEmail(to, code) {
  const t = getTransporter();
  const html = `
    <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px">
      <div style="font-size:11px;font-weight:900;letter-spacing:2px;color:#64748b;margin-bottom:8px">TS_Daily</div>
      <h2 style="color:#2563eb;margin:0 0 12px">Підтвердження нового входу</h2>
      <p style="color:#334155">Хтось виконує вхід до твого акаунта TS_Daily з нового пристрою або сесії.</p>
      <p style="color:#334155">Якщо це ти, введи код:</p>
      <div style="font-size:32px;font-weight:900;letter-spacing:6px;background:#f0f4ff;padding:16px;border-radius:12px;text-align:center;color:#1e293b">${code}</div>
      <p style="color:#666;font-size:13px;margin-top:16px">Код дійсний 15 хвилин. Якщо це був не ти — не вводь код і зміни пароль.</p>
    </div>`;
  await t.sendMail({ from: `"TS_Daily" <${process.env.GMAIL_USER}>`, to, subject: 'Підтвердження нового входу — TS_Daily', html });
}

async function sendNewDeviceAlertEmail(to, info = {}) {
  const t = getTransporter();
  const html = `
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px">
      <div style="font-size:11px;font-weight:900;letter-spacing:2px;color:#64748b;margin-bottom:8px">TS_Daily · БЕЗПЕКА</div>
      <h2 style="color:#2563eb;margin:0 0 12px">Новий вхід до акаунта</h2>
      <p style="color:#334155">До твого акаунта TS_Daily виконано вхід з нового пристрою або сесії.</p>
      <div style="background:#f8fafc;border-radius:12px;padding:14px;color:#334155;font-size:13px;line-height:1.7">
        <b>Пристрій:</b> ${String(info.device || 'Невідомий').replace(/[<>]/g,'')}<br>
        <b>IP:</b> ${String(info.ip || 'Невідомий').replace(/[<>]/g,'')}<br>
        <b>Час:</b> ${new Date(info.at || Date.now()).toLocaleString('uk-UA')}
      </div>
      <p style="color:#666;font-size:13px;margin-top:16px">Якщо це були не ви, негайно змініть пароль і завершіть підозрілі сесії в налаштуваннях безпеки.</p>
    </div>`;
  await t.sendMail({ from: `"TS_Daily" <${process.env.GMAIL_USER}>`, to, subject: 'Новий вхід до акаунта — TS_Daily', html });
}

async function sendAdminRecoveryEmail(to, code) {
  const t = getTransporter();
  const html = `
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px">
      <div style="font-size:11px;font-weight:900;letter-spacing:2px;color:#64748b;margin-bottom:8px">TS_Daily · АДМІНІСТРАЦІЯ</div>
      <h2 style="color:#2563eb;margin:0 0 12px">Оновлення пошти для відновлення акаунта</h2>
      <p style="color:#334155">Адміністратор TS_Daily вказав цю адресу електронної пошти для відновлення акаунта.</p>
      <p style="color:#334155">Якщо ви зверталися до адміністрації щодо відновлення акаунта, передайте адміністратору код підтвердження нижче:</p>
      <div style="font-size:32px;font-weight:900;letter-spacing:6px;background:#f0f4ff;padding:16px;border-radius:12px;text-align:center;color:#1e293b">${code}</div>
      <p style="color:#666;font-size:13px;margin-top:16px">Якщо ви не зверталися до адміністрації щодо відновлення акаунта — проігноруйте цей лист.</p>
    </div>`;
  await t.sendMail({ from: `"TS_Daily" <${process.env.GMAIL_USER}>`, to, subject: 'Оновлення пошти для відновлення акаунта — TS_Daily', html });
}


async function sendAdmin2FACodeEmail(to, code, purpose = 'critical') {
  const t = getTransporter();
  const title = purpose === 'setup' ? 'Налаштування паролю адмінки' : 'Підтвердження критичної дії';
  const text = purpose === 'setup'
    ? 'Для завершення налаштування окремого паролю адмінки введи код нижче.'
    : 'Для виконання критичної дії в адмін-панелі введи код нижче.';
  const html = `
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px">
      <div style="font-size:11px;font-weight:900;letter-spacing:2px;color:#64748b;margin-bottom:8px">TS_Daily · АДМІНІСТРАЦІЯ</div>
      <h2 style="color:#2563eb;margin:0 0 12px">${title}</h2>
      <p style="color:#334155">${text}</p>
      <div style="font-size:32px;font-weight:900;letter-spacing:6px;background:#f0f4ff;padding:16px;border-radius:12px;text-align:center;color:#1e293b">${code}</div>
      <p style="color:#666;font-size:13px;margin-top:16px">Код дійсний 10 хвилин. Не передавай цей код іншим особам. Якщо ти не виконував цю дію — проігноруй лист і перевір безпеку адмінського акаунта.</p>
    </div>`;
  await t.sendMail({ from: `"TS_Daily" <${process.env.GMAIL_USER}>`, to, subject: `${title} — TS_Daily`, html });
}


async function sendAdminEmergencyRecoveryEmail(to, code) {
  const t = getTransporter();
  const html = `
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px">
      <div style="font-size:11px;font-weight:900;letter-spacing:2px;color:#64748b;margin-bottom:8px">TS_Daily · АДМІНІСТРАЦІЯ</div>
      <h2 style="color:#2563eb;margin:0 0 12px">Аварійне відновлення паролю адмінки</h2>
      <p style="color:#334155">Було запрошено аварійне відновлення окремого паролю адміністратора TS_Daily.</p>
      <p style="color:#334155">Якщо це ви, введіть код нижче на сторінці відновлення:</p>
      <div style="font-size:32px;font-weight:900;letter-spacing:6px;background:#f0f4ff;padding:16px;border-radius:12px;text-align:center;color:#1e293b">${code}</div>
      <p style="color:#666;font-size:13px;margin-top:16px">Код дійсний 10 хвилин і одноразовий. Якщо ви не запитували відновлення — проігноруйте цей лист та перевірте безпеку акаунта.</p>
    </div>`;
  await t.sendMail({ from: `"TS_Daily" <${process.env.GMAIL_USER}>`, to, subject: 'Аварійне відновлення паролю адмінки — TS_Daily', html });
}

module.exports = { sendCodeEmail, sendLoginCodeEmail, sendNewDeviceAlertEmail, sendAdminRecoveryEmail, sendAdmin2FACodeEmail, sendAdminEmergencyRecoveryEmail };
