const { getStore } = require('@netlify/blobs');

function store() {
  return getStore({
    name: 'ts-app',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const { userId, schedule, subjects, cfg, notes } = body;

    if (!userId) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає userId' }) };
    }
    if (!schedule || !subjects) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає даних розкладу' }) };
    }

    const s = store();
    await s.setJSON(`schedule-data:${userId}`, {
      schedule,
      subjects,
      notes: notes || [],
      notif10: cfg?.notif10 !== false,
      notif5: cfg?.notif5 !== false,
      updatedAt: Date.now()
    });

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
