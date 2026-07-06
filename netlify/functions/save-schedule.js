const { getStore } = require('@netlify/blobs');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const { schedule, subjects, cfg } = body;

    if (!schedule || !subjects) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає даних розкладу' }) };
    }

    const store = getStore('ts-app');
    await store.setJSON('schedule-data', {
      schedule,
      subjects,
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
