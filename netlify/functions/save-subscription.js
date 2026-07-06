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
    const { subscription, action } = body;

    if (!subscription || !subscription.endpoint) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Немає підписки' }) };
    }

    const s = store();
    const existing = (await s.get('subscriptions', { type: 'json' })) || [];

    let updated;
    if (action === 'unsubscribe') {
      updated = existing.filter(sub => sub.endpoint !== subscription.endpoint);
    } else {
      updated = existing.filter(sub => sub.endpoint !== subscription.endpoint);
      updated.push(subscription);
    }

    await s.setJSON('subscriptions', updated);

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, count: updated.length })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: String(err) }) };
  }
};
