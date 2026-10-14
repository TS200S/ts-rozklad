// Scheduled daily (see netlify.toml): tops up the shared quote pool in advance so
// the app always has fresh quotes with author + source, even if nobody opens the AI chat.
const { store } = require('./lib/store');
const { runRefill } = require('./lib/quotes-refill');

exports.handler = async () => {
  try {
    const result = await runRefill(store(), { maxAuthors: 3 });
    console.log('quotes-refill', JSON.stringify(result));
    return { statusCode: 200, body: JSON.stringify(result) };
  } catch (err) {
    console.error('quotes-refill failed', err?.status || err?.code || err?.message);
    return { statusCode: 500, body: JSON.stringify({ error: 'refill failed' }) };
  }
};
