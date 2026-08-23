// Kept as a separate function for deployments that prefer a dedicated endpoint.
// The admin panel currently uses the action-based endpoint in admin.js.
exports.handler = async () => ({ statusCode: 410, body: JSON.stringify({ error: 'Використовуй admin action reauth-admin' }) });
