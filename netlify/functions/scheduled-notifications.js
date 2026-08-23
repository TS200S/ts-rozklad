const { handler } = require('./check-notifications');

exports.handler = async () => {
  return handler({
    httpMethod: 'GET',
    queryStringParameters: { secret: process.env.CRON_SECRET || undefined }
  });
};
