const ApiRateLimitBucket = require('../models/ApiRateLimitBucket');
const { getClientIpKey } = require('../utils/clientIp');

const consume = async (key, max, windowMs = 10 * 60 * 1000) => {
  const start = Math.floor(Date.now() / windowMs) * windowMs;
  const filter = { key, windowStart: new Date(start) };
  const update = { $inc: { count: 1 }, $setOnInsert: { expiresAt: new Date(start + windowMs * 2) } };
  let bucket;
  try { bucket = await ApiRateLimitBucket.findOneAndUpdate(filter, update, { upsert: true, new: true }); }
  catch (err) {
    if (err.code !== 11000) throw err;
    bucket = await ApiRateLimitBucket.findOneAndUpdate(filter, update, { new: true });
  }
  return { allowed: bucket.count <= max, retryAfter: Math.max(1, Math.ceil((start + windowMs - Date.now()) / 1000)) };
};

module.exports = async (req, res, next) => {
  if (!['POST', 'PATCH', 'DELETE'].includes(req.method)) return next();
  // Express routing is case-insensitive and accepts trailing slashes.
  const endpoint = req.path.toLowerCase().replace(/\/+$/, '') || '/';
  const expensive = endpoint === '/login' || endpoint === '/register' || endpoint === '/reset-password' ||
    endpoint.startsWith('/mfa/') || endpoint.startsWith('/passkeys/') ||
    req.body?.currentPassword !== undefined || endpoint.startsWith('/owner/');
  if (!expensive) return next();
  const max = endpoint === '/register' ? 10 : endpoint === '/login' ? 40 : 20;
  const dimension = endpoint.startsWith('/owner/') ? '/owner' :
    /^\/passkeys\/[^/]+$/.test(endpoint) ? '/passkeys/remove' : endpoint;
  const result = await consume(`auth-work:ip:${getClientIpKey(req)}:${dimension}`, max);
  if (!result.allowed) {
    res.setHeader('Retry-After', result.retryAfter);
    return res.status(429).json({ message: 'Too many attempts. Retry later.', retryAfterSec: result.retryAfter });
  }
  if (req.body?.currentPassword !== undefined && typeof req.body?.currentPassword !== 'string') {
    return res.status(400).json({ message: 'Current password must be a string.' });
  }
  return next();
};
module.exports.consume = consume;
