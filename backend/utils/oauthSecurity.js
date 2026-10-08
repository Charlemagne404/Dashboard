const crypto = require('crypto');
const AuthChallenge = require('../models/AuthChallenge');

const hash = (value) => crypto.createHash('sha256').update(String(value || '')).digest('hex');
const bindingName = (provider) => process.env.NODE_ENV === 'production'
  ? `__Host-oauthBinding_${provider}` : `oauthBinding_${provider}`;
const newTransaction = async (provider, req, res) => {
  const id = crypto.randomBytes(32).toString('base64url');
  const binding = crypto.randomBytes(32).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  await AuthChallenge.create({
    _id: hash(id), kind: 'oauth', browserHash: hash(binding), verifier, nonce,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  });
  res.cookie(bindingName(provider), binding, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production' || req.secure,
    sameSite: 'lax', path: '/', maxAge: 10 * 60 * 1000,
  });
  return { id, nonce, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
};

const consumeTransaction = async (provider, state, req, res) => {
  const binding = req.cookies?.[bindingName(provider)];
  if (!binding || !state.jti) throw Object.assign(new Error('OAuth browser binding is missing.'), { statusCode: 400 });
  const transaction = await AuthChallenge.findOneAndDelete({
    _id: hash(state.jti), kind: 'oauth', browserHash: hash(binding), expiresAt: { $gt: new Date() },
  }).lean();
  res.clearCookie(bindingName(provider), {
    httpOnly: true, secure: process.env.NODE_ENV === 'production' || req.secure,
    sameSite: 'lax', path: '/',
  });
  if (!transaction) throw Object.assign(new Error('OAuth request expired or already used.'), { statusCode: 400 });
  return transaction;
};

const jwksCache = new Map();
const verifyIdToken = async (config, token, nonce, userInfo, keyResolver) => {
  const { createRemoteJWKSet, jwtVerify } = await import('jose');
  const microsoft = config.provider === 'microsoft';
  const jwksUrl = microsoft
    ? 'https://login.microsoftonline.com/common/discovery/v2.0/keys'
    : 'https://www.googleapis.com/oauth2/v3/certs';
  if (!jwksCache.has(jwksUrl)) jwksCache.set(jwksUrl, createRemoteJWKSet(new URL(jwksUrl), { timeoutDuration: 5000 }));
  const { payload } = await jwtVerify(token, keyResolver || jwksCache.get(jwksUrl), {
    algorithms: ['RS256'], audience: config.clientId,
    ...(!microsoft ? { issuer: ['https://accounts.google.com', 'accounts.google.com'] } : {}),
    requiredClaims: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce'], maxTokenAge: '10m',
  });
  if (microsoft) {
    if (!/^[a-f0-9-]{36}$/i.test(payload.tid || '') ||
        payload.iss !== `https://login.microsoftonline.com/${payload.tid}/v2.0` ||
        (config.tenant && !['common', 'organizations', 'consumers'].includes(config.tenant) && config.tenant !== payload.tid)) {
      throw new Error('Invalid Microsoft token issuer.');
    }
  }
  if (payload.nonce !== nonce || payload.sub !== userInfo.sub ||
      (Array.isArray(payload.aud) && payload.aud.length > 1 && !payload.azp) ||
      (payload.azp && payload.azp !== config.clientId)) {
    throw new Error('Invalid OIDC token binding.');
  }
  return payload;
};

module.exports = { newTransaction, consumeTransaction, verifyIdToken };
