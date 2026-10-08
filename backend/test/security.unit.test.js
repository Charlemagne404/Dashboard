const test = require('node:test');
const assert = require('node:assert/strict');
const { verifyIdToken } = require('../utils/oauthSecurity');
const { assertRuntimeConfig } = require('../utils/runtimeConfig');
const { scriptJson } = require('../utils/browserSecurity');
const { safeError } = require('../utils/safeLog');

let jose;
let keys;
test.before(async () => {
  jose = await import('jose');
  keys = await jose.generateKeyPair('RS256');
});
const claims = () => ({ iss: 'https://accounts.google.com', aud: 'client-fixture', sub: 'subject-fixture',
  nonce: 'nonce-fixture', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 });
const sign = (payload, key = keys.privateKey) => new jose.SignJWT(payload).setProtectedHeader({ alg: 'RS256' }).sign(key);
const verify = (token, config = { provider: 'google', clientId: 'client-fixture' }) =>
  verifyIdToken(config, token, 'nonce-fixture', { sub: 'subject-fixture' }, keys.publicKey);

test('OIDC accepts a genuinely signed, correctly bound Google ID token', async () => {
  assert.equal((await verify(await sign(claims()))).sub, 'subject-fixture');
});
for (const [name, override] of Object.entries({
  issuer: { iss: 'https://attacker.example' }, audience: { aud: 'another-client' },
  nonce: { nonce: 'other-nonce' }, subject: { sub: 'other-subject' },
  expiry: { exp: 1 }, age: { iat: 1 }, authorizedParty: { azp: 'another-client' },
  multipleAudiencesWithoutAzp: { aud: ['client-fixture', 'another-client'] },
})) {
  test(`OIDC rejects invalid ${name} binding`, async () => {
    await assert.rejects(verify(await sign({ ...claims(), ...override })));
  });
}
test('OIDC rejects another signing key and missing required claims', async () => {
  const rogue = await jose.generateKeyPair('RS256');
  await assert.rejects(verify(await sign(claims(), rogue.privateKey)));
  const payload = claims();
  delete payload.nonce;
  await assert.rejects(verify(await sign(payload)));
});
test('Microsoft OIDC binds the signed tenant to issuer and configured tenant', async () => {
  const tid = '12345678-1234-1234-1234-123456789abc';
  const config = { provider: 'microsoft', clientId: 'client-fixture', tenant: tid };
  const payload = { ...claims(), tid, iss: `https://login.microsoftonline.com/${tid}/v2.0` };
  assert.equal((await verify(await sign(payload), config)).tid, tid);
  await assert.rejects(verify(await sign({ ...payload, iss: 'https://attacker.example' }), config));
  await assert.rejects(verify(await sign(payload), { ...config, tenant: '87654321-1234-1234-1234-123456789abc' }));
});

const productionConfig = () => ({
  NODE_ENV: 'production', MONGO_URI: 'mongodb://127.0.0.1/fixture',
  JWT_SECRET: 'fixture-access-key-12345678901234567890',
  REFRESH_TOKEN_SECRET: 'fixture-refresh-key-12345678901234567890',
  MFA_SECRET_ENCRYPTION_KEY: 'fixture-mfa-key-12345678901234567890',
  ALLOWED_ORIGINS: 'https://login.example.test,https://dashboard.example.test',
  IDENTITY_MANAGEMENT_ORIGINS: 'https://login.example.test,https://dashboard.example.test',
  PUBLIC_API_ORIGIN: 'https://login.example.test', TRUST_PROXY: '1', HTTPS_MODE: 'off',
  RESEND_API_KEY: 'fixture-mail-key', EMAIL_FROM: 'fixture@example.test', LOGIN_POPUP_URL: 'https://login.example.test/popup.html',
});
test('production configuration rejects unsafe origins, shared secrets, proxy trust, callbacks, and lifetime values', () => {
  assert.doesNotThrow(() => assertRuntimeConfig(productionConfig()));
  for (const override of [
    { ALLOWED_ORIGINS: '*' }, { ALLOW_DEFAULT_TRUSTED_ORIGINS: 'true' }, { ALLOW_LOCALHOST_ORIGINS: 'true' },
    { JWT_SECRET: 'short' }, { MFA_SECRET_ENCRYPTION_KEY: productionConfig().JWT_SECRET },
    { TRUST_PROXY: 'true' }, { HTTPS_MODE: 'auto', TRUST_PROXY: 'false' },
    { HTTPS_MODE: '0', TRUST_PROXY: 'false' }, { IDENTITY_MANAGEMENT_ORIGINS: 'https://attacker.example' },
    { JWT_EXPIRES_IN: '15000' }, { JWT_EXPIRES_IN: '2h' }, { SESSION_IDLE_TTL_MS: '-1' },
    { RESEND_API_KEY: '' }, { LOGIN_POPUP_URL: 'http://login.example.test/popup.html' },
    { GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret', GITHUB_OAUTH_CALLBACK_URL: 'https://attacker.example/callback' },
  ]) assert.throws(() => assertRuntimeConfig({ ...productionConfig(), ...override }));
});
test('production configuration requires a canonical callback for every configured OAuth provider', () => {
  const base = {
    ...productionConfig(),
    GOOGLE_CLIENT_ID: 'google-client',
    GOOGLE_CLIENT_SECRET: 'google-secret',
    GOOGLE_OAUTH_CALLBACK_URL: 'https://login.example.test/api/auth/oauth/google/callback',
  };
  assert.doesNotThrow(() => assertRuntimeConfig(base));
  assert.throws(() => assertRuntimeConfig({ ...base, GOOGLE_OAUTH_CALLBACK_URL: '' }));
  assert.throws(() => assertRuntimeConfig({
    ...base,
    GOOGLE_OAUTH_CALLBACK_URL: 'https://auth.example.test/api/auth/oauth/google/callback',
  }));
});
test('inline callback JSON cannot terminate its script and logs exclude secret-bearing errors', () => {
  const payload = { displayName: '</script><script>steal()</script>&\u2028' };
  assert.doesNotMatch(scriptJson(payload), /<|>|&|\u2028/);
  assert.deepEqual(JSON.parse(scriptJson(payload)), payload);
  const err = Object.assign(new Error('password=secret raw-session-token'), { name: 'MongoServerError', code: 11000, body: 'secret' });
  assert.deepEqual(safeError(err), { name: 'MongoServerError', code: 11000 });
});
test('email transport uses a fixed provider, bounded cancellation, no redirects, and sanitized failures', async () => {
  const saved = { NODE_ENV: process.env.NODE_ENV, RESEND_API_KEY: process.env.RESEND_API_KEY, EMAIL_FROM: process.env.EMAIL_FROM };
  const originalFetch = global.fetch;
  Object.assign(process.env, { NODE_ENV: 'development', RESEND_API_KEY: 'fixture-not-live', EMAIL_FROM: 'fixture@example.test' });
  let calls = 0;
  global.fetch = async (url, options) => {
    calls += 1;
    assert.equal(url, 'https://api.resend.com/emails');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    throw new Error('raw provider secret');
  };
  try {
    await assert.rejects(require('../utils/email')({ to: 'recipient@example.test', subject: 'Fixture', html: '<p>Fixture</p>' }),
      (err) => err.message === 'Email provider request failed.' && !err.cause);
    assert.equal(calls, 1);
  } finally {
    global.fetch = originalFetch;
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});
