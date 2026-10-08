const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const mongoose = require('mongoose');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { MongoMemoryServer } = require('mongodb-memory-server');

Object.assign(process.env, {
  NODE_ENV: 'test', APP_NAME: 'continental-security-test',
  MONGO_URI: 'mongodb://127.0.0.1:27017/unused_security_fixture',
  JWT_SECRET: 'fixture-access-secret-12345678901234567890',
  REFRESH_TOKEN_SECRET: 'fixture-refresh-secret-12345678901234567890',
  MFA_SECRET_ENCRYPTION_KEY: 'fixture-mfa-secret-12345678901234567890',
  TRUST_PROXY: '1', ALLOW_DEFAULT_TRUSTED_ORIGINS: 'true',
  GITHUB_CLIENT_ID: 'fixture-client', GITHUB_CLIENT_SECRET: 'fixture-secret',
  GITHUB_OAUTH_CALLBACK_URL: 'http://localhost/api/auth/oauth/github/callback',
});
const { app, runStartupMaintenance } = require('../server');
const User = require('../models/User');
const AuthChallenge = require('../models/AuthChallenge');
const LoginThrottle = require('../models/LoginThrottle');
const ApiRateLimitBucket = require('../models/ApiRateLimitBucket');
const {
  decryptMfaSecret,
  hashBackupCodeForStorage,
  encryptMfaSecret,
  verifyStoredBackupCodeHash,
} = require('../utils/securityHardening');
const { generateMfaSecret, totp } = require('../utils/mfa');
const { signTypedJwt, ACCESS_TOKEN_AUDIENCE } = require('../utils/tokenHardening');
const ORIGIN = 'http://localhost:3000';
const APP_ORIGIN = 'https://grimoire.continental-hub.com';
const PASSWORD = 'StrongPass1';
const hash = (v) => crypto.createHash('sha256').update(v).digest('hex');
const cookie = (r, name = 'refreshToken') => r.headers['set-cookie']?.find((v) => v.startsWith(`${name}=`))?.split(';')[0] || '';
const createUser = (extra = {}) => User.create({ email: 'fixture@example.test', username: 'fixture.user',
  password: PASSWORD, displayName: 'Fixture User', isVerified: true, ...extra });
const login = (extra = {}, origin = ORIGIN, ip = '192.0.2.1') => request(app).post('/api/auth/login')
  .set('Origin', origin).set('X-Forwarded-For', ip).send({ identifier: 'fixture.user', password: PASSWORD, ...extra });
const refresh = (c, origin = ORIGIN, extra = {}) => request(app).post('/api/auth/refresh_token')
  .set('Origin', origin).set('Cookie', c).send(extra);
const me = (token) => request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
let db;
let originalFetch;

test.before(async () => {
  originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('External network access forbidden in security tests.'); };
  db = await MongoMemoryServer.create();
  await mongoose.connect(db.getUri());
});
test.beforeEach(async () => {
  await mongoose.connection.db.dropDatabase();
  await Promise.all([User.createIndexes(), AuthChallenge.createIndexes(), LoginThrottle.createIndexes(), ApiRateLimitBucket.createIndexes()]);
});
test.after(async () => { global.fetch = originalFetch; await mongoose.disconnect(); await db.stop(); });

test('registration input cannot grant privileges and configured owner emails do not re-grant roles', async () => {
  process.env.OWNER_EMAILS = 'fixture@example.test';
  try {
    const result = await request(app).post('/api/auth/register').set('Origin', ORIGIN).send({
      email: 'fixture@example.test', username: 'fixture.user', password: PASSWORD,
      accountRole: 'owner', accountStatus: 'active', isVerified: true, authority: { role: 'owner' },
    });
    assert.equal(result.status, 201);
    const user = await User.findOne({ username: 'fixture.user' });
    assert.equal(user.accountRole, 'user');
    assert.equal(user.isVerified, false);
    user.isVerified = true;
    await user.save();
    const signedIn = await login();
    assert.equal(signedIn.status, 200);
    assert.equal((await User.findById(user._id)).accountRole, 'user');
    assert.equal((await request(app).get('/api/auth/owner/users').set('Authorization', `Bearer ${signedIn.body.token}`)).status, 403);
  } finally { delete process.env.OWNER_EMAILS; }
});

test('application tokens and refresh cookies cannot acquire account-management scope', async () => {
  await createUser({ accountRole: 'owner' });
  const signedIn = await login({ targetOrigin: 'https://dashboard.continental-hub.com' }, APP_ORIGIN);
  assert.equal(signedIn.status, 200);
  assert.equal(jwt.decode(signedIn.body.token).identityManagement, false);
  assert.equal(signedIn.body.user.security, undefined);
  const token = signedIn.body.token;
  for (const path of ['/owner/users', '/security', '/export', '/sessions']) {
    assert.equal((await request(app).get(`/api/auth${path}`).set('Authorization', `Bearer ${token}`)).status, 403);
  }
  const renewed = await refresh(cookie(signedIn), ORIGIN, { targetOrigin: 'https://dashboard.continental-hub.com' });
  assert.equal(renewed.body.authenticated, true);
  assert.equal(jwt.decode(renewed.body.token).identityManagement, false);
  const identity = (await me(token)).body.user;
  assert.equal(identity.lastLoginIp, undefined);
  assert.equal(identity.authority, undefined);
  assert.equal(identity.auditEvents, undefined);
});

test('dashboard cookie refresh from another app remains scoped to that app', async () => {
  await createUser({ accountRole: 'owner' });
  const signedIn = await login();
  assert.equal(jwt.decode(signedIn.body.token).identityManagement, true);
  const renewed = await refresh(cookie(signedIn), APP_ORIGIN, { targetOrigin: ORIGIN });
  assert.equal(renewed.body.authenticated, true);
  assert.equal(jwt.decode(renewed.body.token).identityManagement, false);
});

test('bootstrap rejects CSRF and hands apps a token without management privileges', async () => {
  await createUser();
  const signedIn = await login();
  const csrf = await request(app).post('/api/auth/bootstrap').set('Cookie', cookie(signedIn)).send({ appId: 'grimoire' });
  assert.equal(csrf.status, 403);
  const handedOff = await request(app).post('/api/auth/bootstrap').set('Origin', ORIGIN)
    .send({ appId: 'grimoire', accessToken: signedIn.body.token });
  assert.equal(handedOff.status, 200);
  assert.equal(jwt.decode(handedOff.body.token).identityManagement, false);
  assert.equal(handedOff.body.user.lastLoginIp, undefined);
});

test('refresh cookie is HttpOnly and host-only; logout invalidates the bearer token', async () => {
  await createUser();
  const signedIn = await login({}, APP_ORIGIN);
  const value = signedIn.headers['set-cookie'].find((v) => v.startsWith('refreshToken='));
  assert.match(value, /HttpOnly/);
  assert.doesNotMatch(value, /Domain=/);
  const result = await request(app).post('/api/auth/logout').set('Origin', APP_ORIGIN).set('Cookie', cookie(signedIn)).send({});
  assert.equal(result.status, 200);
  assert.equal((await me(signedIn.body.token)).status, 401);
  assert.equal((await refresh(cookie(signedIn), APP_ORIGIN)).body.authenticated, false);
});

test('concurrent refreshes converge on one current token without losing the session', async () => {
  const user = await createUser();
  const signedIn = await login();
  const results = await Promise.all(Array.from({ length: 8 }, () => refresh(cookie(signedIn))));
  assert.ok(results.every((r) => r.status === 200 && r.body.authenticated));
  assert.equal(new Set(results.map((r) => jwt.decode(decodeURIComponent(cookie(r).split('=')[1])).jti)).size, 1);
  assert.equal((await User.findById(user._id)).refreshSessions.length, 1);
  assert.equal((await me(results[0].body.token)).status, 200);
});

test('stale account snapshots cannot restore revoked sessions or overwrite new passwords', async () => {
  const user = await createUser();
  const signedIn = await login();
  const stale = await User.findById(user._id);
  const fresh = await User.findById(user._id);
  fresh.password = 'NewStrongPass2';
  await fresh.save();
  stale.displayName = 'Stale overwrite';
  await assert.rejects(stale.save(), { name: 'VersionError' });
  const stored = await User.findById(user._id);
  assert.equal(stored.refreshSessions.length, 0);
  assert.equal(await stored.comparePassword('NewStrongPass2'), true);
  assert.equal((await me(signedIn.body.token)).status, 401);
});

for (const property of ['accountRole', 'accountStatus', 'isVerified']) {
  test(`${property} changes revoke existing access and refresh tokens`, async () => {
    const user = await createUser();
    const signedIn = await login();
    const target = await User.findById(user._id);
    target[property] = property === 'accountRole' ? 'owner' : property === 'accountStatus' ? 'suspended' : false;
    await target.save();
    assert.equal(target.refreshSessions.length, 0);
    assert.ok([401, 403].includes((await me(signedIn.body.token)).status));
    assert.equal((await refresh(cookie(signedIn))).body.authenticated, false);
  });
}

for (const type of ['absolute', 'idle']) {
  test(`server enforces ${type} expiration even when the JWT has not expired`, async () => {
    const user = await createUser();
    const signedIn = await login();
    const field = type === 'absolute' ? 'createdAt' : 'lastUsedAt';
    await User.updateOne({ _id: user._id }, { $set: { [`refreshSessions.0.${field}`]: new Date(Date.now() - 8 * 86400000) } });
    assert.equal((await me(signedIn.body.token)).status, 401);
    assert.equal((await refresh(cookie(signedIn))).body.authenticated, false);
  });
}

test('sessionless, legacy, wrong-type, and unbounded tokens cannot authenticate', async () => {
  const user = await createUser();
  const claims = { userId: String(user._id), tokenVersion: 0 };
  const tokens = [
    jwt.sign(claims, process.env.JWT_SECRET, { expiresIn: '1h' }),
    signTypedJwt({ secret: process.env.JWT_SECRET, payload: claims, expiresIn: '1h', audience: ACCESS_TOKEN_AUDIENCE, type: 'access_token' }),
    signTypedJwt({ secret: process.env.JWT_SECRET, payload: { ...claims, sid: 'invalid' }, audience: ACCESS_TOKEN_AUDIENCE, type: 'access_token' }),
    signTypedJwt({ secret: process.env.JWT_SECRET, payload: claims, expiresIn: '1h', audience: ACCESS_TOKEN_AUDIENCE, type: 'oauth_state' }),
  ];
  for (const token of tokens) assert.equal((await me(token)).status, 401);
});

test('password reset is single-use under concurrency and revokes existing sessions', async () => {
  const user = await createUser();
  const signedIn = await login();
  const raw = crypto.randomBytes(32).toString('hex');
  await User.updateOne({ _id: user._id }, { $set: { passwordResetToken: hash(raw), passwordResetTokenExpires: new Date(Date.now() + 60000) } });
  const results = await Promise.all(['FirstStrongPass2', 'SecondStrongPass3'].map((password) =>
    request(app).post('/api/auth/reset-password').set('Origin', ORIGIN).send({ token: raw, newPassword: password })));
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
  assert.equal((await User.findById(user._id)).passwordResetToken, '');
  assert.equal((await me(signedIn.body.token)).status, 401);
  const replay = await request(app).post('/api/auth/reset-password').set('Origin', ORIGIN).send({ token: raw, newPassword: 'ThirdStrongPass4' });
  assert.equal(replay.status, 400);
});

test('verification is single-use under concurrency and cannot confirm a replaced email token', async () => {
  const raw = crypto.randomBytes(32).toString('hex');
  const user = await createUser({ isVerified: false, verificationToken: hash(raw), verificationTokenExpires: new Date(Date.now() + 60000) });
  const results = await Promise.all([1, 2].map(() => request(app).get('/api/auth/verify-email').query({ token: raw })));
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
  assert.equal((await User.findById(user._id)).isVerified, true);
  assert.equal((await request(app).get('/api/auth/verify-email').query({ token: raw })).status, 400);
});

test('MFA encryption failure never downgrades authentication to password-only', async () => {
  await createUser({ security: { mfa: { enabled: true, secret: 'enc:broken.payload.secret' } } });
  const result = await login({ mfaCode: '123456' });
  assert.equal(result.status, 401);
  assert.equal(result.body.mfaRequired, true);
  assert.equal(result.body.accessToken, undefined);
});

test('adding a dedicated MFA key preserves MFA secrets and backup codes encrypted with the legacy key', () => {
  const keyNames = ['MFA_SECRET_ENCRYPTION_KEY', 'BACKUP_CODE_SECRET', 'REFRESH_TOKEN_SECRET', 'JWT_SECRET'];
  const saved = Object.fromEntries(keyNames.map((name) => [name, process.env[name]]));
  try {
    delete process.env.MFA_SECRET_ENCRYPTION_KEY;
    delete process.env.BACKUP_CODE_SECRET;
    process.env.REFRESH_TOKEN_SECRET = 'legacy-refresh-encryption-key-0123456789';
    process.env.JWT_SECRET = 'legacy-access-signing-key-0123456789';

    const mfaSecret = generateMfaSecret();
    const encryptedMfaSecret = encryptMfaSecret(mfaSecret);
    const backupCode = 'F00D-CAFE-1234-BEEF';
    const encryptedBackupCode = hashBackupCodeForStorage(backupCode);

    process.env.MFA_SECRET_ENCRYPTION_KEY = 'dedicated-mfa-encryption-key-abcdefghij';

    assert.equal(decryptMfaSecret(encryptedMfaSecret), mfaSecret);
    assert.equal(verifyStoredBackupCodeHash(encryptedBackupCode, backupCode), true);

    const newlyEncryptedMfaSecret = encryptMfaSecret(mfaSecret);
    const newlyEncryptedBackupCode = hashBackupCodeForStorage(backupCode);
    assert.equal(decryptMfaSecret(newlyEncryptedMfaSecret), mfaSecret);
    assert.equal(verifyStoredBackupCodeHash(newlyEncryptedBackupCode, backupCode), true);
  } finally {
    for (const name of keyNames) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  }
});

test('MFA backup codes are consumed exactly once across simultaneous logins', async () => {
  const backupCode = 'ABCD-EF01-2345-6789';
  const user = await createUser({ security: { mfa: { enabled: true, secret: encryptMfaSecret(generateMfaSecret()),
    backupCodes: [hashBackupCodeForStorage(backupCode)] } } });
  const results = await Promise.all([login({ backupCode }), login({ backupCode })]);
  assert.equal(results.filter((r) => r.body.authenticated).length, 1);
  assert.equal((await User.findById(user._id)).security.mfa.backupCodes.length, 0);
  assert.equal((await login({ backupCode })).body.authenticated, false);
  assert.ok(!(await User.findById(user._id)).auditEvents.some((e) => JSON.stringify(e).includes(backupCode)));
});

test('TOTP codes cannot be replayed after successful authentication', async () => {
  const secret = generateMfaSecret();
  await createUser({ security: { mfa: { enabled: true, secret: encryptMfaSecret(secret) } } });
  const code = totp({ secret });
  assert.equal((await login({ mfaCode: code })).body.authenticated, true);
  const replay = await login({ mfaCode: code });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.authenticated, false);
});

test('password UTF-8 byte bounds prevent bcrypt truncation collisions and existing hashes rehash', async () => {
  const user = await createUser();
  for (const password of ['Aa1' + 'x'.repeat(70), 'Aa1' + '🙂'.repeat(18), PASSWORD + '\0']) {
    const result = await request(app).post('/api/auth/register').set('Origin', ORIGIN)
      .send({ email: 'another@example.test', username: 'another.user', password });
    assert.equal(result.status, 400);
    assert.equal(await user.comparePassword(password), false);
  }
  await User.updateOne({ _id: user._id }, { $set: { password: await bcrypt.hash(PASSWORD, 10) } });
  assert.equal((await login()).status, 200);
  assert.equal(bcrypt.getRounds((await User.findById(user._id)).password), 12);
});

test('generic recovery responses resist enumeration when mail delivery fails', async () => {
  const user = await createUser();
  const known = await request(app).post('/api/auth/request-password-reset').set('Origin', ORIGIN).send({ identifier: user.email });
  const unknown = await request(app).post('/api/auth/request-password-reset').set('Origin', ORIGIN).send({ identifier: 'missing@example.test' });
  assert.equal(known.status, unknown.status);
  assert.deepEqual(known.body, unknown.body);
  const stored = await User.findById(user._id);
  assert.match(stored.passwordResetToken, /^[a-f0-9]{64}$/);
  assert.equal(stored.isVerified, true);
  assert.equal(stored.refreshTokenVersion, user.refreshTokenVersion);
});

test('login failures remain uniform and an attacker IP cannot lock out a correct login from another IP', async () => {
  await createUser();
  const missing = await login({ identifier: 'missing.user', password: 'WrongPass1' });
  const wrong = await login({ password: 'WrongPass1' });
  assert.equal(missing.status, wrong.status);
  assert.equal(missing.body.error.code, wrong.body.error.code);
  assert.equal(missing.body.message, wrong.body.message);
  for (let i = 0; i < 8; i += 1) await login({ password: 'WrongPass1' });
  assert.equal((await login()).status, 429);
  assert.equal((await login({}, ORIGIN, '192.0.2.2')).status, 200);
});

test('concurrent login failures are counted atomically and IPv6 address rotation cannot bypass limits', async () => {
  const ips = ['2001:db8:1:2::1', '2001:db8:1:2::abcd'];
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => login({ identifier: 'missing.user', password: 'WrongPass1' }, ORIGIN, ips[i % 2])));
  assert.ok(results.every((r) => r.status === 400));
  const bucket = await LoginThrottle.findOne({ key: 'login:ip:20010db800010002/64' });
  assert.equal(bucket.count, 8);
  assert.equal((await login({ identifier: 'missing.user' }, ORIGIN, '2001:db8:1:2::9999')).status, 429);
});

test('successful authentication cannot reset the IP credential-stuffing budget', async () => {
  await createUser();
  for (let i = 0; i < 7; i += 1) assert.equal((await login({ identifier: `missing.${i}`, password: 'WrongPass1' })).status, 400);
  assert.equal((await login()).status, 200);
  assert.equal((await LoginThrottle.findOne({ key: 'login:ip:192.0.2.1' })).count, 7);
  await login({ identifier: 'another.missing', password: 'WrongPass1' });
  assert.equal((await login()).status, 429);
});

test('parallel registration relies on database uniqueness, not a preflight lookup', async () => {
  const register = () => request(app).post('/api/auth/register').set('Origin', ORIGIN)
    .send({ email: 'race@example.test', username: 'race.user', password: PASSWORD });
  const results = await Promise.all([register(), register()]);
  assert.equal(results.filter((r) => r.status === 201).length, 1);
  assert.equal(await User.countDocuments(), 1);
  assert.equal(results.filter((r) => [400, 409].includes(r.status)).length, 1);
});

test('an application cannot use its bearer token or refresh session against another app', async () => {
  await require('../utils/authApps').seedDefaultAuthApps({ logger: { log() {} } });
  await createUser();
  const signedIn = await login({ targetOrigin: APP_ORIGIN }, 'https://blueprint.continental-hub.com');
  assert.equal(signedIn.status, 200);
  assert.equal(jwt.decode(signedIn.body.token).targetOrigin, 'https://blueprint.continental-hub.com');
  assert.equal((await request(app).get('/api/grimoire/decks').set('Authorization', `Bearer ${signedIn.body.token}`)).status, 403);
  const renewed = await refresh(cookie(signedIn), APP_ORIGIN);
  assert.equal(jwt.decode(renewed.body.token).targetOrigin, 'https://blueprint.continental-hub.com');
  for (const credentials of [{ accessToken: signedIn.body.token }, {}]) {
    const exchanged = await request(app).post('/api/auth/bootstrap').set('Origin', APP_ORIGIN)
      .set('Cookie', cookie(signedIn)).send({ appId: 'grimoire', ...credentials });
    assert.equal(exchanged.status, 403);
  }
  const grimoire = await login({}, APP_ORIGIN, '192.0.2.2');
  assert.equal((await request(app).get('/api/grimoire/decks').set('Authorization', `Bearer ${grimoire.body.token}`)).status, 200);
});

test('last owner can change a password but cannot delete their own account', async () => {
  await createUser({ accountRole: 'owner' });
  const signedIn = await login();
  const deletion = await request(app).delete('/api/auth/account').set('Origin', ORIGIN)
    .set('Authorization', `Bearer ${signedIn.body.token}`).send({ currentPassword: PASSWORD, confirmText: 'DELETE' });
  assert.equal(deletion.status, 400);
  const changed = await request(app).patch('/api/auth/password').set('Origin', ORIGIN)
    .set('Authorization', `Bearer ${signedIn.body.token}`).send({ currentPassword: PASSWORD, newPassword: 'AnotherStrong2' });
  assert.equal(changed.status, 200);
  assert.equal((await me(signedIn.body.token)).status, 401);
});

test('deletion intent survives dependent-data failure and cleanup can be retried after restart', async () => {
  const { deleteAccountRecord, cleanupPendingAccountDeletions } = require('../utils/accountDeletion');
  const Job = require('../models/AccountDeletionJob');
  const Deck = require('../models/GrimoireDeck');
  const user = await createUser();
  const other = await createUser({ email: 'other@example.test', username: 'other.user' });
  await Deck.collection.insertMany([{ ownerId: user._id, deckId: 'deleted' }, { ownerId: other._id, deckId: 'retained' }]);
  const original = Deck.deleteMany;
  Deck.deleteMany = () => { throw new Error('fixture dependency outage'); };
  try { assert.equal((await deleteAccountRecord(user)).cleanupPending, true); }
  finally { Deck.deleteMany = original; }
  assert.equal(await User.exists({ _id: user._id }), null);
  assert.ok(await Job.exists({ _id: user._id }));
  await cleanupPendingAccountDeletions();
  assert.equal(await Deck.countDocuments({ ownerId: user._id }), 0);
  assert.equal(await Deck.countDocuments({ ownerId: other._id }), 1);
  assert.equal(await Job.countDocuments(), 0);
});

test('malformed bodies, oversized bodies, untrusted origins, and HTML form authentication are rejected', async () => {
  const malformed = await request(app).post('/api/auth/login').set('Origin', ORIGIN)
    .set('Content-Type', 'application/json').send('{"password":"must-never-log",');
  assert.equal(malformed.status, 400);
  assert.equal((await request(app).post('/api/auth/login').set('Origin', ORIGIN).send([])).status, 400);
  assert.equal((await request(app).post('/api/auth/login').set('Origin', ORIGIN).send({ blob: 'x'.repeat(530000) })).status, 413);
  assert.equal((await request(app).post('/api/auth/login').set('Origin', 'https://attacker.example').send({})).status, 403);
  assert.equal((await request(app).post('/api/auth/login').set('Origin', 'null').send({})).status, 403);
  assert.equal((await request(app).post('/api/auth/login').set('Origin', ORIGIN).type('form').send({ identifier: 'fixture.user', password: PASSWORD })).status, 415);
});

test('route case and trailing slashes cannot bypass CSRF, management scope, or admission budgets', async () => {
  await createUser({ accountRole: 'owner' });
  const signedIn = await login({}, APP_ORIGIN);
  for (const path of ['/API/AUTH/OWNER/USERS/', '/api/AUTH/SECURITY/', '/API/auth/EXPORT/']) {
    assert.equal((await request(app).get(path).set('Authorization', `Bearer ${signedIn.body.token}`)).status, 403);
  }
  for (const path of ['/api/auth/LOGIN/', '/API/AUTH/refresh_token/', '/api/auth/BOOTSTRAP/']) {
    assert.equal((await request(app).post(path).send({})).status, 403);
  }
  const { consume } = require('../middleware/authRateLimiter');
  const key = 'auth-work:ip:192.0.2.100:/login';
  for (let i = 0; i < 40; i += 1) await consume(key, 40);
  const blocked = await request(app).post('/API/AUTH/LOGIN/').set('Origin', ORIGIN).set('X-Forwarded-For', '192.0.2.100')
    .send({ identifier: 'fixture.user', password: PASSWORD });
  assert.equal(blocked.status, 429);
  assert.ok(blocked.headers['retry-after']);
});

test('an exhausted mail quota leaves registration safely unverified without a partial-operation server error', async () => {
  const windowStart = new Date();
  windowStart.setUTCHours(0, 0, 0, 0);
  await ApiRateLimitBucket.create({ key: 'outbound-email:global:day', windowStart, count: 100, expiresAt: new Date(Date.now() + 86400000) });
  const result = await request(app).post('/api/auth/register').set('Origin', ORIGIN)
    .send({ email: 'quota@example.test', username: 'quota.user', password: PASSWORD });
  assert.equal(result.status, 201);
  const user = await User.findOne({ email: 'quota@example.test' });
  assert.equal(user.isVerified, false);
  assert.equal(user.refreshSessions.length, 0);
  assert.match(user.verificationToken, /^[a-f0-9]{64}$/);
  assert.equal((await ApiRateLimitBucket.findOne({ key: 'outbound-email:global:day' })).count, 100);
});

const oauthStart = () => request(app).get('/api/auth/oauth/github/start').query({ origin: ORIGIN, redirect: `${ORIGIN}/done` });
test('OAuth state is bound to the browser and consumed once before contacting the provider', async () => {
  const started = await oauthStart();
  assert.equal(started.status, 302);
  const location = new URL(started.headers.location);
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
  assert.match(location.searchParams.get('code_challenge'), /^[a-zA-Z0-9_-]{43}$/);
  const state = location.searchParams.get('state');
  const callback = () => request(app).get('/api/auth/oauth/github/callback').query({ code: 'fixture-code', state });
  assert.equal((await callback()).status, 400);
  assert.equal(await AuthChallenge.countDocuments(), 1);
  let calls = 0;
  const blockedFetch = global.fetch;
  global.fetch = async () => { calls += 1; return { ok: false, json: async () => ({ error_description: 'secret-detail' }) }; };
  try {
    const first = await callback().set('Cookie', cookie(started, 'oauthBinding_github'));
    assert.equal(first.status, 502);
    assert.doesNotMatch(first.text, /secret-detail/);
    assert.equal((await callback().set('Cookie', cookie(started, 'oauthBinding_github'))).status, 400);
    assert.equal(calls, 1);
  } finally { global.fetch = blockedFetch; }
});

test('OAuth does not permit suspended linked accounts to create sessions', async () => {
  const user = await createUser({ accountStatus: 'suspended', oauthIdentities: [{ provider: 'github', providerUserId: '123', emailVerified: true }] });
  const started = await oauthStart();
  const state = new URL(started.headers.location).searchParams.get('state');
  const blockedFetch = global.fetch;
  global.fetch = async (url, options) => {
    if (url === 'https://github.com/login/oauth/access_token') {
      assert.ok(new URLSearchParams(options.body).get('code_verifier'));
      return { ok: true, json: async () => ({ access_token: 'fixture-provider-token' }) };
    }
    return { ok: true, json: async () => url.endsWith('/emails')
      ? [{ email: user.email, verified: true, primary: true }]
      : { id: 123, login: 'fixture-github', name: 'Fixture' } };
  };
  try {
    const result = await request(app).get('/api/auth/oauth/github/callback').set('Cookie', cookie(started, 'oauthBinding_github')).query({ code: 'fixture-code', state });
    assert.equal(result.status, 403);
    assert.equal(cookie(result), '');
    assert.equal((await User.findById(user._id)).refreshSessions.length, 0);
  } finally { global.fetch = blockedFetch; }
});

const passkeyFixture = async (user) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialId = crypto.randomBytes(32).toString('base64url');
  // A fixed COSE EC2/ES256/P-256 public key map, with generated x/y coordinates.
  const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x, 'base64url'),
    Buffer.from('225820', 'hex'), Buffer.from(jwk.y, 'base64url')]);
  user.security.passkeys.push({ credentialId, publicKey: cose, counter: 0 });
  await user.save();
  const start = await request(app).post('/api/auth/passkeys/authenticate/options').set('Origin', ORIGIN).send({});
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: start.body.options.challenge, origin: ORIGIN }));
  const authData = Buffer.alloc(37);
  crypto.createHash('sha256').update('localhost').digest().copy(authData);
  authData[32] = 5; // User presence and user verification.
  authData.writeUInt32BE(1, 33);
  const signature = crypto.sign('sha256', Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]), privateKey);
  return { cookie: cookie(start, 'webauthnChallenge'), credential: { id: credentialId, rawId: credentialId, type: 'public-key',
    response: { clientDataJSON: clientData.toString('base64url'), authenticatorData: authData.toString('base64url'), signature: signature.toString('base64url') } } };
};

test('real signed passkey assertions authenticate once and their challenge cannot be replayed', async () => {
  const user = await createUser();
  const fixture = await passkeyFixture(user);
  const authenticate = () => request(app).post('/api/auth/passkeys/authenticate/verify').set('Origin', ORIGIN)
    .set('Cookie', fixture.cookie).send({ credential: fixture.credential });
  const result = await authenticate();
  assert.equal(result.status, 200);
  assert.equal(result.body.authenticated, true);
  assert.equal((await authenticate()).status, 400);
  assert.equal((await User.findById(user._id)).security.passkeys[0].counter, 1);
});

test('a cryptographically valid passkey cannot bypass suspension', async () => {
  const user = await createUser({ accountStatus: 'suspended' });
  const fixture = await passkeyFixture(user);
  const result = await request(app).post('/api/auth/passkeys/authenticate/verify').set('Origin', ORIGIN)
    .set('Cookie', fixture.cookie).send({ credential: fixture.credential });
  assert.equal(result.status, 403);
  assert.equal((await User.findById(user._id)).refreshSessions.length, 0);
});

test('required identity indexes enforce OAuth and passkey uniqueness', async () => {
  const a = await createUser();
  a.oauthIdentities.push({ provider: 'github', providerUserId: 'provider-unique' });
  a.security.passkeys.push({ credentialId: 'credential-unique', publicKey: Buffer.from('fixture') });
  await a.save();
  const b = await createUser({ email: 'b@example.test', username: 'second.user' });
  b.oauthIdentities.push({ provider: 'github', providerUserId: 'provider-unique' });
  await assert.rejects(b.save(), (err) => err.code === 11000);
  b.oauthIdentities = [];
  b.security.passkeys.push({ credentialId: 'credential-unique', publicKey: Buffer.from('fixture') });
  await assert.rejects(b.save(), (err) => err.code === 11000);
  const maintenance = await runStartupMaintenance();
  assert.equal(maintenance.status, 'ok');
});

test('removing a potentially compromised passkey revokes all existing sessions', async () => {
  const user = await createUser();
  user.security.passkeys.push({ credentialId: 'fixture-passkey', publicKey: Buffer.from('fixture') });
  await user.save();
  const signedIn = await login();
  const removed = await request(app).delete('/api/auth/passkeys/fixture-passkey').set('Origin', ORIGIN)
    .set('Authorization', `Bearer ${signedIn.body.token}`).send({ currentPassword: PASSWORD });
  assert.equal(removed.status, 200);
  assert.equal(removed.body.forceRelogin, true);
  assert.equal((await me(signedIn.body.token)).status, 401);
  assert.equal((await User.findById(user._id)).security.passkeys.length, 0);
});

test('database outages fail closed, with no session created or success returned', async () => {
  const original = ApiRateLimitBucket.findOneAndUpdate;
  ApiRateLimitBucket.findOneAndUpdate = () => { throw Object.assign(new Error('sensitive database detail'), { name: 'MongoNetworkError' }); };
  try {
    const result = await login();
    assert.equal(result.status, 503);
    assert.equal(cookie(result), '');
    assert.doesNotMatch(JSON.stringify(result.body), /sensitive database detail/);
  } finally { ApiRateLimitBucket.findOneAndUpdate = original; }
});
