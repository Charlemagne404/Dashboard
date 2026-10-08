const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');

Object.assign(process.env, {
  NODE_ENV: 'production', DOTENV_CONFIG_PATH: '/tmp/continental-nonexistent-fixture-env',
  MONGO_URI: 'mongodb://127.0.0.1/unused-production-fixture',
  JWT_SECRET: 'fixture-production-access-key-1234567890',
  REFRESH_TOKEN_SECRET: 'fixture-production-refresh-key-1234567890',
  MFA_SECRET_ENCRYPTION_KEY: 'fixture-production-mfa-key-1234567890',
  ALLOWED_ORIGINS: 'https://login.example.test,https://dashboard.example.test',
  IDENTITY_MANAGEMENT_ORIGINS: 'https://login.example.test,https://dashboard.example.test',
  PUBLIC_API_ORIGIN: 'https://login.example.test', TRUST_PROXY: '1', HTTPS_MODE: 'off',
  RESEND_API_KEY: 'fixture-not-live', EMAIL_FROM: 'fixture@example.test', LOGIN_POPUP_URL: 'https://login.example.test/popup.html',
  ALLOW_DEFAULT_TRUSTED_ORIGINS: 'false', ALLOW_LOCALHOST_ORIGINS: 'false',
});
const { app } = require('../server');
const User = require('../models/User');
const Bucket = require('../models/ApiRateLimitBucket');
const Throttle = require('../models/LoginThrottle');
const ORIGIN = 'https://login.example.test';
const PASSWORD = 'StrongPass1';
let db;
let originalFetch;
test.before(async () => {
  originalFetch = global.fetch;
  global.fetch = async () => { throw new Error('No external network in production-mode fixtures.'); };
  db = await MongoMemoryServer.create();
  await mongoose.connect(db.getUri());
});
test.beforeEach(async () => {
  await mongoose.connection.db.dropDatabase();
  await Promise.all([User.createIndexes(), Bucket.createIndexes(), Throttle.createIndexes()]);
});
test.after(async () => { global.fetch = originalFetch; await mongoose.disconnect(); await db.stop(); });
const login = () => request(app).post('/api/auth/login').set('Origin', ORIGIN)
  .set('X-Forwarded-Proto', 'https').send({ identifier: 'fixture.user', password: PASSWORD });

test('production refresh cookie is host-only, Secure, HttpOnly, correctly cleared, and revoked on logout', async () => {
  await User.create({ email: 'fixture@example.test', username: 'fixture.user', password: PASSWORD, isVerified: true });
  const signedIn = await login();
  assert.equal(signedIn.status, 200);
  const setCookie = signedIn.headers['set-cookie'].find((v) => v.startsWith('__Host-continentalRefresh='));
  assert.match(setCookie, /; Secure/);
  assert.match(setCookie, /; HttpOnly/);
  assert.match(setCookie, /; Path=\//);
  assert.match(setCookie, /; SameSite=Lax/);
  assert.doesNotMatch(setCookie, /; Domain=/);
  const loggedOut = await request(app).post('/api/auth/logout').set('Origin', ORIGIN)
    .set('X-Forwarded-Proto', 'https').set('Cookie', setCookie.split(';')[0]).send({});
  assert.equal(loggedOut.status, 200);
  assert.ok(loggedOut.headers['set-cookie'].some((v) => v.startsWith('__Host-continentalRefresh=;')));
  assert.equal((await request(app).get('/api/auth/me').set('Authorization', `Bearer ${signedIn.body.token}`)).status, 401);
});
test('production denies owner administration without enrolled MFA and excludes development origins', async () => {
  await User.create({ email: 'fixture@example.test', username: 'fixture.user', password: PASSWORD, isVerified: true, accountRole: 'owner' });
  const signedIn = await login();
  assert.equal(signedIn.status, 200);
  assert.equal((await request(app).get('/api/auth/owner/users').set('Authorization', `Bearer ${signedIn.body.token}`)).status, 403);
  assert.equal((await request(app).post('/api/auth/login').set('Origin', 'http://localhost:3000').send({})).status, 403);
});
