const test = require('node:test');
const assert = require('node:assert/strict');
const { boot, from } = require('./harness.cjs');
let h;
test.before(async () => { h = await boot(); });
test.after(async () => { if (h) await h.close(); });
const profile = () => from('blueprint', 'src/auth/continental').createContinentalService({ authApiBaseUrl: h.urls.proxy, baseUrl: h.urls.blueprint, authRequestTimeoutSeconds: 1 });
async function browserSession(token, stateOverride) {
  let response = await fetch(`${h.urls.blueprint}/`);
  let cookie = response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  let csrf = (await response.text()).match(/"csrfToken":"([^"]+)"/)[1];
  const post = async (path, body) => {
    const result = await fetch(`${h.urls.blueprint}${path}`, { method: 'POST', redirect: 'manual', headers: { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: h.urls.blueprint, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (result.headers.getSetCookie().length) cookie = result.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    return result;
  };
  response = await post('/auth/continental/start', { returnTo: '/account' });
  assert.equal(response.status, 200);
  const { state } = await response.json();
  response = await post('/auth/session', { accessToken: token, state: stateOverride || state });
  const payload = await response.json(); if (payload.csrfToken) csrf = payload.csrfToken;
  return { response, payload, post, state, get: path => fetch(`${h.urls.blueprint}${path}`, { headers: { Cookie: cookie }, redirect: 'manual' }) };
}
const linked = () => ({ oauthIdentities: [{ provider: 'discord', providerUserId: '123456789012345678', username: 'stable-fixture', linkedAt: new Date() }] });
test('real ID app-scoped profile preserves optional Discord identity for Blueprint', async () => {
  const user = await h.user(linked());
  const token = await h.appToken(user);
  assert.equal((await profile().profile(token)).discordUserId, '123456789012345678');
});
test('token for Grimoire cannot establish Blueprint identity', async () => {
  const token = await h.appToken(await h.user(), 'grimoire');
  await assert.rejects(profile().profile(token), error => error.statusCode === 401);
});
test('Status owner app login, current role revocation, cross-app denial', async () => {
  const owner = await h.user({ accountRole: 'owner' });
  const token = await h.appToken(owner, 'status');
  const request = value => fetch(`${h.urls.status}/api/internal/status`, { headers: { Authorization: `Bearer ${value}` } });
  assert.equal((await request(token)).status, 200);
  assert.equal((await request(await h.appToken(owner))).status, 401);
  await h.User.updateOne({ _id: owner._id }, { $set: { accountRole: 'user' } });
  assert.equal((await request(token)).status, 403);
});
test('Blueprint real login, existing account, replay, CSRF, logout', async () => {
  const user = await h.user(); const token = await h.appToken(user);
  const session = await browserSession(token);
  assert.equal(session.response.status, 200);
  assert.equal((await session.get('/account')).status, 200);
  const again = await browserSession(token);
  assert.equal(again.payload.user.id, session.payload.user.id);
  assert.equal((await session.post('/auth/session', { accessToken: token, state: session.state })).status, 400);
  assert.equal((await session.post('/logout', {})).status, 302);
  assert.equal((await session.get('/account')).status, 303);
  const mismatch = await browserSession(token, 'malicious-state');
  assert.equal(mismatch.response.status, 400);
});
test('revocation, suspension, deletion propagate to an existing Blueprint session', async () => {
  for (const action of ['revoke', 'suspend', 'delete']) {
    const user = await h.user(); const token = await h.appToken(user);
    const session = await browserSession(token); assert.equal(session.response.status, 200);
    if (action === 'revoke') await h.User.updateOne({ _id: user._id }, { $inc: { refreshTokenVersion: 1 } });
    if (action === 'suspend') await h.User.updateOne({ _id: user._id }, { $set: { accountStatus: 'suspended' } });
    if (action === 'delete') await h.User.deleteOne({ _id: user._id });
    assert.equal((await session.get('/account')).status, 303, action);
  }
});
test('profile extensions are harmless; missing/invalid IDs fail safely', async () => {
  const token = await h.appToken(await h.user());
  try {
    h.fault.rewrite = payload => ({ ...payload, futureField: { version: 20 } });
    assert.ok((await profile().profile(token)).subject);
    for (const value of [undefined, 42, '', null]) {
      h.fault.rewrite = payload => ({ ...payload, user: { ...payload.user, userId: value, continentalId: value } });
      await assert.rejects(profile().profile(token), error => error.statusCode === 502);
    }
  } finally { h.fault.rewrite = null; }
});
test('modest concurrent real token verification and local account login', async () => {
  const token = await h.appToken(await h.user());
  const started = Date.now();
  const results = await Promise.all(Array.from({ length: 12 }, () => browserSession(token)));
  assert.ok(results.every(result => result.response.status === 200));
  assert.equal(new Set(results.map(result => result.payload.user.id)).size, 1);
  h.report.events.push({ scenario: '12 concurrent Blueprint logins', durationMs: Date.now() - started });
});
test('Status probes actual local providers and suppresses internal diagnostics', async () => {
  const { validateConfig } = from('status', 'src/model');
  const { runProbe } = from('status', 'src/probes');
  const config = validateConfig(JSON.parse(require('node:fs').readFileSync(`${h.directory}/status-config.json`)));
  for (const probe of config.probes) assert.equal((await runProbe(probe, AbortSignal.timeout(1000))).outcome, 'pass');
  const payload = await (await fetch(`${h.urls.status}/api/v2/status`)).text();
  assert.doesNotMatch(payload, /127\.0\.0\.1|mongodb:|stack|JWT_SECRET|probeUrl/);
  assert.equal((await fetch(`${h.urls.status}/api/internal/status`)).status, 401);
});
test('chaos: bounded dependency failures preserve public pages and recover', { skip: !process.env.ECOSYSTEM_CHAOS }, async () => {
  const token = await h.appToken(await h.user());
  const session = await browserSession(token);
  try {
    for (const mode of ['500', 'malformed', 'reset', 'timeout', 'partial', 'delay']) {
      h.fault.mode = mode;
      const started = Date.now();
      await assert.rejects(profile().profile(token), error => [502, 503, 504].includes(error.statusCode));
      assert.ok(Date.now() - started < 2500, `${mode} exceeded consumer deadline`);
      assert.equal((await fetch(`${h.urls.blueprint}/healthz`)).status, 200);
      assert.equal((await fetch(`${h.urls.contact}/api/health`)).status, 200);
    }
    h.fault.mode = '500';
    assert.equal((await session.get('/account')).status, 503);
    h.fault.mode = 'pass';
    assert.equal((await session.get('/account')).status, 200);
  } finally { h.fault.mode = 'pass'; }
});
test('Pulse real consumer rejects other app tokens and preserves sessions during ID outage', async () => {
  const user = await h.user(); const token = await h.appToken(user, 'pulse');
  const request = value => fetch(`${h.urls.pulse}/v1/workspace`, { headers: { Authorization: `Bearer ${value}` } });
  assert.equal((await request(token)).status, 200);
  assert.equal((await request(await h.appToken(user))).status, 401);
  try { h.fault.mode = '500'; assert.equal((await request(token)).status, 503); }
  finally { h.fault.mode = 'pass'; }
  assert.equal((await request(token)).status, 200);
});
test('app bootstrap cannot retarget another application session', async () => {
  const token = await h.appToken(await h.user());
  const response = await fetch(`${h.urls.id}/api/auth/bootstrap`, { method: 'POST', headers: { Origin: h.urls.status, 'Content-Type': 'application/json' }, body: JSON.stringify({ appId: 'status', accessToken: token }) });
  assert.equal(response.status, 403);
});
test('Contact uses a fake Discord webhook with bounded failure and mention suppression', async () => {
  const send = () => fetch(`${h.urls.contact}/api/contact`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ project: 'Blueprint', reason: 'Bug report', email: 'fixture@example.test', message: '@everyone integration fixture message' }) });
  assert.equal((await send()).status, 200);
  assert.deepEqual(h.external.messages.at(-1).allowed_mentions, { parse: [] });
  try {
    h.external.mode = '500'; assert.equal((await send()).status, 502);
    if (process.env.ECOSYSTEM_CHAOS) {
      h.external.mode = 'timeout'; const at = Date.now();
      assert.equal((await send()).status, 502); assert.ok(Date.now() - at < 6500);
    }
  } finally { h.external.mode = 'pass'; }
});
test('browser: actual Blueprint popup, ID credentials, cookies and protected account', { skip: !process.env.ECOSYSTEM_BROWSER }, async () => {
  const { chromium } = from('blueprint', 'node_modules/playwright');
  const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
  try {
    const context = await browser.newContext();
    const blocked = [];
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (['127.0.0.1', 'localhost'].includes(url.hostname)) return route.continue();
      blocked.push(url.origin); return route.abort();
    });
    const page = await context.newPage();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    const user = await h.user();
    await page.goto(`${h.urls.blueprint}/auth/complete?returnTo=/account`);
    const [popup] = await Promise.all([page.waitForEvent('popup'), page.locator('#relogin-button').click()]);
    await popup.locator('#login-identifier').fill(user.email);
    await popup.locator('#login-password').fill('EcosystemStrongPass123!');
    await popup.locator('#login-btn').click();
    await page.waitForURL(`${h.urls.blueprint}/account`, { timeout: 20000 });
    assert.equal((await page.request.get(`${h.urls.blueprint}/account`)).status(), 200);
    const cookies = await context.cookies(h.urls.blueprint);
    const cookie = cookies.find(value => value.name === 'blueprint.sid');
    assert.equal(cookie.httpOnly, true); assert.equal(cookie.sameSite, 'Lax');
    assert.equal(errors.length, 0); assert.deepEqual(blocked, []);
    await page.screenshot({ path: `${h.directory}/browser-account.png` });
  } finally { await browser.close(); }
});
test('Vanguard real Python consumer verifies app boundary through HTTP', async () => {
  const { spawn } = require('node:child_process');
  const path = require('node:path');
  const { root } = require('./harness.cjs');
  const user = await h.user();
  const run = token => new Promise((resolve, reject) => {
    const child = spawn(path.join(root, 'discord-bots/.venv/bin/python'), [path.join(__dirname, 'vanguard-consumer.py')], { cwd: h.directory, env: { PATH: process.env.PATH, HOME: h.directory, ECOSYSTEM_ROOT: root, PYTHON_DOTENV_DISABLED: '1', VANGUARD_DATA_DIR: `${h.directory}/vanguard-data`, CONTINENTAL_ID_AUTH_BASE_URL: h.urls.proxy, VANGUARD_CONTROL_CENTER_PUBLIC_URL: h.urls.vanguard }, stdio: ['pipe','pipe','pipe'] });
    h.trackChild(child);
    let output = '', error = ''; child.stdout.on('data', data => output += data); child.stderr.on('data', data => error += data);
    child.stdin.end(token);
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Vanguard consumer deadline')); }, 15000);
    child.once('error', reject); child.once('exit', code => { clearTimeout(timer); if (code) reject(new Error(`Vanguard consumer failed: ${error.slice(-300)}`)); else resolve(JSON.parse(output.trim().split('\n').at(-1))); });
  });
  const accepted = await run(await h.appToken(user, 'vanguard'));
  assert.equal(accepted.ok, true); assert.equal(accepted.subject, String(user._id));
  assert.equal((await run(await h.appToken(user))).ok, false);
});
test('request correlation crosses Blueprint and ID without storing credentials', async () => {
  const token = await h.appToken(await h.user()); const session = await browserSession(token);
  assert.equal(session.response.status, 200);
  const id = session.response.headers.get('x-correlation-id');
  assert.ok(h.fault.records.some(record => record.path === '/api/auth/me' && record.requestId === id));
  const response = await fetch(`${h.urls.id}/api/auth/me`, { headers: { Authorization: `Bearer ${token}`, 'X-Request-Id': id, Origin: h.urls.blueprint } });
  assert.equal(response.headers.get('x-request-id'), id);
});
async function linkStart(user) {
  const credentials = await h.login(user, h.urls.id);
  const response = await fetch(`${h.urls.id}/api/auth/oauth/discord/link-start`, { method: 'POST', headers: { Authorization: `Bearer ${credentials.token}`, Origin: h.urls.id, 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword: 'EcosystemStrongPass123!', origin: h.urls.id, redirect: `${h.urls.id}/popup.html` }) });
  assert.equal(response.status, 200);
  const url = new URL((await response.json()).url);
  return { state: url.searchParams.get('state'), cookie: response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ') };
}
const linkCallback = (transaction, code = require('node:crypto').randomUUID(), extras = '') => fetch(`${h.urls.id}/api/auth/oauth/discord/callback?state=${encodeURIComponent(transaction.state)}&code=${encodeURIComponent(code)}${extras}`, { headers: { Cookie: transaction.cookie }, redirect: 'manual' });
test('ID Discord linking across provider HTTP: stable ID, replay, collision, unlink/relink', async () => {
  const user = await h.user();
  const transaction = await linkStart(user);
  assert.equal((await linkCallback(transaction, undefined, '&providerUserId=attacker')).status, 200);
  const linked = await h.User.findById(user._id);
  assert.equal(linked.oauthIdentities[0].providerUserId, h.external.identity.id);
  assert.equal((await linkCallback(transaction)).status, 400);
  const token = await h.appToken(user); const session = await browserSession(token);
  assert.equal(session.payload.user.discordLinked, true);
  const other = await h.user(); const collision = await linkStart(other);
  assert.equal((await linkCallback(collision)).status, 409);
  assert.equal((await h.User.findById(other._id)).oauthIdentities.length, 0);
  h.external.identity.username = 'renamed-discord'; h.external.identity.email = 'changed@example.test';
  assert.equal((await linkCallback(await linkStart(user))).status, 200);
  assert.equal((await h.User.findById(user._id)).oauthIdentities[0].providerUserId, h.external.identity.id);
  const management = await h.login(user, h.urls.id);
  const unlink = await fetch(`${h.urls.id}/api/auth/oauth/discord`, { method: 'DELETE', headers: { Authorization: `Bearer ${management.token}`, Origin: h.urls.id, 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword: 'EcosystemStrongPass123!' }) });
  assert.equal(unlink.status, 200);
  assert.equal((await session.get('/account')).status, 303);
  assert.equal((await linkCallback(await linkStart(user))).status, 200);
});
test('two ID accounts race to claim the same external identity', async () => {
  h.external.identity.id = '900000000000000002';
  const users = await Promise.all([h.user(), h.user()]);
  const transactions = await Promise.all(users.map(linkStart));
  const callbacks = await Promise.all(transactions.map(transaction => linkCallback(transaction)));
  assert.equal(callbacks.filter(response => response.status === 200).length, 1);
  assert.ok(callbacks.every(response => [200,409].includes(response.status)), 'Identity ownership collision must be an explicit conflict');
  assert.equal(await h.User.countDocuments({ oauthIdentities: { $elemMatch: { provider: 'discord', providerUserId: h.external.identity.id } } }), 1);
});
async function eventually(check, label, timeout = 14000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 200)); }
  assert.fail(`Deadline waiting for ${label}`);
}
test('Status tracks ID outage, dependent degradation, automatic incident and recovery', { skip: !process.env.ECOSYSTEM_CHAOS }, async () => {
  const status = async () => (await fetch(`${h.urls.status}/api/v2/status`)).json();
  await eventually(async () => (await status()).services.every(service => service.state === 'operational'), 'initial service health');
  try {
    h.fault.mode = '500';
    await eventually(async () => {
      const data = await status();
      return data.services.find(service => service.id === 'id').state === 'major_outage' && data.services.find(service => service.id === 'blueprint').state === 'degraded';
    }, 'ID outage and propagated degradation');
    const data = await status();
    assert.equal(data.services.find(service => service.id === 'contact').state, 'operational');
    assert.ok(data.incidents.some(incident => incident.origin === 'automatic' && incident.serviceIds.includes('id')));
    assert.doesNotMatch(JSON.stringify(data), /127\.0\.0\.1|private|diagnostic|mongodb:/);
    const token = await h.appToken(await h.user({ accountRole: 'owner' }), 'status');
    // Operator authentication degrades while ID verification is unavailable.
    assert.equal((await fetch(`${h.urls.status}/api/internal/status`, { headers: { Authorization: `Bearer ${token}` } })).status, 503);
  } finally { h.fault.mode = 'pass'; }
  await eventually(async () => (await status()).services.every(service => service.state === 'operational'), 'service recovery');
});
test('typed token contract: issuer, audience, expiry, format and centrally verified consumer clocks', async () => {
  const token = await h.appToken(await h.user());
  const jwt = from('Dashboard', 'backend/node_modules/jsonwebtoken'); const claims = jwt.decode(token);
  for (const mutate of [ value => value.iss = 'wrong-issuer', value => value.aud = 'other-service', value => value.type = 'refresh_token', value => value.exp = Math.floor(Date.now()/1000)-60, value => delete value.sid, value => delete value.tokenVersion ]) {
    const value = { ...claims }; mutate(value);
    const changed = jwt.sign(value, h.env.JWT_SECRET, { algorithm: 'HS256' });
    await assert.rejects(profile().profile(changed), error => error.statusCode === 401);
  }
  await assert.rejects(profile().profile('malformed.token'), error => error.statusCode === 401);
  const realNow = Date.now;
  try { Date.now = () => realNow() + 30000; assert.ok((await profile().profile(token)).subject); }
  finally { Date.now = realNow; }
});
test('real CORS preflight, forbidden origin, cookie refresh/revocation and CSRF boundaries', async () => {
  const preflight = await fetch(`${h.urls.id}/api/auth/login`, { method: 'OPTIONS', headers: { Origin: h.urls.blueprint, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
  assert.equal(preflight.status, 204); assert.equal(preflight.headers.get('access-control-allow-origin'), h.urls.blueprint);
  assert.equal(preflight.headers.get('access-control-allow-credentials'), 'true');
  const denied = await fetch(`${h.urls.id}/api/auth/login`, { method: 'POST', headers: { Origin: 'https://attacker.example.test', 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(denied.status, 403); assert.equal(denied.headers.get('access-control-allow-origin'), null);
  const user = await h.user(); const credentials = await h.login(user);
  const refresh = await fetch(`${h.urls.id}/api/auth/refresh_token`, { method: 'POST', headers: { Origin: h.urls.id, Cookie: credentials.cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ targetOrigin: h.urls.blueprint }) });
  assert.equal(refresh.status, 200); assert.equal((await refresh.json()).authenticated, true);
  const cookie = refresh.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  const logout = await fetch(`${h.urls.id}/api/auth/logout`, { method: 'POST', headers: { Origin: h.urls.id, Cookie: cookie, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(logout.status, 200); await assert.rejects(profile().profile(credentials.token), error => error.statusCode === 401);
  const noOrigin = await fetch(`${h.urls.id}/api/auth/refresh_token`, { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(noOrigin.status, 403);
  assert.equal((await fetch(`${h.urls.blueprint}/auth/continental/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
});
test('Aegis forwards collection to real Pulse and bounds collector outages', async () => {
  assert.equal((await fetch(`${h.urls.aegis}/api/pulse/health`)).status, 200);
  try {
    h.fault.mode = 'timeout';
    const response = await fetch(`${h.urls.aegis}/api/pulse/health`, { signal: AbortSignal.timeout(1200) });
    assert.equal(response.status, 502);
  } finally { h.fault.mode = 'pass'; }
});
test('Blueprint real Vanguard resolution and AI HTTP contract with fake Ollama', async () => {
  const runtime = from('blueprint', 'src/ai-runtime');
  const user = await h.user({ oauthIdentities: [{ provider: 'discord', providerUserId: '900000000000000003', username: 'boundary-fixture' }] });
  const config = { continentalIdResolveUrl: `${h.urls.id}/api/vanguard/users/resolve`, vanguardBackendApiKey: h.env.VANGUARD_API_KEY, authRequestTimeoutSeconds: 1,
    aiChatUrl: `${h.urls.ai}/chat`, aiAskUrl: `${h.urls.ai}/ask`, aiRequestTimeoutSeconds: 2, aiUseCache: false, aiHistoryMessages: 12, aiChatStyle: 'balanced' };
  // Adapter field name is part of the service credential contract.
  config.vanguardBackendKeyHeader = 'X-Vanguard-Api-Key';
  const result = await runtime.resolveContinentalUser('900000000000000003', config);
  assert.equal(result.ok, true); assert.equal(result.linked, true);
  const answer = await runtime.requestAiReply({ question: 'Integration fixture question', runtimeConfig: config, sessionId: 'ecosystem-fixture', userId: String(user._id), username: user.username });
  assert.equal(answer.mode, 'chat'); assert.equal(answer.answer, 'Local fixture answer');
  const unauthed = await fetch(`${h.urls.id}/api/vanguard/users/resolve`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ discordUserId: '900000000000000003' }) });
  assert.equal(unauthed.status, 401);
});
test('StepCast real consumer accepts ID nested subject and denies other application tokens', async () => {
  const user = await h.user(); const token = await h.appToken(user, 'stepcast');
  const request = value => fetch(`${h.urls.stepcast}/api/auth/protected`, { headers: { Authorization: `Bearer ${value}`, Origin: h.urls.stepcast } });
  const response = await request(token);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).userId, String(user._id));
  assert.equal((await request(await h.appToken(user))).status, 401);
});
test('Terra Tread cloud APIs require app-scoped identity and deny cross-account ownership', async () => {
  const a = await h.user(), b = await h.user();
  const accountA = String(a._id), accountB = String(b._id);
  const tokenA = await h.appToken(a, 'terra-tread');
  const tokenB = await h.appToken(b, 'terra-tread');
  const state = (userId, token, options = {}) => fetch(`${h.urls.terra}/api/game/state/${encodeURIComponent(userId)}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });

  assert.equal((await fetch(`${h.urls.terra}/api/game/state/${accountA}`)).status, 401);
  assert.equal((await state(accountA, tokenA, {
    method: 'PUT', body: JSON.stringify({ state: { availableSteps: 1700, buildings: [] } }),
  })).status, 200);
  assert.equal((await state(accountA, tokenB)).status, 403);
  assert.equal((await state(accountA, tokenB, {
    method: 'PUT', body: JSON.stringify({ state: { availableSteps: 0, buildings: [] } }),
  })).status, 403);
  assert.equal((await state(accountB, tokenA)).status, 403);
  assert.equal((await state(accountA, await h.appToken(a, 'blueprint'))).status, 401);

  const upload = (token, userId) => fetch(`${h.urls.terra}/api/game/steps`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, steps: 4000, source: 'ecosystem-fixture', deviceDayKey: new Date().toISOString().slice(0, 10) }),
  });
  assert.equal((await upload(tokenA, accountB)).status, 403);
  assert.equal((await upload(tokenA, accountA)).status, 200);
  assert.equal((await fetch(`${h.urls.terra}/api/game/steps/${accountA}`, { headers: { Authorization: `Bearer ${tokenB}` } })).status, 403);
  assert.equal((await fetch(`${h.urls.terra}/api/game/streaks/${accountA}/claim`, {
    method: 'POST', headers: { Authorization: `Bearer ${tokenB}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'daily-goal', dayKey: new Date().toISOString().slice(0, 10) }),
  })).status, 403);
  assert.equal((await fetch(`${h.urls.terra}/api/game/streaks/${accountA}/claim`, {
    method: 'POST', headers: { Authorization: `Bearer ${tokenA}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'daily-goal', dayKey: new Date().toISOString().slice(0, 10) }),
  })).status, 200);
});
test('Grimoire API app isolation and StepCast walk ownership through real ID tokens', async () => {
  const a = await h.user(), b = await h.user();
  const grimoire = await h.appToken(a, 'grimoire');
  assert.equal((await fetch(`${h.urls.id}/api/grimoire/decks`, { headers: { Authorization: `Bearer ${grimoire}` } })).status, 200);
  assert.equal((await fetch(`${h.urls.id}/api/grimoire/decks`, { headers: { Authorization: `Bearer ${await h.appToken(a)}` } })).status, 403);
  const tokens = await Promise.all([h.appToken(a, 'stepcast'), h.appToken(b, 'stepcast')]);
  const request = (token, options = {}) => fetch(`${h.urls.stepcast}/api/location`, { ...options, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } });
  const save = await request(tokens[0], { method: 'POST', body: JSON.stringify({ id: 'fixture-walk', podcastName: 'Fixture podcast', userId: String(b._id), points: [{ lat: 1, lng: 2 }] }) });
  assert.equal(save.status, 200);
  assert.equal((await (await request(tokens[0])).json()).length, 1);
  assert.equal((await (await request(tokens[1])).json()).length, 0);
});
test('Aegis collection reaches Pulse; malformed ID responses degrade Pulse safely', async () => {
  const token = await h.appToken(await h.user(), 'pulse');
  const create = await fetch(`${h.urls.pulse}/v1/projects`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Aegis fixture', projectId: 'aegis', domain: 'https://aegis.example.test', integrationPreset: 'website' }) });
  assert.equal(create.status, 201);
  await create.json();
  h.report.events.push({ scenario: 'Pulse project fixture', created: true });
  const collect = await fetch(`${h.urls.aegis}/api/pulse/collect`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ events: [{ eventId: 'ecosystem-event-0001', eventName: 'page_view', occurredAt: new Date().toISOString(), projectId: 'aegis', page: { path: '/integration' }, consent: { state: 'granted', mode: 'standard' }, identity: { sessionId: 'ecosystem-session-0001', visitorKey: 'fixture-visitor' } }] }) });
  assert.equal(collect.status, 202, JSON.stringify(await collect.json()));
  try {
    h.fault.mode = 'malformed';
    assert.equal((await fetch(`${h.urls.pulse}/v1/workspace`, { headers: { Authorization: `Bearer ${token}` } })).status, 503);
    h.fault.mode = 'pass'; h.fault.rewrite = () => null;
    assert.equal((await fetch(`${h.urls.pulse}/v1/workspace`, { headers: { Authorization: `Bearer ${token}` } })).status, 503);
  } finally { h.fault.mode = 'pass'; h.fault.rewrite = null; }
});
test('Grimoire real fetch consumer keeps its timeout active while reading a partial response', async () => {
  const fs = require('node:fs'), path = require('node:path');
  const { pathToFileURL } = require('node:url'); const { root } = require('./harness.cjs');
  const ts = from('pulse', 'node_modules/typescript');
  const directory = path.join(h.directory, 'grimoire-consumer'); fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, 'package.json'), '{"type":"module"}');
  for (const name of ['client', 'config']) {
    const source = fs.readFileSync(path.join(root, `Grimoire/src/auth/${name}.ts`), 'utf8');
    const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.ES2022 } }).outputText.replace('@/auth/config', './config.js');
    fs.writeFileSync(path.join(directory, `${name}.js`), compiled);
  }
  const { fetchWithTimeout } = await import(pathToFileURL(path.join(directory, 'client.js')));
  let timer;
  try {
    h.fault.mode = 'partial';
    const read = fetchWithTimeout(`${h.urls.proxy}/api/auth/me`, {}, 200).then(response => response.text());
    const bounded = Promise.race([read, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('Consumer cleared timeout before body completed')), 1000); })]);
    await assert.rejects(bounded, error => ['TimeoutError', 'AbortError'].includes(error.name));
  } finally { clearTimeout(timer); h.fault.mode = 'pass'; }
});
test('isolated Caddy outage does not stop the ID origin', { skip: !process.env.ECOSYSTEM_CHAOS }, async t => {
  if (!h.edgeProcess) return t.skip('Caddy binary unavailable; no host proxy is used');
  assert.equal((await fetch(`${h.urls.edge}/api/health`)).status, 200);
  const exited = new Promise(resolve => h.edgeProcess.once('exit', resolve));
  h.edgeProcess.kill('SIGTERM'); await exited;
  await assert.rejects(fetch(`${h.urls.edge}/api/health`, { signal: AbortSignal.timeout(1000) }));
  assert.equal((await fetch(`${h.urls.id}/api/health`)).status, 200);
});
test('database outage leaves independent services alive and ID readiness false', { skip: !process.env.ECOSYSTEM_CHAOS }, async () => {
  await h.mongo.stop();
  await eventually(async () => (await fetch(`${h.urls.id}/api/health`)).status === 503, 'ID database readiness', 10000);
  assert.equal((await fetch(`${h.urls.id}/api/live`)).status, 200);
  for (const [service, path] of [['blueprint','/healthz'],['pulse','/api/health'],['contact','/api/health'],['status','/live']]) assert.equal((await fetch(`${h.urls[service]}${path}`)).status, 200);
  const response = await fetch(`${h.urls.id}/api/auth/me`, { headers: { Authorization: 'Bearer fixture' } });
  assert.equal(response.status, 503); assert.doesNotMatch(await response.text(), /mongodb:|stack|JWT_SECRET/);
});
