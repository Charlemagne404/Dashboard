const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { from, listen } = require('./harness.cjs');
const { createContinentalService } = from('blueprint', 'src/auth/continental');
const origin = 'https://blueprint.example.test';
const good = { authContext: { applicationOrigin: origin, identityManagement: false }, user: { userId: 'stable-id', displayName: 'Fixture', oauthProviders: { discord: { linked: false } } } };
test('consumer schema matrix over real HTTP: status, shape, extension, scope, deadline', async () => {
  let mode = 'good';
  const server = http.createServer((req, res) => {
    assert.equal(req.url, '/api/auth/me'); assert.equal(req.headers.origin, origin);
    if (mode === 'timeout') return;
    if (mode === 'reset') return req.socket.destroy();
    const codes = { unauthorized: 401, forbidden: 403, missing: 404, limited: 429, unavailable: 500, changed: 201 };
    res.writeHead(codes[mode] || 200);
    const bodies = { good, extended: { ...good, future: ['additive'] }, missingId: { ...good, user: {} }, wrongId: { ...good, user: { userId: 17 } }, noScope: { user: good.user }, otherScope: { ...good, authContext: { applicationOrigin: 'https://other.test' } }, changed: good };
    res.end(mode === 'malformed' ? '{oops' : JSON.stringify(bodies[mode] || { secret: 'private-provider-error' }));
  });
  const base = await listen(server);
  const service = createContinentalService({ authApiBaseUrl: base, baseUrl: origin, authRequestTimeoutSeconds: 0.1 });
  try {
    for (const name of ['good', 'extended', 'changed']) { mode = name; assert.equal((await service.profile('fixture-token')).subject, 'stable-id'); }
    for (const [name, code] of [['missingId',502], ['wrongId',502], ['noScope',401], ['otherScope',401], ['malformed',502], ['unauthorized',401], ['forbidden',401], ['missing',401], ['limited',503], ['unavailable',503], ['reset',503], ['timeout',504]]) {
      mode = name;
      await assert.rejects(service.profile('fixture-token'), error => { assert.doesNotMatch(error.message, /private-provider-error/); return error.statusCode === code; }, name);
    }
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  await assert.rejects(service.profile('fixture-token'), error => error.statusCode === 503);
});
test('StepCast accepts current and legacy subjects without coercing invalid fields', () => {
  const { extractContinentalUserId } = from('StepCast', 'backend/utils/continentalAuth');
  for (const payload of [{ user: { userId: 'cid' } }, { user: { continentalId: 'cid' } }, { user: { id: 'cid' } }, { continentalId: 'cid' }]) assert.equal(extractContinentalUserId(payload), 'cid');
  for (const payload of [{ user: { userId: 42 } }, { user: { userId: {} } }, {}]) assert.equal(extractContinentalUserId(payload), '');
});
test('pinned Blueprint shared client and workspace shared client parse additive popup/bootstrap contracts', () => {
  const clients = [from('continental-id-client', 'shared.cjs'), from('blueprint', 'node_modules/@continental/id-client/shared.cjs')];
  for (const client of clients) {
    const message = { source: 'continental-id', type: 'auth-result', event: 'login_success', accessToken: 'fixture', futureField: true };
    assert.equal(client.parseAuthPopupMessage(message).accessToken, 'fixture');
    assert.equal(client.getBootstrapAccessToken({ session: { accessToken: 'fixture' }, authContext: { applicationOrigin: origin } }), 'fixture');
    assert.equal(client.parseAuthPopupMessage({ ...message, event: 'unknown-event' }), null);
  }
});
