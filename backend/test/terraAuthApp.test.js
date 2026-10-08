const test = require('node:test');
const assert = require('node:assert/strict');
const { getDefaultAuthApp } = require('../utils/authApps');

test('Terra Tread has a registered, unique application origin for native cloud access', () => {
  const app = getDefaultAuthApp('terra-tread');
  assert.equal(app?.status, 'active');
  assert.deepEqual(app?.allowedOrigins, ['https://terra-tread.continental-hub.com']);
  assert.deepEqual(app?.allowedRedirectOrigins, ['https://terra-tread.continental-hub.com']);
});
