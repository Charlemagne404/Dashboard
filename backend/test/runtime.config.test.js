const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const backendDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(__dirname, '../..');

const loadServerConfig = (env = {}) => {
  const script = `
    const { config, selectServerTransport } = require('./server');
    console.log(JSON.stringify({
      host: config.host,
      httpsMode: config.httpsMode,
      transportWithCerts: selectServerTransport(config.httpsMode, true),
      transportWithoutCerts: selectServerTransport(config.httpsMode, false)
    }));
  `;

  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: backendDir,
    env: {
      ...process.env,
      MONGO_URI: 'mongodb://127.0.0.1:27017/runtime_config_test',
      JWT_SECRET: '12345678901234567890123456789012',
      REFRESH_TOKEN_SECRET: 'abcdefghijklmnopqrstuvwxyz123456',
      ...env,
    },
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim());
};

test('production defaults bind publicly without auto-enabling HTTPS', () => {
  const config = loadServerConfig({
    NODE_ENV: 'production',
    HOST: '',
    HTTPS_MODE: '',
  });

  assert.equal(config.host, '0.0.0.0');
  assert.equal(config.httpsMode, 'off');
  assert.equal(config.transportWithCerts, 'http');
  assert.equal(config.transportWithoutCerts, 'http');
});

test('explicit HTTPS auto mode only enables TLS when cert files exist', () => {
  const config = loadServerConfig({
    NODE_ENV: 'production',
    HTTPS_MODE: 'auto',
  });

  assert.equal(config.httpsMode, 'auto');
  assert.equal(config.transportWithCerts, 'https');
  assert.equal(config.transportWithoutCerts, 'http');
});

test('compose defaults are aligned with local container development', () => {
  const composeSource = fs.readFileSync(path.join(repoRoot, 'compose.yml'), 'utf8');

  assert.match(composeSource, /HOST:\s*0\.0\.0\.0/);
  assert.match(composeSource, /NODE_ENV:\s*development/);
  assert.match(composeSource, /HTTPS_MODE:\s*off/);
});

test('deploy helper can fall back to a direct HTTPS health probe', () => {
  const deployScriptSource = fs.readFileSync(
    path.join(repoRoot, 'backend/deploy-backend.sh'),
    'utf8'
  );

  assert.match(deployScriptSource, /https:\/\/127\.0\.0\.1:5000\/api\/health/);
  assert.match(deployScriptSource, /curl -kfsS/);
});

test('hosted frontend probes only accept healthy auth API responses', () => {
  const probeFiles = [
    path.join(repoRoot, 'frontend/script.js'),
    path.join(repoRoot, 'frontend/profile.html'),
    path.join(repoRoot, 'login popup/popup.js'),
    path.join(repoRoot, 'login popup/reset-password.js'),
    path.join(repoRoot, 'login popup/verify.js'),
  ];

  for (const filePath of probeFiles) {
    const source = fs.readFileSync(filePath, 'utf8');
    assert.doesNotMatch(source, /\['ok',\s*'degraded'\]\.includes\(status\)/);
    assert.match(source, /\['ok'\]\.includes\(status\)/);
  }
});
