const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(process.env.ECOSYSTEM_ROOT || path.join(__dirname, '../..'));
const from = (repo, file) => require(path.join(root, repo, file));
const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`));
});
const freePort = async () => {
  const server = http.createServer(); const url = await listen(server);
  await new Promise(resolve => server.close(resolve)); return Number(new URL(url).port);
};
async function ready(url, child) {
  const until = Date.now() + 40000;
  while (Date.now() < until) {
    if (child.startError) throw child.startError;
    if (child.exitCode !== null) throw new Error(`Service exited before readiness: ${url}`);
    try { if ((await fetch(url, { signal: AbortSignal.timeout(500) })).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Service readiness deadline: ${url}`);
}
async function boot(options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'continental-ecosystem-'));
  const children = [], servers = [];
  let mongo, mongoose;
  const report = { root, revisions: {}, events: [] };
  let closed = false, savedFault;
  async function close() {
    if (closed) return; closed = true;
    for (const child of [...children].reverse()) {
      if (child.exitCode !== null || child.startError) continue;
      const done = new Promise(resolve => child.once('exit', resolve));
      child.kill('SIGTERM');
      const kill = setTimeout(() => child.kill('SIGKILL'), 6000);
      await done; clearTimeout(kill);
    }
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    if (mongoose) await mongoose.disconnect();
    if (mongo) await mongo.stop();
    report.requests = typeof savedFault !== 'undefined' ? savedFault.records : [];
    fs.writeFileSync(path.join(directory, 'report.json'), JSON.stringify(report, null, 2));
    console.log(`Ecosystem evidence: ${directory}`);
  }
  const stop = () => { void close().finally(() => process.exit(130)); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  try {
    mongo = await from('Dashboard', 'backend/node_modules/mongodb-memory-server').MongoMemoryServer.create();
    report.mongoPid = mongo.instanceInfo?.instance?.mongodProcess?.pid;
    mongoose = from('Dashboard', 'backend/node_modules/mongoose');
    await mongoose.connect(mongo.getUri('ecosystem'));
    const ports = Object.fromEntries(await Promise.all(['id', 'blueprint', 'status', 'contact', 'pulse', 'vanguard', 'aegis', 'ai', 'stepcast', 'terra', 'edge'].map(async name => [name, await freePort()])));
    const urls = Object.fromEntries(Object.entries(ports).map(([name, port]) => [name, `http://127.0.0.1:${port}`]));
    const fault = { mode: 'pass', records: [], rewrite: null }; savedFault = fault;
    const proxy = http.createServer(async (req, res) => {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      fault.records.push({ method: req.method, path: req.url, requestId: req.headers['x-request-id'] || '', mode: fault.mode });
      if (fault.mode === 'timeout') return;
      if (fault.mode === 'reset') return req.socket.destroy();
      if (fault.mode === '500') { res.writeHead(500); return res.end('{"private":"not reflected"}'); }
      if (fault.mode === 'malformed') { res.writeHead(200); return res.end('{broken'); }
      if (fault.mode === 'partial') { res.writeHead(200, { 'content-length': '9999' }); res.write('{"user":'); return; }
      if (fault.mode === 'delay') await new Promise(resolve => setTimeout(resolve, 1500));
      try {
        const headers = { ...req.headers }; delete headers.host; delete headers.connection; delete headers['content-length'];
        const upstream = await fetch(`${req.url.startsWith('/__pulse/') ? urls.pulse : urls.id}${req.url.replace(/^\/__pulse/, '')}`, { method: req.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined, signal: AbortSignal.timeout(6000), redirect: 'manual' });
        let body = await upstream.text();
        if (fault.rewrite && upstream.ok) body = JSON.stringify(fault.rewrite(JSON.parse(body)));
        res.writeHead(upstream.status, { 'content-type': 'application/json', 'x-request-id': upstream.headers.get('x-request-id') || '' }); res.end(body);
      } catch { if (!res.destroyed) { res.writeHead(503); res.end('{}'); } }
    });
    servers.push(proxy); urls.proxy = await listen(proxy);
    const external = { mode: 'pass', messages: [], identity: { id: '900000000000000001', username: 'fixture-discord', email: 'discord@example.test', verified: true }, tokens: new Map(), codes: new Set() };
    const webhook = http.createServer(async (req, res) => {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString();
      if (req.url === '/api/tags') { res.setHeader('content-type', 'application/json'); return res.end('{"models":[{"name":"fixture-model"}]}'); }
      if (req.url === '/api/chat' || req.url === '/api/generate') {
        res.setHeader('content-type', 'application/json');
        return res.end(JSON.stringify({ message: { content: 'Local fixture answer' }, response: 'Local fixture answer', done: true, eval_count: 4 }));
      }
      if (req.url === '/api/oauth2/token') {
        const values = new URLSearchParams(body), code = values.get('code');
        if (!code || external.codes.has(code)) { res.writeHead(400); return res.end('{}'); }
        external.codes.add(code); const token = crypto.randomUUID();
        external.tokens.set(token, { ...external.identity });
        res.setHeader('content-type', 'application/json');
        return res.end(JSON.stringify({ access_token: token, refresh_token: crypto.randomUUID(), expires_in: 3600, token_type: 'Bearer', scope: 'identify email' }));
      }
      if (req.url === '/api/users/@me') {
        const identity = external.tokens.get((req.headers.authorization || '').replace('Bearer ', ''));
        res.writeHead(identity ? 200 : 401, { 'content-type': 'application/json' }); return res.end(JSON.stringify(identity || {}));
      }
      external.messages.push(JSON.parse(body));
      if (external.mode === 'timeout') return;
      res.writeHead(external.mode === '500' ? 500 : 204); res.end();
    });
    servers.push(webhook); urls.webhook = await listen(webhook);
    const secret = () => crypto.randomBytes(32).toString('hex');
    const config = {
      concurrency: 4,
      services: ['id', 'blueprint', 'contact'].map(id => ({ id, name: id, description: `${id} local service`, visibility: 'public', dependencies: id === 'blueprint' ? [{ serviceId: 'id', impact: 'degraded', reason: 'Sign-in unavailable' }] : [] })),
      probes: [ ['id', `${urls.proxy}/api/health`, { status: 'ok' }], ['blueprint', `${urls.blueprint}/healthz`, { ok: true }], ['contact', `${urls.contact}/api/health`, { ok: true }] ].map(([serviceId, url, expectedJson]) => ({ id: `${serviceId}-http`, serviceId, type: 'http', label: 'Local readiness', url, expectedJson, intervalMs: 1000, timeoutMs: 300, failureThreshold: 1, recoveryThreshold: 1 }))
    };
    fs.writeFileSync(path.join(directory, 'status-config.json'), JSON.stringify(config));
    // Compile the real Pulse source into the private run directory; never use stale dist.
    const ts = from('pulse', 'node_modules/typescript');
    const pulseBuild = path.join(directory, 'pulse-build'); fs.mkdirSync(pulseBuild);
    fs.writeFileSync(path.join(pulseBuild, 'package.json'), '{"type":"module"}');
    for (const entry of fs.readdirSync(path.join(root, 'pulse/server/src'))) {
      if (!entry.endsWith('.ts') || entry.endsWith('.test.ts')) continue;
      const source = fs.readFileSync(path.join(root, 'pulse/server/src', entry), 'utf8');
      fs.writeFileSync(path.join(pulseBuild, entry.replace(/\.ts$/, '.js')), ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.ES2022 } }).outputText);
    }
    const env = {
      PULSE_BUILD: pulseBuild, PULSE_PORT: String(ports.pulse), PULSE_HOST: '127.0.0.1', PULSE_AUTH_API_BASE_URL: urls.proxy, PULSE_AUTH_APPLICATION_ORIGIN: urls.pulse,
      PULSE_DB_PATH: path.join(directory, 'pulse.sqlite'), PULSE_EVENT_LOG_PATH: path.join(directory, 'pulse.ndjson'), PULSE_EXPORT_DIR: path.join(directory, 'pulse-exports'), PULSE_CORS_ORIGINS: urls.pulse,
      PATH: process.env.PATH, HOME: directory, NODE_ENV: 'test', ECOSYSTEM_ROOT: root,
      DOTENV_CONFIG_PATH: path.join(directory, 'absent.env'), HOST: '127.0.0.1',
      MONGO_URI: mongo.getUri('ecosystem'), JWT_SECRET: secret(), REFRESH_TOKEN_SECRET: secret(), MFA_TOKEN_SECRET: secret(),
      ALLOWED_ORIGINS: Object.values(urls).filter(url => url !== urls.webhook).join(','),
      IDENTITY_MANAGEMENT_ORIGINS: urls.id, ALLOW_LOCALHOST_ORIGINS: 'false', ALLOW_DEFAULT_TRUSTED_ORIGINS: 'false', RATE_LIMIT_MAX: '10000', AUTH_RATE_LIMIT_MAX_REQUESTS: '10000',
      CONTINENTAL_AUTH_BASE_URL: urls.proxy, CONTINENTAL_APPLICATION_ORIGIN: urls.stepcast, CONTINENTAL_AUTH_TIMEOUT_MS: '300', CORS_ORIGIN: urls.stepcast,
      TERRA_TREAD_DATA_DIR: path.join(directory, 'terra-tread'), TERRA_TREAD_STEP_LOG_PATH: path.join(directory, 'terra-tread', 'steps.log'),
      TERRA_TREAD_AUTH_API_BASE_URL: urls.proxy, TERRA_TREAD_APPLICATION_ORIGIN: urls.terra, TERRA_TREAD_AUTH_TIMEOUT_MS: '300',
      SSL_KEY_PATH: path.join(directory, 'absent-tls-key'), SSL_CERT_PATH: path.join(directory, 'absent-tls-cert'),
      AEGIS_ENABLE_PULSE: 'true', AEGIS_PULSE_PROJECT_ID: 'aegis', AEGIS_PULSE_COLLECT_URL: `${urls.proxy}/__pulse/v1/collect`, AEGIS_PULSE_HEALTH_URL: `${urls.proxy}/__pulse/api/health`, AEGIS_PULSE_TIMEOUT_MS: '200', AEGIS_PUBLIC_BASE_URL: urls.aegis,
      OLLAMA_BASE_URL: urls.webhook, MODEL_NAME: 'fixture-model', REQUEST_TIMEOUT_MS: '1000',
      EXTERNAL_OAUTH_URL: urls.webhook, DISCORD_CLIENT_SECRET: secret(), DISCORD_OAUTH_CALLBACK_URL: `${urls.id}/api/auth/oauth/discord/callback`,
      DISCORD_TOKEN: 'fake-gateway-token', DISCORD_CLIENT_ID: '123456789012345678', DISCORD_SESSION_SECRET: secret(),
      BASE_URL: urls.blueprint, AUTH_API_BASE_URL: urls.proxy, AUTH_LOGIN_POPUP_URL: `${urls.id}/popup.html`, AUTH_REQUEST_TIMEOUT_SECONDS: '1',
      DATA_DIR: path.join(directory, 'blueprint'), CONTINENTAL_ID_API: urls.proxy, SITE_ORIGIN: urls.status,
      STATUS_CONFIG_PATH: path.join(directory, 'status-config.json'), STATUS_DB_PATH: path.join(directory, 'status.sqlite'), STATUS_DATA_PATH: path.join(directory, 'absent.json'),
      DISCORD_CONTACT_WEBHOOK_URL: urls.webhook, VANGUARD_API_KEY: secret()
    };
    for (const repo of ['Dashboard', 'blueprint', 'status', 'contact', 'pulse', 'Aegis', 'Ai', 'discord-bots', 'continental-id-client', 'Grimoire', 'StepCast', 'Terra-Treck']) {
      const result = require('node:child_process').spawnSync('git', ['rev-parse', 'HEAD'], { cwd: path.join(root, repo), encoding: 'utf8' });
      const dirty = require('node:child_process').spawnSync('git', ['status', '--porcelain'], { cwd: path.join(root, repo), encoding: 'utf8' });
      report.revisions[repo] = { head: result.stdout.trim(), dirty: Boolean(dirty.stdout.trim()) };
    }
    for (const name of ['id', 'blueprint', 'contact', 'pulse', 'aegis', 'ai', 'stepcast', 'terra', 'status']) {
      const child = spawn(process.execPath, [path.join(__dirname, 'worker.cjs'), name], { cwd: directory, env: { ...env, PORT: String(ports[name]), MONGO_URI: mongo.getUri(name === 'stepcast' ? 'stepcast' : 'ecosystem') }, stdio: ['ignore', 'pipe', 'pipe'] });
      child.once('error', error => { child.startError = error; });
      children.push(child); report.events.push({ service: name, pid: child.pid, event: 'started' });
      const output = fs.createWriteStream(path.join(directory, `${name}.log`), { mode: 0o600 });
      child.stdout.pipe(output, { end: false }); child.stderr.pipe(output, { end: false }); child.once('exit', () => output.end());
      await ready(`${urls[name]}${ { id: '/api/health', blueprint: '/healthz', contact: '/api/health', status: '/live', pulse: '/api/health', aegis: '/api/health', ai: '/health', stepcast: '/api/health', terra: '/api/health' }[name]}`, child);
      if (options.failAtService === name) throw new Error('Injected startup failure');
    }
    let edgeProcess;
    if (require('node:child_process').spawnSync('caddy', ['version'], { env: { PATH: process.env.PATH }, stdio: 'ignore' }).status === 0) {
      const config = { admin: { disabled: true }, storage: { module: 'file_system', root: path.join(directory, 'caddy-data') }, apps: { http: { servers: { ecosystem: { listen: [`127.0.0.1:${ports.edge}`], automatic_https: { disable: true }, routes: [{ handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: `127.0.0.1:${ports.id}` }] }] }] } } } } };
      const configPath = path.join(directory, 'caddy.json'); fs.writeFileSync(configPath, JSON.stringify(config));
      edgeProcess = spawn('caddy', ['run', '--config', configPath], { cwd: directory, env: { PATH: process.env.PATH, HOME: directory, XDG_CONFIG_HOME: path.join(directory, 'caddy-config'), XDG_DATA_HOME: path.join(directory, 'caddy-data') }, stdio: ['ignore', 'pipe', 'pipe'] });
      children.push(edgeProcess); report.events.push({ service: 'edge', pid: edgeProcess.pid, event: 'started' });
      edgeProcess.once('error', error => { edgeProcess.startError = error; });
      const log = fs.createWriteStream(path.join(directory, 'edge.log'), { mode: 0o600 });
      edgeProcess.stdout.pipe(log, { end: false }); edgeProcess.stderr.pipe(log, { end: false }); edgeProcess.once('exit', () => log.end());
      await ready(`${urls.edge}/api/health`, edgeProcess);
    }
    const User = from('Dashboard', 'backend/models/User');
    const AuthApp = from('Dashboard', 'backend/models/AuthApp');
    for (const appId of ['blueprint', 'status', 'grimoire', 'pulse', 'vanguard', 'stepcast', 'terra-tread']) {
      const origin = appId === 'terra-tread' ? urls.terra : urls[appId] || 'https://grimoire.example.test';
      await AuthApp.findOneAndUpdate({ appId }, { displayName: appId, status: 'active', allowedOrigins: [origin], allowedRedirectOrigins: [origin] }, { upsert: true });
    }
    let serial = 0;
    async function user(overrides = {}) {
      const n = ++serial;
      const fixture = new User({ email: `fixture${n}@example.test`, username: `fixture${n}`, password: 'EcosystemStrongPass123!', displayName: `Fixture ${n}`, isVerified: true, ...overrides });
      await fixture.save(); return fixture;
    }
    async function login(fixture, targetOrigin = urls.blueprint) {
      const response = await fetch(`${urls.id}/api/auth/login`, { method: 'POST', headers: { Origin: urls.id, 'Content-Type': 'application/json' }, body: JSON.stringify({ email: fixture.email, password: 'EcosystemStrongPass123!', targetOrigin }) });
      const payload = await response.json();
      if (!response.ok || !payload.accessToken) throw new Error(`Fixture login failed: ${response.status} ${payload.error?.code}`);
      return { token: payload.accessToken, cookie: response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ') };
    }
    async function appToken(fixture, appId = 'blueprint') {
      const appOrigin = appId === 'terra-tread' ? urls.terra : urls[appId] || 'https://grimoire.example.test';
      const credentials = await login(fixture, appOrigin);
      const bootstrapOrigin = appId === 'terra-tread' ? urls.terra : urls[appId] || urls.id;
      const response = await fetch(`${urls.id}/api/auth/bootstrap`, { method: 'POST', headers: { Origin: bootstrapOrigin, 'Content-Type': 'application/json' }, body: JSON.stringify({ appId, accessToken: credentials.token }) });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(`Bootstrap failed: ${response.status} ${payload.error?.code || ''}`.trim());
      return payload.accessToken;
    }
    return { edgeProcess, trackChild: child => children.push(child), urls, fault, external, User, AuthApp, user, login, appToken, mongoose, mongo, env, report, directory, close: async () => { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); await close(); } };
  } catch (error) { await close(); throw error; }
}
module.exports = { boot, root, from, listen };
