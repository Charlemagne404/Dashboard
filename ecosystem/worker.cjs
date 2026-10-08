// Isolated wrappers: production applications, fake Discord gateway only.
const path = require('node:path');
const root = process.env.ECOSYSTEM_ROOT;
const service = process.argv[2];
const realFetch = global.fetch;
global.fetch = (input, options) => {
  const url = new URL(input instanceof Request ? input.url : input);
  if (url.origin === 'https://discord.com' && url.pathname.startsWith('/api/'))
    return realFetch(`${process.env.EXTERNAL_OAUTH_URL}${url.pathname}`, options);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))
    throw new Error('Ecosystem worker refuses external network access');
  return realFetch(input, options);
};
if (service === 'id') {
  const provider = require(path.join(root, 'Dashboard/backend/server'));
  provider.app.use(require(path.join(root, 'Dashboard/backend/node_modules/express')).static(path.join(root, 'Dashboard/frontend/login')));
  provider.startServer();
}
if (service === 'status') require(path.join(root, 'status/server')).start();
if (service === 'contact') {
  const server = require(path.join(root, 'contact/server')).listen(Number(process.env.PORT), '127.0.0.1');
  process.on('SIGTERM', () => server.close(() => process.exit(0)));
}
if (service === 'blueprint') {
  const { app, client } = require(path.join(root, 'blueprint/src/index'));
  client.isReady = () => true; // No real Discord login or guild mutation.
  const server = app.listen(Number(process.env.PORT), '127.0.0.1');
  process.on('SIGTERM', () => server.close(() => { client.destroy(); process.exit(0); }));
}

if (service === 'pulse') {
  (async () => {
    const { pathToFileURL } = require('node:url');
    const { createPulseServer } = await import(pathToFileURL(path.join(process.env.PULSE_BUILD, 'app.js')));
    const { loadConfig } = await import(pathToFileURL(path.join(process.env.PULSE_BUILD, 'config.js')));
    const config = loadConfig(); const server = createPulseServer(config);
    server.listen(config.port, config.host);
    process.on('SIGTERM', () => server.close(() => process.exit(0)));
  })().catch(() => process.exit(1));
}

if (service === 'ai') require(path.join(root, 'Ai/server'));
if (service === 'aegis') {
  (async () => {
    const { pathToFileURL } = require('node:url');
    const { createServer } = await import(pathToFileURL(path.join(root, 'Aegis/server/index.js')));
    const { loadConfig } = await import(pathToFileURL(path.join(root, 'Aegis/server/config.js')));
    const server = createServer(loadConfig(process.cwd()));
    server.listen(Number(process.env.PORT), '127.0.0.1');
    process.on('SIGTERM', () => server.close(() => process.exit(0)));
  })().catch(() => process.exit(1));
}

if (service === 'stepcast') require(path.join(root, 'StepCast/backend/server'));
if (service === 'terra') {
  const terra = require(path.join(root, 'Terra-Treck/backend/index'));
  const server = terra.createServer();
  server.listen(Number(process.env.PORT), '127.0.0.1');
  process.on('SIGTERM', () => server.close(() => process.exit(0)));
}
