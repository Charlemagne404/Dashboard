const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const destination = path.resolve(process.argv[2] || path.join(process.cwd(), 'artifacts/ecosystem'));
fs.mkdirSync(destination, { recursive: true });

const directories = fs.readdirSync(os.tmpdir())
  .filter(name => name.startsWith('continental-ecosystem-'))
  .map(name => path.join(os.tmpdir(), name))
  .filter(directory => fs.existsSync(path.join(directory, 'report.json')))
  .sort((left, right) => fs.statSync(left).mtimeMs - fs.statSync(right).mtimeMs);

directories.forEach((directory, index) => {
  const source = JSON.parse(fs.readFileSync(path.join(directory, 'report.json'), 'utf8'));
  const report = {
    schemaVersion: 1,
    revisions: Object.fromEntries(Object.entries(source.revisions || {}).map(([name, revision]) => [name, {
      head: String(revision?.head || '').slice(0, 40),
      dirty: Boolean(revision?.dirty),
    }])),
    events: (source.events || []).map(event => ({
      ...(event.service ? { service: event.service } : {}),
      ...(event.event ? { event: event.event } : {}),
      ...(event.scenario ? { scenario: event.scenario } : {}),
      ...(event.created !== undefined ? { created: Boolean(event.created) } : {}),
    })),
    requests: (source.requests || []).map(request => ({
      method: String(request.method || '').slice(0, 12),
      path: String(request.path || '')
        .split('?')[0]
        .replace(/\/[^/]+@[^/]+/g, '/:redacted')
        .replace(/\/[0-9a-f-]{16,}/gi, '/:id')
        .replace(/\/[0-9]{3,}/g, '/:id')
        .replace(/\/[^/]{36,}/g, '/:value')
        .slice(0, 180),
      mode: String(request.mode || '').slice(0, 24),
    })),
  };
  fs.writeFileSync(path.join(destination, `run-${String(index + 1).padStart(2, '0')}.json`), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });

  if (process.env.ECOSYSTEM_UPLOAD_SCREENSHOTS === 'true') {
    const screenshot = path.join(directory, 'browser-account.png');
    if (fs.existsSync(screenshot)) {
      fs.copyFileSync(screenshot, path.join(destination, `run-${String(index + 1).padStart(2, '0')}-browser-account.png`));
    }
  }
});

console.log(`Collected ${directories.length} sanitized ecosystem report(s) in ${destination}`);
