const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { boot } = require('./harness.cjs');
test('failed startup cleans service processes and the disposable MongoDB', async () => {
  const before = new Set(fs.readdirSync(os.tmpdir()));
  await assert.rejects(boot({ failAtService: 'terra' }), /Injected startup failure/);
  const directories = fs.readdirSync(os.tmpdir()).filter(name => name.startsWith('continental-ecosystem-') && !before.has(name));
  assert.equal(directories.length, 1);
  const report = JSON.parse(fs.readFileSync(path.join(os.tmpdir(), directories[0], 'report.json')));
  for (const pid of [...report.events.filter(event => event.event === 'started').map(event => event.pid), report.mongoPid].filter(Boolean)) {
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  }
});
