const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const dir = path.resolve(__dirname, '../../ui/demonstrator/src');
const source = fs.readFileSync(path.join(dir, 'index.js'), 'utf8');
function fixture(state = 'logged out', fetchOverride) {
  let component, calls = 0;
  const timers = new Map(); let timerId = 0;
  const sandbox = {
    window: {location: {pathname: '/dev/facis-demo/'}, Vue: {
      defineComponent(c) { if (c.name === 'FacisZeroTrustDemo') component = c; return c; },
      createApp() { return {component() {}, mount() {}}; }
    }},
    document: {querySelector(s) { return s.includes('facis-auth-mode') ? {content: 'oidc'} : s === '#app' ? {} : null; }},
    setTimeout(fn, delay) { timers.set(++timerId, {fn, delay}); return timerId; },
    clearTimeout(id) { timers.delete(id); },
    AbortSignal, console,
    fetch: async () => { calls++; return fetchOverride ? fetchOverride() : {ok: state !== 'logged out' && state !== 'expired', json: async () => ({mode: 'oidc', state, role: 'ztd-operator', canOperate: true, csrf: 'test'})}; }
  };
  vm.runInNewContext(source, sandbox);
  const app = {...component.data(), isServicePending: false, canOperate: true, $refs: {}, $nextTick: fn => fn()};
  for (const [name, fn] of Object.entries(component.methods)) app[name] = fn.bind(app);
  app.syncStatus = async () => {};
  return {app, component, timers, calls: () => calls};
}
for (const state of ['logged out', 'expired']) test('session polling stops after ' + state + ' and does not repeat 401 requests', async () => {
  const f = fixture(state);
  f.component.mounted.call(f.app);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.calls(), 1); assert.equal(f.timers.size, 0);
  await f.app.pollIdentity(); assert.equal(f.calls(), 1);
});
test('authenticated polling preserves shared progress updates without overlapping requests', async () => {
  let release;
  const f = fixture('authenticated', () => new Promise(resolve => release = resolve));
  f.component.mounted.call(f.app);
  await f.app.pollIdentity(); assert.equal(f.calls(), 1);
  release({ok: true, json: async () => ({mode: 'oidc', state: 'authenticated', csrf: 'test', canOperate: true})});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.timers.size, 1); assert.equal([...f.timers.values()][0].delay, 2000);
});
test('session provider failures back off instead of repeatedly hammering the endpoint', async () => {
  const f = fixture('unavailable'); f.component.mounted.call(f.app);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal([...f.timers.values()][0].delay, 4000);
  await f.app.pollIdentity(); assert.equal([...f.timers.values()][0].delay, 8000);
});
test('unmounting during a session request does not restart polling', async () => {
  let release; const f = fixture('authenticated', () => new Promise(resolve => release = resolve));
  f.component.mounted.call(f.app); f.component.beforeUnmount.call(f.app);
  release({ok: true, json: async () => ({mode: 'oidc', state: 'authenticated', csrf: 'test'})});
  await new Promise(resolve => setImmediate(resolve)); assert.equal(f.timers.size, 0);
});
test('invalid measurement remains local, marks the field and focuses it without changing the session notice', async () => {
  const f = fixture(); const a = f.app; let focused = 0;
  a.identityMode = false; a.errorMessage = ''; a.draftConfig = {kind: 'measurement', target: 'zone-a-gateway', digest: 'bad'};
  a.$refs.measurementDigest = {focus() { focused++; }};
  await a.previewDraft(); assert.ok(a.configErrors.digest); assert.equal(focused, 1); assert.equal(a.errorMessage, ''); assert.equal(f.calls(), 0); assert.equal(a.draftPreview, null);
  a.draftConfig.digest = 'sha256:' + 'a'.repeat(64); a.clearConfigError('digest'); await a.previewDraft();
  assert.equal(a.configErrors.digest, undefined); assert.equal(a.draftPreview.payload.digest, a.draftConfig.digest);
});
test('missing policy inputs receive individual errors and focus the first missing field', async () => {
  const f = fixture(); const a = f.app; let focused = 0;
  a.identityMode = false; a.draftConfig = {kind: 'policy-ref', target: 'guard-a', bundle: '', revision: ''};
  a.$refs.policyBundle = {focus() { focused++; }};
  await a.previewDraft(); assert.ok(a.configErrors.bundle); assert.ok(a.configErrors.revision); assert.equal(focused, 1); assert.equal(f.calls(), 0);
});
test('approved branding and accessible configuration feedback are supplied', () => {
  for (const name of ['Facis-logo.svg', 'favicon-32x32.png', 'favicon-192x192.png', 'apple-touch-icon-180x180.png']) assert.ok(fs.statSync(path.join(dir, 'assets', name)).size > 0);
  assert.match(source, /alt="FACIS" width="63" height="22"/);
  assert.match(source, /aria-describedby="configErrors.digest/);
  const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  assert.match(html, /assets\/favicon-32x32.png/);
});
test('updated Vue template compiles including accessible field errors and progress states', () => {
  const f = fixture();
  const Vue = vm.runInNewContext(fs.readFileSync(path.join(dir, 'vendor/vue.global.js'), 'utf8') + ';Vue');
  const errors = [];
  Vue.compile(f.component.template, {decodeEntities: text => text.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&'), onError: e => errors.push(e.message)});
  assert.deepEqual(errors, []);
});
