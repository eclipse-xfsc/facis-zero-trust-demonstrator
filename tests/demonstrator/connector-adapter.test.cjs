const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { createPublicKey, verify, createHash } = require('node:crypto');
const adapter = import('../../flows/demonstrator/connector-adapter.mjs');
const ids = { requestId: 'request-1', correlationId: 'correlation-1' };

async function fixture(t, options = {}) {
  const requests = [], seen = new Set(), challenges = new Set(), keys = new Map();
  const server = http.createServer(async (req, res) => {
    try {
      const parts = []; for await (const part of req) parts.push(part);
      const raw = Buffer.concat(parts).toString();
      const form = new URLSearchParams(raw);
      const client = Buffer.from((req.headers.authorization || '').slice(6), 'base64').toString().split(':')[0];
      const stage = req.url === '/register' ? 'registration' : req.url.startsWith('/resource') ? 'resource' : client === 'registrar' ? 'bootstrap' : 'token';
      requests.push({ stage, authorization: req.headers.authorization, correlationId: req.headers['x-correlation-id'], requestId: req.headers['x-request-id'] });
      const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
      if (options.delay === stage) { await new Promise(resolve => setTimeout(resolve, 70)); if (res.destroyed) return; }
      if (options.fail === stage) return send(options.status || 403, { error: 'access_denied', reason: options.reason || 'insufficient_scope', error_description: 'private-upstream-detail' });
      if (options.redirect === stage) { res.writeHead(302, { location: '/leak' }); return res.end(); }
      let proof;
      if (stage !== 'registration' || options.boundBootstrap) {
        assert.ok(req.headers.dpop, stage + ' needs a proof');
        const [head, claims, signature] = req.headers.dpop.split('.');
        const header = JSON.parse(Buffer.from(head, 'base64url'));
        proof = JSON.parse(Buffer.from(claims, 'base64url'));
        assert.equal(header.typ, 'dpop+jwt'); assert.equal(header.alg, 'ES256'); assert.equal(header.jwk.d, undefined);
        assert.ok(verify('sha256', Buffer.from(head + '.' + claims), { key: createPublicKey({ key: header.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')));
        assert.equal(proof.htm, req.method); assert.equal(proof.htu, (options.proofHTTPS ? origin.replace('http:', 'https:') : origin) + req.url.split('?')[0]);
        assert.ok(Math.abs(proof.iat - Date.now() / 1000) < 5); assert.ok(!seen.has(proof.jti)); seen.add(proof.jti);
        if (stage === 'resource' || stage === 'registration') {
          const token = stage === 'resource' ? 'resource-token' : 'registrar-token';
          assert.equal(proof.ath, createHash('sha256').update(token).digest('base64url'));
          assert.equal(req.headers.authorization, 'DPoP ' + token);
          assert.deepEqual(header.jwk, keys.get(stage === 'resource' ? 'token' : 'bootstrap'));
        } else { assert.equal(proof.ath, undefined); keys.set(stage, header.jwk); }
      }
      if (options.nonce && (stage !== 'registration' || options.boundBootstrap)) {
        if (!proof.nonce || options.repeatedNonce) {
          challenges.add(stage); res.setHeader('DPoP-Nonce', 'nonce-' + stage);
          return send(400, { error: 'use_dpop_nonce', reason: 'dpop_use_nonce' });
        }
        assert.equal(proof.nonce, 'nonce-' + stage);
      }
      if (options.malformed === stage) { res.writeHead(200); return res.end('invalid JSON'); }
      if (stage === 'bootstrap') {
        assert.equal(req.headers.authorization, 'Basic ' + Buffer.from('registrar:registrar-secret').toString('base64'));
        assert.equal(form.get('audience'), (options.proofHTTPS ? origin.replace('http:', 'https:') : origin) + '/register');
        assert.equal(form.get('scope'), 'connector:client_registration report:read');
        return send(200, { access_token: 'registrar-token', token_type: options.boundBootstrap ? 'DPoP' : 'Bearer', expires_in: 300 });
      }
      if (stage === 'registration') {
        if (!options.boundBootstrap) assert.equal(req.headers.authorization, 'Bearer registrar-token');
        const metadata = JSON.parse(raw);
        assert.deepEqual(metadata.grant_types, ['client_credentials']);
        assert.equal(metadata.token_endpoint_auth_method, 'client_secret_basic');
        assert.equal(metadata.scope, 'report:read'); assert.equal(metadata.dpop_bound_access_tokens, true);
        return send(201, { client_id: 'participant', client_secret: options.specialSecret ? 'secret +:@' : 'participant-secret', dpop_bound_access_tokens: !options.unboundRegistration });
      }
      if (stage === 'token') {
        const escaped = options.specialSecret ? 'secret+%2B%3A%40' : 'participant-secret';
        assert.equal(req.headers.authorization, 'Basic ' + Buffer.from('participant:' + escaped).toString('base64'));
        assert.equal(form.get('grant_type'), 'client_credentials'); assert.equal(form.get('scope'), 'report:read');
        return send(200, { access_token: 'resource-token', token_type: options.bearer ? 'Bearer' : 'DPoP', expires_in: options.expired ? 0 : 300, scope: options.wrongScope ? 'other' : 'report:read' });
      }
      if (stage === 'resource') {
        if (options.large) { res.writeHead(200); return res.end(JSON.stringify({ value: 'x'.repeat(70000) })); }
        if (req.method === 'POST') assert.deepEqual(JSON.parse(raw), { resource: 'sample-report', action: 'read' });
        return send(200, { resource: 'sample-report', report: { id: 'sample-1', content: 'local contract response' } });
      }
      send(404, {});
    } catch (error) { errors.push(error); res.writeHead(500); res.end('{}'); }
  });
  const errors = [];
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const origin = 'http://127.0.0.1:' + server.address().port;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); assert.deepEqual(errors, []); });
  const config = { mode: 'local-contract', tokenURL: origin + '/token', registrationURL: origin + '/register', protectedURL: origin + '/resource?view=sample', registrarClientId: 'registrar', registrarClientSecret: 'registrar-secret', scope: 'report:read', timeoutMs: 1000, ...options.config };
  const { createConnectorAdapter } = await adapter;
  return { app: createConnectorAdapter(config), requests, challenges, config, createConnectorAdapter };
}

test('local Connector contract: registration, bound token and protected response share correlation IDs and emit sanitized events', async t => {
  const f = await fixture(t); const result = await f.app.run(ids);
  assert.equal(result.ok, true); assert.equal(result.mode, 'local-contract'); assert.equal(result.data.resource, 'sample-report');
  assert.deepEqual(f.requests.map(r => r.stage), ['bootstrap', 'registration', 'token', 'resource']);
  for (const r of f.requests) { assert.equal(r.correlationId, ids.correlationId); assert.equal(r.requestId, ids.requestId); }
  for (const e of result.events) { assert.equal(e.correlationId, ids.correlationId); assert.ok(Date.parse(e.timestamp)); }
  assert.ok(!/secret|resource-token|registrar-token|private-upstream-detail/.test(JSON.stringify(result.events)));
  await f.app.run({ requestId: 'request-2', correlationId: 'correlation-2' });
  assert.equal(f.requests.filter(r => r.stage === 'registration').length, 1);
});
test('fresh DPoP proofs handle nonce challenges at token, registration and resource endpoints', async t => {
  const f = await fixture(t, { nonce: true, boundBootstrap: true }); const result = await f.app.run(ids);
  assert.equal(result.ok, true); assert.equal(f.challenges.size, 4);
});
test('a repeated nonce challenge has a bounded retry and never reaches the resource', async t => {
  const f = await fixture(t, { nonce: true, repeatedNonce: true }); const result = await f.app.run(ids);
  assert.equal(result.ok, false); assert.equal(result.reasonCode, 'dpop_use_nonce'); assert.equal(f.requests.length, 2);
});
for (const stage of ['bootstrap', 'registration', 'token', 'resource']) test('refusal at ' + stage + ' stops the path without direct-call fallback or credential disclosure', async t => {
  const f = await fixture(t, { fail: stage }); const result = await f.app.run(ids);
  assert.equal(result.ok, false); assert.equal(result.reasonCode, 'insufficient_scope'); assert.equal(result.data, undefined);
  assert.equal(f.requests.at(-1).stage, stage); assert.equal(result.events.at(-1).event, 'request.refused');
  assert.ok(!/secret|resource-token|registrar-token|private-upstream-detail/.test(JSON.stringify(result)));
});
for (const option of ['bearer', 'expired', 'wrongScope', 'unboundRegistration']) test('rejects unsafe response: ' + option, async t => {
  const f = await fixture(t, { [option]: true }); const result = await f.app.run(ids);
  assert.equal(result.ok, false); assert.equal(f.requests.some(r => r.stage === 'resource'), false);
});
test('HTTP redirects are refused before credentials can be forwarded', async t => {
  const f = await fixture(t, { redirect: 'token' }); const result = await f.app.run(ids);
  assert.equal(result.ok, false); assert.equal(result.status, 302); assert.ok(f.requests.every(r => r.stage !== 'resource'));
});
test('malformed JSON and oversized protected responses never produce success', async t => {
  for (const options of [{ malformed: 'resource' }, { large: true }]) {
    const f = await fixture(t, options); const result = await f.app.run(ids); assert.equal(result.ok, false); assert.equal(result.data, undefined);
  }
});
test('one deadline bounds the complete path including response bodies', async t => {
  const f = await fixture(t, { delay: 'bootstrap', config: { timeoutMs: 15 } }); const result = await f.app.run(ids);
  assert.equal(result.ok, false); assert.equal(result.reasonCode, 'CONNECTOR_TIMEOUT');
});
test('unreachable Connector fails closed', async t => {
  const f = await fixture(t);
  // Use a port that has been allocated and then closed, without an external network call.
  const closed = http.createServer(); closed.listen(0, '127.0.0.1'); await once(closed, 'listening'); const port = closed.address().port; await new Promise(resolve => closed.close(resolve));
  const unavailable = f.createConnectorAdapter({ ...f.config, tokenURL: 'http://127.0.0.1:' + port + '/token' });
  assert.equal((await unavailable.run(ids)).reasonCode, 'CONNECTOR_UNAVAILABLE');
});
test('POST supports server-selected protected payloads and OAuth Basic form escaping', async t => {
  const f = await fixture(t, { specialSecret: true, config: { method: 'POST' } });
  assert.equal((await f.app.run({ ...ids, payload: { resource: 'sample-report', action: 'read' } })).ok, true);
});
test('configuration and identifiers are rejected before any network call', async t => {
  const f = await fixture(t);
  for (const change of [{ mode: 'live' }, { scope: 'connector:client_registration' }, { protectedURL: 'http://example.com/resource' }, { tokenURL: 'https://user:password@example.com/token' }, { timeoutMs: 0 }, { method: 'DELETE' }]) assert.throws(() => f.createConnectorAdapter({ ...f.config, ...change }), /CONNECTOR_CONFIG_INVALID/);
  await assert.rejects(f.app.run({ ...ids, correlationId: 'bad\r\nHeader: injection' }), /CONNECTOR_IDENTIFIER_INVALID/);
  await assert.rejects(f.app.run({ ...ids, payload: {} }), /CONNECTOR_PAYLOAD_INVALID/);
  assert.equal(f.requests.length, 0);
});

async function runFlow(config, msg = {payload:{}}, options = {}) {
  const fs = require('node:fs'), path = require('node:path');
  const root = path.resolve(__dirname, '../..');
  const nodes = JSON.parse(fs.readFileSync(path.join(root, 'flows/demonstrator/connector-adapter-flow.json')));
  const combined = JSON.parse(fs.readFileSync(path.join(root, 'flows/demonstrator/current-facis-flows.json')));
  for (const n of nodes) assert.deepEqual(combined.find(c => c.id === n.id), n);
  const engine = nodes.find(n => n.id === 'facis-connector-run');
  assert.equal(engine.func, fs.readFileSync(path.join(root, 'flows/demonstrator/connector-flow-run.js'), 'utf8'));
  assert.equal(nodes.find(n => n.type === 'inject').once, false);
  const statuses = [];
  const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
  const fn = new AsyncFunction('msg', 'env', 'node', 'nodeCrypto', 'nodeHTTP', 'nodeHTTPS', 'nodeURL', 'nodeUtil', 'Buffer', 'setTimeout', 'clearTimeout', engine.func);
  // Only the test harness maps HTTPS to its numeric-loopback contract server.
  // The shipped flow uses Node's unmodified HTTPS transport.
  const testTransport = {request(url, opts, callback) {
    assert.equal(opts.rejectUnauthorized, undefined);
    const target = new URL(url); target.protocol = 'http:';
    return http.request(target, opts, callback);
  }};
  const result = await fn(msg, {get:k=>config[k]}, {status:s=>statuses.push(s)}, require('node:crypto'), http, options.localHTTPS ? testTransport : require('node:https'), require('node:url'), require('node:util'), Buffer, setTimeout, clearTimeout);
  return {result, statuses};
}
function flowEnv(config) {
  return {CONNECTOR_ADAPTER_ENABLED:'true', CONNECTOR_TOKEN_URL:config.tokenURL.replace('http:', 'https:'), CONNECTOR_REGISTRATION_URL:config.registrationURL.replace('http:', 'https:'), CONNECTOR_PROTECTED_URL:config.protectedURL.replace('http:', 'https:'), CONNECTOR_REGISTRAR_CLIENT_ID:config.registrarClientId, CONNECTOR_REGISTRAR_CLIENT_SECRET:config.registrarClientSecret, CONNECTOR_SCOPE:config.scope};
}
test('importable flow is disabled by default, has no automatic inject and matches standalone source', async () => {
  const f = await runFlow({}); assert.equal(f.result[0].payload.reasonCode, 'CONNECTOR_NOT_ENABLED'); assert.equal(f.result[1], null);
});
test('embedded Node-RED flow executes the contract through standard transports and emits separate sanitized events', async t => {
  const f = await fixture(t, {proofHTTPS:true});
  const run = await runFlow(flowEnv(f.config), {payload:{tokenURL:'https://unapproved.invalid'}}, {localHTTPS:true});
  assert.equal(run.result[0].payload.ok, true); assert.equal(run.result[1].length, 5);
  const cid = run.result[0].payload.correlationId;
  assert.ok(f.requests.every(r => r.correlationId === cid));
  assert.ok(!/secret|resource-token|registrar-token/.test(JSON.stringify(run.result[1])));
});
test('embedded flow refuses cleartext live endpoints before sending any request', async t => {
  const f = await fixture(t); const env = flowEnv(f.config); env.CONNECTOR_TOKEN_URL = f.config.tokenURL;
  const run = await runFlow(env); assert.equal(run.result[0].payload.reasonCode, 'CONNECTOR_CONFIG_INVALID'); assert.equal(f.requests.length, 0);
});
test('embedded transport honors nonce retry and stops on registration refusal', async t => {
  const f = await fixture(t, {proofHTTPS:true,nonce:true,fail:'registration'});
  const run = await runFlow(flowEnv(f.config), {payload:{}}, {localHTTPS:true});
  assert.equal(run.result[0].payload.reasonCode, 'insufficient_scope'); assert.equal(f.requests.at(-1).stage, 'registration');
});
