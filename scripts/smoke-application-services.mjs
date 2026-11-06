#!/usr/bin/env node
// Checks sample services already running at explicitly supplied test URLs.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    'participant-url': { type: 'string', default: 'http://127.0.0.1:8085' },
    'resource-url': { type: 'string', default: 'http://127.0.0.1:8086' },
    help: { type: 'boolean', default: false },
  },
});
if (values.help) {
  console.log('Usage: node scripts/smoke-application-services.mjs [--participant-url URL] [--resource-url URL]');
  console.log('Requires Node.js 22+, Participant http-sample mode, Resource sample adapter, 2s slow delay.');
  process.exit(0);
}

async function request(url, payload) {
  const response = await fetch(url, {
    method: payload === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  return [response.status, await response.json()];
}

async function main() {
  const run = `smoke-${randomUUID()}`;
  let checks = 0;
  const scenarios = [
    ['success', 200, 200, 'success', 'SAMPLE_RESOURCE_RETURNED'],
    ['denied', 403, 403, 'denied', 'SAMPLE_ACCESS_DENIED'],
    ['unavailable', 503, 503, 'unavailable', 'SAMPLE_RESOURCE_UNAVAILABLE'],
    ['error', 500, 502, 'error', 'SAMPLE_RESOURCE_ERROR'],
    ['slow', 200, 200, 'success', 'SAMPLE_SLOW_RESOURCE_RETURNED'],
  ];
  for (const [service, baseURL, throughParticipant] of [
    ['resource', values['resource-url'], false],
    ['participant', values['participant-url'], true],
  ]) {
    const url = new URL(baseURL);
    assert(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.search && !url.hash,
      'Use an HTTP(S) base URL without credentials, query or fragment');
    const base = baseURL.replace(/\/+$/, '');
    const [status, health] = await request(`${base}/health`);
    assert.equal(status, 200, `${service}: health HTTP status`);
    assert.equal(health.status, 'ok', `${service}: unhealthy`);
    assert.equal(health.mode, 'sample', `${service}: unexpected mode`);
    assert.equal(health.liveMode, 'unavailable', `${service}: unexpected liveMode`);
    checks++;
    console.log('PASS', service, 'health');
    for (const [scenario, resourceStatus, participantStatus, outcome, reasonCode] of scenarios) {
      const requestId = `${run}-${service}-${scenario}`;
      const payload = { resource: 'sample-report', action: 'read', scenario, requestId, correlationId: run };
      const [status, body] = await request(`${base}/demo`, payload);
      const label = `${service}/${scenario}`;
      assert.equal(status, throughParticipant ? participantStatus : resourceStatus, `${label}: HTTP status`);
      for (const [key, value] of Object.entries({ requestId, correlationId: run, source: 'sample', mode: 'sample', outcome, reasonCode })) {
        assert.equal(body[key], value, `${label}: ${key}`);
      }
      assert(Number.isFinite(Date.parse(body.timestamp)), `${label}: invalid timestamp`);
      if (outcome === 'success') {
        assert.equal(body.safeData?.resource, 'sample-report', `${label}: resource`);
        assert.equal(body.safeData?.action, 'read', `${label}: action`);
        assert.equal(typeof body.safeData?.report?.id, 'string', `${label}: missing report`);
      } else {
        assert.deepEqual(body.safeData, {}, `${label}: unexpected failure payload`);
      }
      checks++;
      console.log('PASS', label, 'HTTP', status, reasonCode);
    }
  }
  console.log(`PASS: ${checks} sample HTTP checks; correlationId=${run}`);
  console.log('Scope: sample application integration only; no security acceptance claim.');
}

main().catch(error => {
  console.error('FAIL:', error.message);
  process.exitCode = 1;
});
