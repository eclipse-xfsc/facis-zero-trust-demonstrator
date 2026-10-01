// Steps for TDR-BDD-06: a controlled error is triggered through the ORCE lifecycle workflow; its
// log record must be structured JSON and its machine-readable error must be in the ORCE context.
// It runs in its own pool namespace with the lifecycle hooks (see lifecycle.steps.mjs).
import { Given, When, Then } from '@cucumber/cucumber'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { INVALID, command, finalResult, assertSameCluster, refusalLogEntry } from './lifecycle.steps.mjs'

const RECORD_FIELDS = ['time', 'level', 'type', 'name', 'id', 'msg']

Given('a controlled error condition', function () {
  // Values the release's own schema rejects: accepted by ORCE, refused by Helm while it runs.
  this.controlled = INVALID['chart value rejected'](this)
})

When('it is triggered', async function () {
  const sent = await command(this, 'deploy', {
    release: this.release, namespace: this.namespace, chart: this.target.chart, values: this.controlled.values
  })
  this.triggered = { ...sent, result: await finalResult(this, sent.requestId) }
})

Then('the corresponding log is structured JSON and the machine-readable error is available through the ORCE context.', async function () {
  const { status, result, requestId } = this.triggered
  assert.equal(status, 202, 'the command was not accepted, so the error did not come from the workflow')
  assert.equal(result.ok, false, 'the controlled error did not fail')
  assert.equal(result.errors && result.errors.action, this.controlled.action, `unexpected error: ${JSON.stringify(result.errors)}`)
  assertSameCluster(this, result)

  const found = await refusalLogEntry(this, requestId)
  assert.ok(found, `no whole-line JSON log record for the refusal of ${requestId}`)
  assert.deepEqual(Object.keys(found.record), RECORD_FIELDS, 'the log record does not have the documented fields')
  assert.equal(found.record.type, 'ztd-lifecycle')
  assert.equal(found.entry.reason, this.controlled.action)
  for (const [name, secret] of [
    ['the ORCE HTTP password', process.env.BDD_ORCE_HTTP_PASS],
    ['the ORCE HTTP credentials', this.target.httpAuth.slice('Basic '.length)],
    ['the ORCE read token', this.target.adminToken]
  ]) {
    assert.ok(!found.line.includes(secret), `the log record contains ${name}`)
  }
  writeFileSync(`${this.evidence}/log-record.json`, found.line + '\n')
  // A sample of the real log around it, as the TDR evidence of the format.
  writeFileSync(`${this.evidence}/log-sample.log`, found.log.split('\n').slice(-200).join('\n'))
})
