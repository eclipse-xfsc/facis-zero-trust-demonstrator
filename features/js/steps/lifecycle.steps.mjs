// Steps for the deployment-lifecycle rows TDR-BDD-01..04. A command goes to the ORCE workflow,
// its final result is read back from the ORCE context, and the outcome is decided from the
// cluster by scripts/bdd/cluster-state.sh with the read-only observer identity.
import { Before, After, Given, When, Then, setDefaultTimeout } from '@cucumber/cucumber'
import assert from 'node:assert/strict'
import { execFile, exec } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { loadTarget, baselineValues } from '../support/target.mjs'

const run = promisify(execFile)
const shell = promisify(exec)
const repoRoot = fileURLToPath(new URL('../../../', import.meta.url))
const clusterState = `${repoRoot}scripts/bdd/cluster-state.sh`
const RESULT_DEADLINE_MS = 8 * 60 * 1000

// A deploy waits for readiness inside ORCE; the step waits for its result.
setDefaultTimeout(15 * 60 * 1000)

// --- helpers ---------------------------------------------------------------------------------

async function observe (world, expect, { expected = [], recordBaseline = false, deadline } = {}) {
  const dir = world.evidence
  const args = ['--namespace', world.namespace, '--release', world.release, '--expect', expect]
  writeFileSync(`${dir}/expected.json`, JSON.stringify(expected))
  args.push('--expected', `${dir}/expected.json`)
  if (recordBaseline) args.push('--record-baseline', `${dir}/baseline.json`)
  else args.push('--baseline', `${dir}/baseline.json`)
  if (deadline !== undefined) args.push('--deadline', String(deadline))
  let stdout
  try {
    ({ stdout } = await run(clusterState, args, { env: { ...process.env, KUBECONFIG: world.target.kubeconfig }, maxBuffer: 64 << 20 }))
  } catch (error) {
    if (error.code === 2 || !error.stdout) throw new Error(`the cluster could not be observed: ${error.stdout || error.message}`)
    stdout = error.stdout
  }
  const state = JSON.parse(stdout)
  world.observations = (world.observations || 0) + 1
  writeFileSync(`${dir}/inventory-${world.observations}-${expect}.json`, JSON.stringify(state, null, 2))
  return state
}

function assertHolds (state, what) {
  assert.equal(state.converged, true, `${what}:\n  ${state.violations.join('\n  ')}`)
}

async function command (world, action, payload) {
  const requestId = `${world.release}-${randomUUID().slice(0, 8)}`
  const body = { type: 'command', action, requestId, payload, meta: { source: 'bdd', row: world.row } }
  const response = await fetch(`${world.target.orceUrl}/lifecycle`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: world.target.httpAuth },
    body: JSON.stringify(body)
  })
  const ack = await response.json()
  world.commands.push({ requestId, action, status: response.status, ack })
  return { requestId, status: response.status, ack }
}

// The final result, read from the ORCE flow context through the read-only admin API.
async function finalResult (world, requestId) {
  const started = Date.now()
  while (Date.now() - started < RESULT_DEADLINE_MS) {
    const response = await fetch(`${world.target.orceUrl}/context/flow/ztd-lifecycle-tab/lifecycle`, {
      headers: { authorization: `Bearer ${world.target.adminToken}` }
    })
    assert.equal(response.status, 200, `the ORCE context could not be read (HTTP ${response.status})`)
    const entry = await response.json()
    const context = entry && entry.msg ? JSON.parse(entry.msg) : null
    const job = context && context.jobs && context.jobs[requestId]
    if (job && job.result) {
      writeFileSync(`${world.evidence}/context-${requestId}.json`, JSON.stringify(job, null, 2))
      return job.result
    }
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }
  throw new Error(`no final result for ${requestId} in the ORCE context`)
}

async function deploy (world, values = world.values, payload = {}) {
  const sent = await command(world, 'deploy', { release: world.release, namespace: world.namespace, chart: world.target.chart, values, ...payload })
  return { ...sent, result: await finalResult(world, sent.requestId) }
}

// Fails if ORCE and the observer are not looking at the same cluster.
function assertSameCluster (world, result) {
  if (result.data && result.data.clusterId) {
    assert.equal(result.data.clusterId, world.clusterId, 'ORCE deployed to a different cluster than the one observed')
  }
}

// --- lifecycle -------------------------------------------------------------------------------

Before({ tags: '@cluster' }, async function (scenario) {
  this.target = loadTarget()
  const tags = scenario.pickle.tags.map((t) => t.name)
  const row = tags.find((t) => /^@TDR-BDD-0[1-4]$/.test(t))
  assert.ok(row, 'a lifecycle scenario carries its TDR-BDD row tag')
  this.row = row.slice(1)
  const n = row.slice(-2)
  this.namespace = `ztd-bdd-tdr-0${n}`
  this.release = `ztd-bdd-${this.target.run}-${n}`.slice(0, 53).replace(/-+$/, '')
  const example = scenario.pickle.name.includes(' - ') ? scenario.pickle.name.split(' - ').pop() : 'main'
  this.evidence = `${repoRoot}bundles/bdd/evidence/bdd-tdr-00${n.slice(-1)}/${this.target.name}/${example.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`
  mkdirSync(this.evidence, { recursive: true })
  this.values = baselineValues()
  this.commands = []

  // The pool namespace exists, holds only its baseline, and has no release: record the baseline.
  const before = await observe(this, 'absent', { recordBaseline: true, deadline: 30 })
  assertHolds(before, 'the pool namespace is not in its baseline state before the scenario')
  this.clusterId = before.clusterId
  this.crdsBefore = before.crds
})

After({ tags: '@cluster' }, async function () {
  if (!this.target) return
  writeFileSync(`${this.evidence}/commands.json`, JSON.stringify(this.commands, null, 2))
  writeFileSync(`${this.evidence}/scenario.json`, JSON.stringify({
    row: this.row, target: this.target.name, run: this.target.run, namespace: this.namespace,
    release: this.release, chart: this.target.chart, clusterId: this.clusterId,
    fixture: this.target.chart.includes('lifecycle-fixture')
  }, null, 2))
  // Leave the pool namespace as it was found, through the same workflow.
  const leftover = await observe(this, 'absent', { expected: this.expected || [], deadline: 0 })
  if (!leftover.converged) {
    const { requestId } = await command(this, 'uninstall', { release: this.release, namespace: this.namespace })
    await finalResult(this, requestId)
  }
  assertHolds(await observe(this, 'absent', { expected: this.expected || [] }), 'the pool namespace was not restored')
})

// --- TDR-BDD-01 ------------------------------------------------------------------------------

Given('an approved release and target cluster', function () {
  assert.ok(this.target.chart, 'a release under test is given')
})

When('the Helm\\/ORCE deployment workflow is executed', async function () {
  this.deployed = await deploy(this)
})

Then('all required resources are created and the release reaches Ready state without manual intervention', async function () {
  const { status, result } = this.deployed
  assert.equal(status, 202, 'the command was not accepted')
  assert.equal(result.ok, true, `the deployment failed: ${JSON.stringify(result.errors)}`)
  assertSameCluster(this, result)
  this.expected = result.data.expected
  assertHolds(await observe(this, 'present', { expected: this.expected }), 'the release is not complete and ready')
})

// --- TDR-BDD-02 ------------------------------------------------------------------------------

const INVALID = {
  // rejected by the Builder Node before anything runs
  'release name missing': (world) => ({ payload: { release: undefined }, fields: 'release' }),
  'values of the wrong type': (world) => ({ values: 'two', fields: 'values' }),
  // rejected by the chart's own values schema
  'chart value rejected': (world) => {
    const { message, ...rest } = world.values
    return { values: rest, action: 'valuesSchemaRejected' }
  }
}

Given('invalid or incomplete deployment parameters: {}', function (example) {
  assert.ok(INVALID[example], `unknown invalid-parameter example: ${example}`)
  this.invalid = INVALID[example](this)
})

When('the deployment workflow is executed', async function () {
  const { values = this.values, payload = {} } = this.invalid
  const body = { release: this.release, namespace: this.namespace, chart: this.target.chart, values, ...payload }
  if (payload.release === undefined && 'release' in payload) delete body.release
  const sent = await command(this, 'deploy', body)
  this.refused = { ...sent, result: await finalResult(this, sent.requestId) }
})

Then('deployment fails cleanly, returns a machine-readable error via the automation context, and no partial trusted state is left behind', async function () {
  const { result, requestId } = this.refused
  assert.equal(result.ok, false, 'the invalid deployment was not refused')
  if (this.invalid.fields) {
    assert.ok(result.errors && result.errors.fields && result.errors.fields[this.invalid.fields],
      `the error does not name the parameter ${this.invalid.fields}: ${JSON.stringify(result.errors)}`)
  } else {
    assert.equal(result.errors && result.errors.action, this.invalid.action, `unexpected error: ${JSON.stringify(result.errors)}`)
    assertSameCluster(this, result)
  }
  // The refusal is recorded in the ORCE log as a structured entry carrying this request.
  const { stdout } = await shell(this.target.logsCommand, { maxBuffer: 64 << 20 })
  const entry = stdout.split('\n').map((line) => line.slice(line.indexOf('{'))).find((line) => {
    try { const e = JSON.parse(line); return e.event === 'lifecycle.refused' && e.requestId === requestId } catch { return false }
  })
  assert.ok(entry, `no structured refusal entry for ${requestId} in the ORCE log`)
  writeFileSync(`${this.evidence}/refusal-log-entry.json`, entry)
  // Nothing of the release exists, and no CRD appeared.
  const after = await observe(this, 'absent')
  assertHolds(after, 'a partial deployment was left behind')
  assert.deepEqual(after.crds, this.crdsBefore, 'the CRD set changed')
})

// --- TDR-BDD-03 ------------------------------------------------------------------------------

Given('a successfully deployed release', async function () {
  this.first = await deploy(this)
  assert.equal(this.first.result.ok, true, `the first deployment failed: ${JSON.stringify(this.first.result.errors)}`)
  assertSameCluster(this, this.first.result)
  this.expected = this.first.result.data.expected
  this.inventoryA = await observe(this, 'present', { expected: this.expected })
  assertHolds(this.inventoryA, 'the first deployment is not complete and ready')
})

When('the same release is deployed again', async function () {
  this.second = await deploy(this)
})

Then('the operation completes successfully and the resulting Kubernetes state remains consistent and ready', async function () {
  const { result, requestId } = this.second
  assert.notEqual(requestId, this.first.requestId, 'the redeploy must be a distinct execution')
  assert.equal(result.ok, true, `the redeployment failed: ${JSON.stringify(result.errors)}`)
  assertSameCluster(this, result)
  assert.equal(result.data.revision, this.first.result.data.revision + 1, 'the redeploy did not produce the next revision')
  // Checked against the first deployment's expected list, so a replaced object (new UID) fails.
  const b = await observe(this, 'present', { expected: this.expected })
  assertHolds(b, 'the redeployed release is not consistent and ready')
  const replicaSets = (state) => state.classes.descendants.filter((d) => d.kind === 'ReplicaSet').map((d) => d.uid).sort()
  assert.deepEqual(replicaSets(b), replicaSets(this.inventoryA), 'an unchanged redeploy started a new rollout')
})

// --- TDR-BDD-04 ------------------------------------------------------------------------------

Given('a deployed release', async function () {
  const { result } = await deploy(this)
  assert.equal(result.ok, true, `the deployment failed: ${JSON.stringify(result.errors)}`)
  assertSameCluster(this, result)
  this.expected = result.data.expected
  assertHolds(await observe(this, 'present', { expected: this.expected }), 'the release is not complete and ready')
})

When('the uninstall workflow is executed', async function () {
  const sent = await command(this, 'uninstall', { release: this.release, namespace: this.namespace })
  this.uninstalled = { ...sent, result: await finalResult(this, sent.requestId) }
})

Then('the release is removed without manual intervention and the expected project resources are no longer present', async function () {
  const { status, result } = this.uninstalled
  assert.equal(status, 202, 'the uninstall command was not accepted')
  assert.equal(result.ok, true, `the uninstall failed: ${JSON.stringify(result.errors)}`)
  assertSameCluster(this, result)
  const after = await observe(this, 'absent', { expected: this.expected })
  assertHolds(after, 'the release left resources behind')
  assert.deepEqual(after.crds, this.crdsBefore, 'the CRD set changed')
})
