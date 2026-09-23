// Unit tests for the ztd-lifecycle node against a minimal stand-in for the Node-RED runtime, so
// they need no dependency. The lifecycle script is replaced by a stub that prints fixed lines.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const require = createRequire(import.meta.url)
const lifecycle = require('../ztd-lifecycle.js')
const schema = JSON.parse(readFileSync(new URL('../ztd-lifecycle.schema.json', import.meta.url)))

function runtime () {
  const flowContext = new Map()
  const logs = []
  let Ctor
  const RED = {
    nodes: {
      createNode (node) {
        node.handlers = {}
        node.on = (event, fn) => { node.handlers[event] = fn }
        node.status = () => {}
        node.log = (line) => logs.push(line)
        node.context = () => ({ flow: { get: (k) => flowContext.get(k), set: (k, v) => flowContext.set(k, v) } })
      },
      registerType (_, ctor) { Ctor = ctor }
    }
  }
  lifecycle(RED)
  return {
    logs,
    context: () => flowContext.get('lifecycle'),
    node (config) { const n = {}; Ctor.call(n, config); return n }
  }
}

function stub (lines) {
  const dir = mkdtempSync(join(tmpdir(), 'ztd-stub-'))
  const marker = join(dir, 'ran')
  const script = join(dir, 'lifecycle.sh')
  writeFileSync(script, `touch ${JSON.stringify(marker)}\n` + lines.map((l) => `printf '%s\\n' ${JSON.stringify(l)}`).join('\n') + '\n')
  return { script, ran: () => existsSync(marker) }
}

function send (node, payload) {
  return new Promise((resolve) => {
    node.handlers.input({ payload }, (msg) => resolve(msg.payload), () => {})
  })
}

async function finalResult (rt, requestId) {
  for (let i = 0; i < 200; i++) {
    const job = rt.context() && rt.context().jobs[requestId]
    if (job && job.result) return job.result
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error('no final result in context')
}

const deploy = (requestId, payload) => ({
  type: 'command', action: 'deploy', requestId,
  payload: { release: 'fx', namespace: 'ztd-bdd-tdr-001', chart: '/opt/ztd/charts/fixture', values: { message: 'm' }, ...payload }
})

test('an invalid command is refused with errors.fields and nothing runs', async () => {
  const rt = runtime(); const s = stub(['RESULT_JSON={"ok":true}'])
  const node = rt.node({ script: s.script })
  const ack = await send(node, deploy('r1', { release: undefined }))
  assert.equal(ack.ok, false)
  assert.ok(ack.errors.fields.release)
  assert.equal(rt.context().jobs.r1.result.ok, false)
  assert.equal(s.ran(), false)
  assert.match(rt.logs.at(-1), /"event":"lifecycle.refused"/)
  assert.match(rt.logs.at(-1), /"requestId":"r1"/)
})

test('values of the wrong type are refused by the node', async () => {
  const rt = runtime(); const s = stub([])
  const ack = await send(rt.node({ script: s.script }), deploy('r2', { values: 'two' }))
  assert.deepEqual(Object.keys(ack.errors.fields), ['values'])
  assert.equal(s.ran(), false)
})

test('a valid command is acknowledged, then its final result lands in context', async () => {
  const rt = runtime()
  const s = stub([
    'EVENT_JSON={"action":"deploy","step":"deploy","status":"running"}',
    'RESULT_JSON={"ok":true,"release":"fx","namespace":"ztd-bdd-tdr-001","clusterId":"c","revision":1,"expected":[{"kind":"Deployment","name":"fx","uid":"u"}],"output":"done"}'
  ])
  const ack = await send(rt.node({ script: s.script }), deploy('r3'))
  assert.equal(ack.ok, true)
  assert.deepEqual(ack.data, { accepted: true })
  const final = await finalResult(rt, 'r3')
  assert.equal(final.ok, true)
  assert.equal(final.errors, null)
  assert.equal(final.data.revision, 1)
  assert.equal(final.data.expected[0].kind, 'Deployment')
  assert.equal(rt.context().jobs.r3.events.length, 1)
})

test('a script failure becomes errors.action with its reason code', async () => {
  const rt = runtime()
  const s = stub(['RESULT_JSON={"ok":false,"error":{"code":"valuesSchemaRejected","message":"no"}}'])
  await send(rt.node({ script: s.script }), deploy('r4'))
  const final = await finalResult(rt, 'r4')
  assert.equal(final.ok, false)
  assert.equal(final.errors.action, 'valuesSchemaRejected')
  assert.match(rt.logs.at(-1), /"event":"lifecycle.refused".*"reason":"valuesSchemaRejected"/)
})

test('a script error naming a parameter becomes errors.fields', async () => {
  const rt = runtime()
  const s = stub(['RESULT_JSON={"ok":false,"error":{"code":"namespaceNotPermitted","message":"not in the pool","field":"namespace"}}'])
  await send(rt.node({ script: s.script }), deploy('r5'))
  const final = await finalResult(rt, 'r5')
  assert.deepEqual(final.errors, { fields: { namespace: 'not in the pool' } })
})

test('a script that prints no result is a systemError, never a silent success', async () => {
  const rt = runtime(); const s = stub(['nothing useful'])
  await send(rt.node({ script: s.script }), deploy('r6'))
  const final = await finalResult(rt, 'r6')
  assert.equal(final.ok, false)
  assert.equal(final.errors.action, 'systemError')
})

test('a secret never reaches the log or the context', async () => {
  const rt = runtime()
  const s = stub(['RESULT_JSON={"ok":true,"output":"password=hunter2 token: abc"}'])
  await send(rt.node({ script: s.script }), deploy('r7', { values: { adminPassword: 'hunter2' } }))
  await finalResult(rt, 'r7')
  const everything = JSON.stringify(rt.context()) + rt.logs.join('\n')
  assert.doesNotMatch(everything, /hunter2/)
  assert.doesNotMatch(everything, /token: abc/)
})

test('a finished requestId is not run again', async () => {
  const rt = runtime(); const s = stub(['RESULT_JSON={"ok":true}'])
  const node = rt.node({ script: s.script })
  await send(node, deploy('r10'))
  const first = await finalResult(rt, 'r10')
  const again = await send(node, deploy('r10'))
  assert.equal(again.errors.action, 'duplicateRequest')
  assert.deepEqual(rt.context().jobs.r10.result, first)
})

test('a script path that does not exist ends in exactly one systemError', async () => {
  const rt = runtime()
  await send(rt.node({ script: '/nonexistent/lifecycle.sh' }), deploy('r11'))
  const final = await finalResult(rt, 'r11')
  assert.equal(final.errors.action, 'systemError')
  await new Promise((r) => setTimeout(r, 200))
  assert.equal(rt.logs.filter((l) => l.includes('"requestId":"r11"')).length, 1)
})

// The node and the script must mask the same inputs, including quoted values: Helm output quotes
// scalars and JSON quotes every string.
const SECRETS = [
  ['password=hunter2', 'hunter2'],
  ['token: abc123', 'abc123'],
  ['{"password":"hunter2"}', 'hunter2'],
  ['adminPassword: "hunter2"', 'hunter2'],
  ["client-secret: 'hunter2'", 'hunter2'],
  ['Authorization: Bearer abc.def-ghi', 'abc.def-ghi'],
  ['jwt eyJhbGciOiJ.eyJzdWIiOiJ4.c2lnbmF0dXJl here', 'eyJzdWIiOiJ4']
]

test('the node masks credentials, quoted or not', () => {
  for (const [input, secret] of SECRETS) {
    assert.doesNotMatch(lifecycle.mask(input), new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), input)
  }
})

test('the lifecycle script masks the same credentials', () => {
  const script = readFileSync(new URL('../../../../scripts/lifecycle.sh', import.meta.url), 'utf8')
  const fn = script.slice(script.indexOf('mask() {'), script.indexOf('\n}\n', script.indexOf('mask() {')) + 3)
  const out = execFileSync('bash', ['-c', fn + '\nmask'], { input: SECRETS.map(([i]) => i).join('\n') + '\n' }).toString()
  for (const [, secret] of SECRETS) assert.doesNotMatch(out, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
})

test('a requestId still running is not started twice', async () => {
  const rt = runtime(); const s = stub(['sleep 1', 'RESULT_JSON={"ok":true}'])
  writeFileSync(s.script, 'sleep 1\nprintf "%s\\n" \'RESULT_JSON={"ok":true}\'\n')
  const node = rt.node({ script: s.script })
  await send(node, deploy('r8'))
  const second = await send(node, deploy('r8'))
  assert.equal(second.errors.action, 'duplicateRequest')
  await finalResult(rt, 'r8')
})

test('the node enforces every field the schema requires', () => {
  for (const field of schema.required) {
    const command = deploy('r9'); delete command[field]
    assert.ok(lifecycle.validate(command)[field] || lifecycle.validate(command).payload, `missing ${field} not refused`)
  }
  for (const field of schema.properties.payload.required) {
    const command = deploy('r9'); delete command.payload[field]
    assert.ok(lifecycle.validate(command)[field], `missing payload.${field} not refused`)
  }
})
