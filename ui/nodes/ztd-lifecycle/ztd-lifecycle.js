// ztd-lifecycle: an ORCE Builder Node that deploys or uninstalls one Helm release in a
// provisioned namespace by running scripts/lifecycle.sh.
//
// A command is validated first; an invalid one is refused with errors.fields and nothing runs.
// A valid one is acknowledged at once, then runs in the background. Progress and the final
// result are kept in the flow context under lifecycle.jobs[requestId], where callers read
// them - the TDR requires machine-readable errors "exposed via ORCE context".
'use strict'

const { spawn } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const DNS_LABEL = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/
const RELEASE = /^[a-z0-9]([-a-z0-9]{0,51}[a-z0-9])?$/
const KEPT_JOBS = 50

// Field checks of the command, mirroring ztd-lifecycle.schema.json. A test holds the two to
// the same required fields.
function validate (command) {
  const fields = {}
  if (!command || typeof command !== 'object') return { command: 'must be an object' }
  if (command.type !== 'command') fields.type = 'must be "command"'
  if (command.action !== 'deploy' && command.action !== 'uninstall') fields.action = 'must be deploy or uninstall'
  if (typeof command.requestId !== 'string' || command.requestId.length < 1 || command.requestId.length > 128) {
    fields.requestId = 'must be a string of 1 to 128 characters'
  }
  const payload = command.payload
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    fields.payload = 'must be an object'
    return fields
  }
  for (const key of Object.keys(payload)) {
    if (!['release', 'namespace', 'chart', 'values'].includes(key)) fields[key] = 'is not a known parameter'
  }
  if (typeof payload.release !== 'string' || !RELEASE.test(payload.release)) {
    fields.release = 'is required: a DNS-1123 label of at most 53 characters'
  }
  if (typeof payload.namespace !== 'string' || !DNS_LABEL.test(payload.namespace)) {
    fields.namespace = 'is required: a DNS-1123 label'
  }
  if (command.action === 'deploy') {
    if (typeof payload.chart !== 'string' || payload.chart.length === 0) fields.chart = 'is required for deploy'
    if (!payload.values || typeof payload.values !== 'object' || Array.isArray(payload.values)) {
      fields.values = 'is required for deploy: an object'
    }
  }
  return fields
}

// Credentials never leave the node: key=value and key: value pairs, quoted or not (Helm output
// quotes values, JSON always does), bearer tokens and JWTs. scripts/lifecycle.sh masks the same way.
function mask (text) {
  return String(text || '')
    .replace(/((password|passwd|secret|token|apikey|api-key|client-secret)[^=:\n]{0,20}[=:]\s*["']?)[^\s,"'}]+/gi, '$1[masked]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/g, '$1[masked]')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[masked-jwt]')
}

function result (command, ok, data, errors) {
  return {
    type: 'result',
    ok,
    action: command && command.action,
    requestId: command && command.requestId,
    data: data || null,
    ui: {
      toast: ok
        ? { kind: 'success', message: data && data.accepted ? 'Request accepted.' : 'Done.' }
        : { kind: 'error', message: errors && errors.fields ? 'Please correct the highlighted fields.' : 'The request could not be completed.' }
    },
    errors: ok ? null : errors
  }
}

// Map the script's one RESULT_JSON line onto the result contract.
function fromScript (command, script) {
  if (!script) return result(command, false, null, { action: 'systemError' })
  if (script.ok) {
    const { release, namespace, clusterId, revision, chartDigest, valuesHash, helmVersion, expected } = script
    return result(command, true, { release, namespace, clusterId, revision, chartDigest, valuesHash, helmVersion, expected, output: mask(script.output) })
  }
  const error = script.error || { code: 'systemError' }
  const errors = error.field ? { fields: { [error.field]: error.message } } : { action: error.code }
  return result(command, false, { clusterId: script.clusterId, output: mask(script.output) }, errors)
}

module.exports = function (RED) {
  function LifecycleNode (config) {
    RED.nodes.createNode(this, config)
    const node = this
    const scriptPath = config.script || process.env.ZTD_LIFECYCLE_SCRIPT || '/opt/ztd/scripts/lifecycle.sh'
    const flow = node.context().flow

    // Structured JSON log lines only; values and raw output are never logged.
    const log = (entry) => node.log(JSON.stringify({ node: 'ztd-lifecycle', ...entry }))

    function store (requestId, update) {
      const state = flow.get('lifecycle') || { jobs: {} }
      state.jobs[requestId] = { ...(state.jobs[requestId] || { events: [], result: null }), ...update(state.jobs[requestId] || { events: [], result: null }) }
      const ids = Object.keys(state.jobs)
      for (const id of ids.slice(0, Math.max(0, ids.length - KEPT_JOBS))) delete state.jobs[id]
      flow.set('lifecycle', state)
    }

    function finish (command, final) {
      store(command.requestId, () => ({ result: final }))
      log({
        event: final.ok ? 'lifecycle.result' : 'lifecycle.refused',
        requestId: command.requestId,
        action: command.action,
        ok: final.ok,
        reason: final.errors ? (final.errors.action || Object.keys(final.errors.fields || {}).join(',')) : null
      })
      node.status(final.ok ? { fill: 'green', shape: 'dot', text: `${command.action} ok` } : { fill: 'red', shape: 'ring', text: `${command.action} refused` })
    }

    node.on('input', function (msg, send, done) {
      send = send || function () { node.send.apply(node, arguments) }
      const command = msg.payload
      const fields = validate(command)

      if (Object.keys(fields).length > 0) {
        // Refused before anything runs. The result still lands in context when the command
        // carries a usable requestId, so a caller polling for it gets an explicit answer.
        const refused = result(command, false, null, { fields })
        if (command && typeof command.requestId === 'string' && command.requestId) finish(command, refused)
        else log({ event: 'lifecycle.refused', requestId: null, reason: Object.keys(fields).join(',') })
        msg.payload = refused
        send(msg)
        return done()
      }

      // A requestId names one execution: a repeat is refused, whether it is still running or
      // finished, so a recorded result can never be overwritten.
      const seen = (flow.get('lifecycle') || { jobs: {} }).jobs[command.requestId]
      if (seen) {
        msg.payload = result(command, false, null, { action: 'duplicateRequest' })
        send(msg)
        return done()
      }

      store(command.requestId, () => ({ events: [], result: null }))
      msg.payload = result(command, true, { accepted: true })
      send(msg)
      node.status({ fill: 'blue', shape: 'dot', text: `${command.action} running` })

      const env = {
        ...process.env,
        LIFECYCLE_RELEASE: command.payload.release,
        LIFECYCLE_NAMESPACE: command.payload.namespace
      }
      let valuesDir = null
      if (command.action === 'deploy') {
        valuesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ztd-lifecycle-'))
        const valuesFile = path.join(valuesDir, 'values.json')
        fs.writeFileSync(valuesFile, JSON.stringify(command.payload.values), { mode: 0o600 })
        env.LIFECYCLE_CHART = command.payload.chart
        env.LIFECYCLE_VALUES_FILE = valuesFile
      }

      let scriptResult = null
      let buffer = ''
      const child = spawn('bash', [scriptPath, command.action], { env, stdio: ['ignore', 'pipe', 'pipe'] })
      child.stdout.on('data', (chunk) => {
        buffer += chunk.toString()
        const lines = buffer.split(/\r?\n/)
        buffer = lines.pop()
        for (const line of lines) {
          if (line.startsWith('EVENT_JSON=')) {
            try {
              const event = JSON.parse(line.slice('EVENT_JSON='.length))
              store(command.requestId, (job) => ({ events: [...job.events, event] }))
              node.status({ fill: 'blue', shape: 'dot', text: `${event.step}:${event.status}` })
            } catch (_) { /* a malformed progress line is not a result; ignore it */ }
          } else if (line.startsWith('RESULT_JSON=')) {
            try { scriptResult = JSON.parse(line.slice('RESULT_JSON='.length)) } catch (_) { scriptResult = null }
          }
        }
      })
      child.stderr.on('data', () => {}) // the script reports through RESULT_JSON; stderr is not relayed
      // A spawn that fails emits both 'error' and 'close'; the job finishes exactly once.
      let completed = false
      const complete = () => {
        if (completed) return
        completed = true
        if (valuesDir) fs.rmSync(valuesDir, { recursive: true, force: true })
        finish(command, fromScript(command, scriptResult))
      }
      child.on('error', () => { scriptResult = null; complete() })
      child.on('close', complete)
      done()
    })
  }

  RED.nodes.registerType('ztd-lifecycle', LifecycleNode)
}

module.exports.validate = validate
module.exports.mask = mask
