// ORCE settings for the FACIS ZTD image: the upstream settings, with their security replaced.
//
// The upstream file ships a fixed admin user; here every credential comes from the environment
// and ORCE refuses to start when one is missing. TLS 1.3 terminates in front of ORCE (ingress or
// mesh), and the editor and admin API are reachable from the management plane only.
'use strict'

const crypto = require('node:crypto')
const base = require('./settings.upstream.js')

function required (name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} must be set: ORCE does not start without its credentials`)
  return value
}

const readToken = Buffer.from(required('ORCE_READ_TOKEN'))

// One JSON object per line for every record sent through the Node-RED logging API. Only these
// fields are written: never an error object or its stack, and never a payload merged into the
// top level, so a message cannot overwrite level or id. Output outside the logging API (console
// calls in function or third-party nodes, Node.js itself, the entrypoint) is not covered.
const LEVELS = { 10: 'fatal', 20: 'error', 30: 'warn', 40: 'info', 50: 'debug', 60: 'trace', 98: 'audit', 99: 'metric' }
function jsonLogger () {
  return function (record) {
    // A message whose conversion throws must not crash ORCE (the upstream logger guards the same).
    let msg
    try {
      msg = record.msg
      if (msg instanceof Error || (msg && typeof msg === 'object' && typeof msg.message === 'string')) msg = msg.message
      msg = typeof msg === 'string' ? msg : String(msg)
    } catch {
      msg = '[unprintable log message]'
    }
    process.stdout.write(JSON.stringify({
      time: new Date(record.timestamp || Date.now()).toISOString(),
      level: LEVELS[record.level] || String(record.level),
      type: record.type || null,
      name: record.name || null,
      id: record.id || null,
      msg
    }) + '\n')
  }
}

module.exports = {
  ...base,
  // Fixed on purpose: the upstream image sets FLOWS=flows.json, which would load its demo flows.
  flowFile: 'lifecycle.json',

  // The editor and admin API. A person administers ORCE with the user; the acceptance runner
  // reads the lifecycle results from the flow context with a read-only bearer token.
  adminAuth: {
    type: 'credentials',
    users: [{ username: required('ORCE_ADMIN_USER'), password: required('ORCE_ADMIN_PASSWORD_HASH'), permissions: '*' }],
    tokens: function (token) {
      const offered = Buffer.from(String(token))
      const match = offered.length === readToken.length && crypto.timingSafeEqual(offered, readToken)
      return Promise.resolve(match ? { user: 'bdd-observer', permissions: 'read' } : null)
    }
  },

  // Replaces the upstream console logger: the only handler is the JSON one (TDR logging).
  logging: { json: { level: 'info', metrics: false, audit: false, handler: jsonLogger } },

  // The flow's own HTTP endpoints, including the lifecycle command endpoint.
  httpNodeAuth: { user: required('ORCE_HTTP_USER'), pass: required('ORCE_HTTP_PASSWORD_HASH') },

  // The admin API returns context values through the same encoder as the debug sidebar; the
  // lifecycle results must come back whole, not truncated at the 1000-character default.
  debugMaxLength: 1000000
}
