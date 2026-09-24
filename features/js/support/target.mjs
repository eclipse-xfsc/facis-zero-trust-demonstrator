// The target of a lifecycle run. Every input comes from the environment, so the same scenarios
// run against a developer's local cluster (never evidence) and against a client cluster through
// CI; only these values change. A missing input fails the run at once and is named.
import { readFileSync } from 'node:fs'

const repoRoot = new URL('../../../', import.meta.url)

const REQUIRED = [
  ['KUBECONFIG', 'kubeconfig of the read-only observer identity'],
  ['BDD_ORCE_URL', 'base URL of ORCE, e.g. https://orce.example'],
  ['BDD_ORCE_ADMIN_TOKEN', 'read-only ORCE admin API bearer token'],
  ['BDD_ORCE_HTTP_USER', 'user of the ORCE HTTP endpoints (httpNodeAuth)'],
  ['BDD_ORCE_HTTP_PASS', 'password of the ORCE HTTP endpoints'],
  ['BDD_ORCE_LOGS_CMD', 'shell command that prints the ORCE log, e.g. "kubectl -n ztd-orce logs deploy/orce"']
]

export function loadTarget (env = process.env) {
  const missing = REQUIRED.filter(([name]) => !env[name])
  if (missing.length > 0) {
    throw new Error('the lifecycle scenarios need a target; missing:\n' +
      missing.map(([name, what]) => `  ${name} - ${what}`).join('\n'))
  }
  const run = (env.BDD_RUN_ID || `local-${Date.now()}`).toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 30)
  return {
    kubeconfig: env.KUBECONFIG,
    orceUrl: env.BDD_ORCE_URL.replace(/\/$/, ''),
    adminToken: env.BDD_ORCE_ADMIN_TOKEN,
    httpAuth: 'Basic ' + Buffer.from(`${env.BDD_ORCE_HTTP_USER}:${env.BDD_ORCE_HTTP_PASS}`).toString('base64'),
    logsCommand: env.BDD_ORCE_LOGS_CMD,
    chart: env.BDD_RELEASE_CHART || '/opt/ztd/charts/lifecycle-fixture',
    name: (env.BDD_TARGET || 'local').replace(/[^A-Za-z0-9-]/g, '-'),
    run
  }
}

// The valid baseline values of the release under test; each negative example mutates one value.
export function baselineValues (env = process.env) {
  const file = env.BDD_RELEASE_VALUES
    ? env.BDD_RELEASE_VALUES
    : new URL('features/fixtures/charts/lifecycle-fixture/ci/values.yaml', repoRoot)
  const text = readFileSync(file, 'utf8').split('\n').filter((line) => !line.trimStart().startsWith('#')).join('\n')
  return JSON.parse(text)
}
