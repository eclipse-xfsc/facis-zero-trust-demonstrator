# Orchestration flows

ORCE / Node-RED flows driving the demonstrator's journeys, exported as JSON and deployed from this
repository rather than edited live on a cluster.

Node.js is the language for Builder module logic inside ORCE per the Technical Development
Requirements. The functional breakdown of these flows is documented in
[`docs/flows.md`](../docs/flows.md).

## Connector contract adapter

`demonstrator/connector-adapter.mjs` is a server-side ORCE integration module,
not a replacement for the Go Participant service or the Connector security core.
It implements the repository's 30 September `docs/oauth2-provider.md` contract.
No additional npm dependency is required; use Node.js 22 or later.
The current journey flow and UI continue to use their existing adapters. The module is also embedded in the independent `Connector adapter` flow; it remains disconnected from the Journey while the approved live route and event feed are unavailable.

```js
import { createConnectorAdapter } from './flows/demonstrator/connector-adapter.mjs';
const adapter = createConnectorAdapter({
  tokenURL: process.env.CONNECTOR_TOKEN_URL,
  registrationURL: process.env.CONNECTOR_REGISTRATION_URL,
  protectedURL: process.env.CONNECTOR_PROTECTED_URL,
  registrarClientId: process.env.CONNECTOR_REGISTRAR_CLIENT_ID,
  registrarClientSecret: process.env.CONNECTOR_REGISTRAR_CLIENT_SECRET,
  scope: process.env.CONNECTOR_SCOPE,
  audience: process.env.CONNECTOR_AUDIENCE || undefined,
  mode: 'live',
  method: 'GET',
  timeoutMs: 7000
});
const result = await adapter.run({requestId, correlationId});
```

All endpoint URLs and credentials are supplied by the server operator, never by
browser input. `protectedURL` must be the approved Connector/PEP route, not a
fallback direct Resource URL. Live mode requires HTTPS with normal certificate
validation; there is no TLS exception switch. A provisioned registrar client must
be allowed to obtain the registration audience and both
`connector:client_registration` and the requested resource scopes. Scope and
optional audience must match the approved deployment. No endpoint paths or role
mapping are assumed.

The adapter obtains a registration token, registers a DPoP-bound participant
client, obtains its client-credentials token, then calls the configured protected
route. Generated client credentials are cached only within the server-side
adapter instance. Reuse that instance for subsequent calls; concurrent first
calls can register independently. It does not persist tokens or private keys to
flows, logs or disk. Use `method: 'POST'` and pass a JSON object as `payload` to
`run` only when the approved resource contract requires POST.

DPoP uses ES256 with a public JWK, a unique `jti`, method/URI/time binding and an
`ath` digest on protected requests. Token, registration and resource nonce
challenges receive at most one retry with a fresh proof. Redirects, malformed or
oversized responses, non-DPoP participant tokens and expired token responses are
refused. One timeout bounds the complete execution. There is no direct-call or
fixture fallback when a protected call fails.

Results include `ok`, `mode`, request/correlation IDs and sanitized `events`.
Success returns the resource JSON in `data`; refusal returns `reasonCode`,
`failedStage` and HTTP `status` without upstream response content or credentials.
Each HTTP request carries `X-Request-ID` and `X-Correlation-ID`. Events contain
no tokens, proofs, client secrets or protected payload. Treat `data` as protected
application content and map it through the approved UI schema before displaying
or recording it. The adapter does not interpret viewer roles as service rights
and does not verify credential presentations or make policy decisions.

Run `node --test tests/demonstrator/connector-adapter.test.cjs` for local HTTP
contract checks. `mode: 'local-contract'` permits plain HTTP only at numeric
loopback addresses and labels every result accordingly. These checks are
component evidence for BDD-ZT-039/074 preparation; they do not close live
registration, DPoP interoperability, guard or trust acceptance. Live execution
remains blocked pending the deployed endpoints and ATLAS integration settings.

### Independent Node-RED flow

Import `demonstrator/connector-adapter-flow.json` once into the existing editor.
The same nodes are included in `demonstrator/current-facis-flows.json` for clean
installation; do not import both copies. The flow uses the runtime's built-in
`crypto`, `http`, `https`, `url` and `util` modules through Function external
modules, matching the existing identity flow setup. `connector-flow-run.js`
contains the exact embedded Function body.

The `Run protected call` inject never runs automatically. By default it produces
`CONNECTOR_NOT_ENABLED` without network activity. Set server environment
`CONNECTOR_ADAPTER_ENABLED=true` only after the approved HTTPS endpoints and
registrar credentials described above are configured. Optional
`CONNECTOR_METHOD` is GET or POST and `CONNECTOR_TIMEOUT_MS` defaults to 7000.
There is no cleartext/local-contract mode in this deployable flow.

The adapter's first output feeds `Connector result` and carries the result,
including protected JSON only on success. Its second output feeds
`Connector events` and carries individual sanitized event messages. Both terminal
nodes currently have no outgoing wires; they display status without logging
protected content. These are the connection points for the future approved
Journey/event integration. Each trigger creates a fresh adapter instance and
registers a client for that run. No private key or generated client credentials
are persisted in Node-RED context. Repeated live runs should use the agreed
client lifecycle before this path becomes the normal Journey adapter.

## Protected Resource fixture decisions

The Journey catalogue includes 13 `resource-fixture-*` cases from
`demonstrator/protected-resource-fixture.mjs`. Reader, reader-with-detail, auditor
and reader-plus-auditor return distinct synthetic payloads. Missing or unauthorized
roles, wrong scope, detail-only rights, revoked/invalid credentials, expired or
missing context and unavailable security dependency return no protected data.
These local service roles and scopes are test policy only; they are not the
ATLAS role mapping and never authorize a real resource. Operator/observer remain
viewer roles and cannot substitute for service rights.

In the UI select a `Resource fixture:` security scenario, start it and advance
to its second step. The final result and `fixture.resource.decision` evidence
share request/correlation IDs and explicitly identify fixture-only security.
The cases execute locally even when the existing adapter is HTTP sample. They
never call Participant or Connector and never fall back from a failed live call.
Observer can view shared outcomes but cannot start, advance or reset a run.

The evaluator accepts only a registered case ID and correlation identifiers;
service roles, headers or a claimed verified context supplied by a caller are
refused. The Journey uses its server-owned case catalogue. Reset removes the
previous payload and evidence. Actual verified access contexts, role/policy
mapping and live BDD-ZT-041/075 acceptance remain blocked on ATLAS interfaces.

## Preparing replacement of both application roles

`demonstrator/replacement-adapters.mjs` defines a common local execution pipeline
with separate `participant-backend` and `protected-resource` adapters. Either
role can select `mock` or `sample-http` without changing the pipeline. The
Participant prepares the normalized request; the Resource returns the bounded
sample result. This preparation module is not wired into the deployed Journey
or the Connector security core. The current UI's real-API choice remains disabled.

```js
import { createReplacementJourney, replacementContracts } from './flows/demonstrator/replacement-adapters.mjs';
const journey = await createReplacementJourney({
  participant: {
    kind: 'mock', role: 'participant-backend',
    contract: replacementContracts['participant-backend']
  },
  resource: {
    kind: 'sample-http', role: 'protected-resource',
    contract: replacementContracts['protected-resource'],
    baseURL: 'http://127.0.0.1:PORT'
  },
  timeoutMs: 3000
});
const result = await journey.run({
  requestId: 'sample-request', correlationId: 'sample-correlation',
  resource: 'sample-report', action: 'read', scenario: 'success'
});
```

For either role, select `sample-http` and provide that sample server's numeric
loopback origin to replace its mock. These adapters deliberately permit only
local sample HTTP servers. `real` is rejected as
`REPLACEMENT_TARGET_NOT_APPROVED`; no IONOS or OCM-W interface or authentication
is assumed before the client supplies the approved target contract.

Both role configurations are validated before network access. Each selected
HTTP sample must then expose `GET /interface` returning exactly these values:

| Member | Participant sample | Resource sample |
| --- | --- | --- |
| contract | facis.sample-participant/v1 | facis.sample-resource/v1 |
| role | participant-backend | protected-resource |
| mode | sample | sample |
| method | POST | POST |
| path | /execute | /execute |

An incompatible descriptor fails adapter creation before either role executes.
These are local preparation contracts, not claims about the existing deployed
Participant's `/demo` endpoint or any approved external API.

Both `POST /execute` requests carry the request fields shown above and matching
`X-Request-ID` and `X-Correlation-ID` headers. The Participant returns
`{contract, role, mode: 'sample', outcome: 'ready', request}`; its request must
preserve all five input fields exactly. `sampleParticipantResponse(request)`
builds this response for a disposable sample server. A refusal or mismatch stops
before the Resource is called.

The Resource returns `{contract, role, mode: 'sample', requestId, correlationId,
outcome, reasonCode, safeData}`. `sampleResourceResponse(request)` builds its
local fixture response. Success uses HTTP 200 and bounded
`{resource, action, report: {id, title, content}}`; denied uses 403, unavailable
503 and error 502, all with empty `safeData`. Supported local scenarios are
`success`, `denied`, `unavailable` and `error`. Unknown fields, wrong IDs, live
mode, malformed data and status/outcome mismatches are refused.

The returned result includes sample/fixture provenance, outcome, reason code,
protected sample data only on success, and correlated events. Every response is
bounded to 64 KiB; deadlines include response bodies. Redirects are refused.
There is no fallback between adapters when a selected service fails.
Configuration is server-owned and copied after validation; browser input cannot
select endpoints or inject roles or authorization headers.

Run `node --test tests/demonstrator/replacement-adapters.test.cjs` to launch
and close disposable loopback HTTP sample servers. The 21 checks exercise all
four adapter combinations and refusal/failure cases. They prepare
BDD-ZT-007/077 component evidence only. Real API replacement acceptance remains
blocked pending the approved targets, authentication and deterministic data.
