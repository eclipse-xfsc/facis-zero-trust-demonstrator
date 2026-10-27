# Participant and Protected Resource services

Two Go sample services for application deployment and HTTP integration. They do not implement the guard, Keycloak login, workload identity, attestation or real API replacement. A sample `denied` result is deliberately selected test data, not a security decision. In sample mode the responses are marked `source: sample` and `mode: sample`; health reports `liveMode: unavailable`.

Both services also have a token mode (see [Modes](#modes) and [Token mode](#token-mode)): the Participant obtains a DPoP-bound access token from the Connector through the verified-presentation grant and calls the Resource with it and a fresh proof per call; the Resource verifies both with `internal/tokenverify` and answers by the token's scope. `PARTICIPANT_ADAPTER_MODE=token` and `PROTECTED_RESOURCE_MODE=token` select it; without them both binaries run in sample mode exactly as before.

## Source and build

Use the repository root as the build context and retain its `go.mod` and `go.sum`. The services use the standard library and the repository's `internal/` packages (token path: `connectorclient`, `dpopproof`, `if03`, `jose`, `replay`, `tokenverify`) and add no module dependencies; both images therefore copy `internal/`.

| Service | Entry point | Package | Default TCP port | Endpoints |
| --- | --- | --- | --- | --- |
| Participant | `cmd/participant` | `services/participant` | 8085 | `GET /health`, `POST /demo`, `GET /state`, `POST /reset` |
| Protected Resource | `cmd/protected-resource` | `services/protectedresource` | 8086 | `GET /health`, `POST /demo`, `POST /reset` |

From the repository root:

```sh
go version
go build ./cmd/participant ./cmd/protected-resource
go test ./services/participant/... ./services/protectedresource/... -timeout 30s
go vet ./services/participant/... ./services/protectedresource/...
```

The two-target build checks compilation without leaving two runnable executables. To produce executables, run separate builds with `-o`, or use `go run` as below.

Container build recipes are included at `deployment/docker/participant/Dockerfile` and `deployment/docker/protected-resource/Dockerfile`, each with repository-root context. They compile Linux/amd64 static binaries using a digest-pinned Go builder, run from `scratch` as UID/GID 65532, and include CA certificates. The release workflow builds, signs and publishes them with every other image under `deployment/docker/`; follow [Packaging](packaging.md) for release builds/signing; a local source test is not a release build or publication.

The pipeline build commands, from the repository root, are:

```sh
docker build --platform linux/amd64 -f deployment/docker/participant/Dockerfile -t ci/participant:check .
docker build --platform linux/amd64 -f deployment/docker/protected-resource/Dockerfile -t ci/protected-resource:check .
```

These are build-check tags, not deployment references. Deploy the pipeline-produced images by digest. The Participant image defaults to `http-sample` and deliberately requires `PARTICIPANT_RESOURCE_URL` at runtime; it will reject startup without that setting. Both images use HTTP `/health` probes supplied by the orchestrator; the scratch images contain no shell or curl.

## Configuration

The processes read environment variables; they do not load `.env` files automatically. Set variables in the process environment or deployment configuration. Example files contain no credentials.

### Participant

| Variable | Code default | Meaning |
| --- | --- | --- |
| `PARTICIPANT_ADDRESS` | `:8085` | HTTP listener; use `:8085` in a container and `127.0.0.1:8085` for a host-only local test. |
| `PARTICIPANT_REQUEST_TIMEOUT` | `5s` | Positive Go duration bounding each adapter call. |
| `PARTICIPANT_ADAPTER_MODE` | `sample` | `sample` handles the result internally. `http-sample` calls Protected Resource over HTTP(S). `token` selects [token mode](#token-mode). |
| `PARTICIPANT_RESOURCE_URL` | Empty | Required for `http-sample` and `token`; base URL without `/demo`, credentials, query or fragment. The adapter appends `/demo`. In token mode it must be the Resource's public base URL, since the proof's `htu` is built from it. |
| `PARTICIPANT_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

Token mode only; each is required there except the entitlement, and none is read otherwise:

| Variable | Meaning |
| --- | --- |
| `PARTICIPANT_CONNECTOR_URL` | The Connector's base URL; `/oauth2/challenge` and `/oauth2/token` are called below it. |
| `PARTICIPANT_CREDENTIALS_FILE` | Mounted file with the provisioned client: one JSON object with exactly the members `client_id` and `client_secret` (case-sensitive), both non-empty strings, no duplicate member and nothing after the object; read at every bootstrap run, never logged. |
| `PARTICIPANT_AUDIENCE` | The audience the token is requested for: the guard's `inbound_audience` for the guarded path, registered for the Participant client. It differs from the Resource's `PROTECTED_RESOURCE_AUDIENCE`, which equals the guard's `upstream_audience`. |
| `PARTICIPANT_OUTCOME_ISSUER`, `PARTICIPANT_OUTCOME_KID` | `iss` and `kid` of the fixture IF-03 outcomes; the Connector's trusted-issuers file must hold this issuer and key id. |
| `PARTICIPANT_OUTCOME_KEY_FILE` | PEM P-256 private key (`EC PRIVATE KEY` or `PRIVATE KEY`) the fixture signs outcomes with; read at start. |
| `PARTICIPANT_OUTCOME_ROLE`, `PARTICIPANT_OUTCOME_ENTITLEMENT` | The outcome's claims; the Connector's scope map turns them into the token's scopes. The entitlement is optional. |

`configs/participant.env.example` enables the two-process local HTTP route. `configs/participant.osc.env.example` shows the separate-service deployment shape. It matches the Service the application-service chart (`deployment/helm/application-service`) creates. `127.0.0.1` cannot address a different pod.

### Protected Resource

| Variable | Code default | Meaning |
| --- | --- | --- |
| `PROTECTED_RESOURCE_ADDRESS` | `:8086` | HTTP listener; use `:8086` in a container and loopback for a host-only test. |
| `PROTECTED_RESOURCE_REQUEST_TIMEOUT` | `5s` | Positive duration bounding each resource request. |
| `PROTECTED_RESOURCE_SLOW_DELAY` | `2s` | Positive simulated delay; must be shorter than the Resource request timeout. |
| `PROTECTED_RESOURCE_MODE` | `sample` | `sample`, or `token` for [token mode](#token-mode). |
| `PROTECTED_RESOURCE_ADAPTER_MODE` | `sample` | `sample` or `sample-alternative`; both are deterministic sample data. |
| `PROTECTED_RESOURCE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

Token mode only, all required there:

| Variable | Meaning |
| --- | --- |
| `PROTECTED_RESOURCE_TOKEN_ISSUER` | Required `iss` of the access tokens: the Connector's `--issuer`. |
| `PROTECTED_RESOURCE_JWKS_URL` | The Connector's key set, `<connector>/.well-known/jwks.json`; the only place keys come from. |
| `PROTECTED_RESOURCE_AUDIENCE` | The audience a token must carry. |
| `PROTECTED_RESOURCE_PUBLIC_BASE_URL` | The Resource's base URL as callers reach it; a proof's `htu` must be this plus the request path. `Host` and forwarded headers are ignored. |

In sample mode the services require no application secrets, database, persistent volume or Keycloak client secret. In token mode the Participant needs two mounted secrets, the client credentials file and the outcome signer's key; the Resource needs none. Registry credentials and ingress TLS secrets belong to deployment configuration; secret values must not enter this repository. The applications serve plain HTTP; HTTPS routes require the approved ingress configuration. Do not disable certificate verification for outbound HTTPS calls.

## Modes

Each service has two modes. The package derives the mode from `Config` (a verifier or a bootstrapper set), and is reported as `mode` in `/health`, in every `/demo` response and, for the Participant, in `/state`.

| Service | `sample` (default) | `token` |
| --- | --- | --- |
| Protected Resource | No `Config.Verifier`. `/demo` is unauthenticated and the `scenario` field selects the result, as described below. | `Config.Verifier` (a `tokenverify.RequestVerifier`) is set. `/demo` runs behind its `Middleware`; the response is chosen by the caller's token scopes ([scope table](#scope-table)). A `scenario` field that is non-empty after trimming whitespace is rejected; an empty or whitespace-only one counts as absent. |
| Participant | No `Config.Bootstrapper`. The `sample` or `http-sample` adapter (or one injected through `NewServerWithAdapter`) is used, as before. | `Config.Bootstrapper` is set. The lifecycle runs it at start and the request adapter calls the Resource with credentials from the resulting `TokenSession`. An adapter injected through `NewServerWithAdapter` is ignored in this mode. |

`LoadConfig` sets them only when the mode variable says `token`: the Participant's to a `ConnectorBootstrap`, the Resource's to a `tokenverify.Verifier`. Without it both binaries start in sample mode with the existing settings and no new required variable. A token-mode setting that is missing or invalid stops the process at start; it never falls back to sample mode.

### Token mode

**Participant.** `ConnectorBootstrap` (`services/participant/connector.go`) is the `Bootstrapper` (design D12). Its DPoP key is a P-256 key generated in the process when it starts: a Participant is a workload, not the token store, so it has no transit key, and the key never leaves the process or survives a restart. The client is provisioned (its credentials come from the mounted file), so the `registering` step is skipped and a run starts at `presenting`:

1. `presenting` / `step_started`; read the credentials file.
2. `POST /oauth2/challenge` with `client_secret_basic` and the audience.
3. The fixture `OutcomeSource` (`internal/if03/if03fixture`) signs an IF-03 outcome for that challenge.
4. `acquiring_token` / `step_started`; the grant with a proof of the Participant's key, retried once with the Connector's nonce (`internal/connectorclient`, shared with the token store).
5. The token must be `token_type` DPoP, `cnf.jkt` the Participant key's thumbprint, `aud` the audience, `exp` in the future; then `ready` / `step_completed`.

| Failure | State / reason |
| --- | --- |
| Credentials file missing or malformed | `failed_registration` / `bootstrap_error` |
| Connector answers 401 (client unknown or secret wrong) | `failed_registration` / `registration_rejected` |
| No answer, 5xx, or the grant's answer lost | `failed_connector_unreachable` / `connector_unreachable` (retried by the lifecycle, bounded, with backoff; each retry starts again with a fresh challenge and outcome) |
| Challenge refused or malformed; outcome source failed | `failed_presentation` / `presentation_rejected` or `upstream_error` |
| Grant refused with a `CRED-OUTCOME-*` code | `failed_presentation` / `presentation_rejected` |
| Nonce demanded again after the one retry | `failed_token` / `nonce_retry_exhausted` |
| Grant refused otherwise; the token fails a check | `failed_token` / `token_rejected` |

`TokenSession.Authorize` returns `DPoP <token>` and a fresh proof per call (`htm`, `htu`, `ath` of the token, a new `jti`). Once three quarters of the token's lifetime have passed, the next `Authorize` runs the grant again (challenge, outcome, grant, checks) before answering; one lock covers every grant, so concurrent calls wait for one renewal and never start two. If the renewal fails, the current token is used until it expires and the grant is tried again at most every 5 s, counted from the end of the failed attempt; expiry is judged by the clock after the attempt and again just before `Authorize` returns, so an expired token is never handed out. Past expiry `Authorize` fails and `/demo` answers `TOKEN_AUTHORIZE_FAILED`. A renewal failure does not change `/state`.

**Protected Resource.** The verifier requires no scope itself; the [scope table](#scope-table) decides, so a token with neither scope is answered 403 `RESOURCE_SCOPE_INSUFFICIENT`. Its replay record is its own, in memory (`replay.Memory`), not the zone's shared `proof_jti` table: a proof names this Resource in `htu`, so only this Resource can be presented with it and nothing else needs to see the record, and the Resource needs no database. A restart empties the record, which re-opens at most one proof window (120 s: lifespan plus twice the skew) for proofs captured before it; replicas do not share it, so run one replica, or give replicas the shared Postgres record instead.

**What the demo needs.** A Connector with the verified-presentation grant on: its trusted-issuers file holds the fixture issuer's public key under `PARTICIPANT_OUTCOME_KID`, its scope map maps the outcome's role (and entitlement) to `report:read` or `report:summary`, and the Participant registrar may delegate those scopes and name the guard's inbound audience. A separate store client and registrar name only the Resource's upstream audience. For the direct two-service example, the Participant instead names the Resource's audience. The Participant's client is registered through the registrar's DCR for the grant, DPoP-bound, with that scope and audience, and its credentials are mounted as the credentials file. The Resource points at the Connector's issuer and key set. Two Participants with different roles show the two answers of the scope table.

The end-to-end test `services/participant/tokenpath_test.go` does exactly this against the real `connector` binary (`internal/connectortest`), PostgreSQL and OpenBao, and skips without `TOKEN_STORE_TEST_DATABASE_URL`, `TRANSIT_TEST_ADDR` and `TRANSIT_TEST_TOKEN`. It drives `/demo` on two Participants and checks the `/state` path, the answer per scope, the identity in the Resource's log, the refusal of a request without a proof, with a replayed proof and with a token for another audience, and that no token, proof or secret reaches a log or a body.

### Scope table

In token mode the Protected Resource answers `POST /demo` for `sample-report` / `read` as follows. The verifier has already accepted the token and its DPoP proof; refusals by the verifier (401, 403, 503 with `WWW-Authenticate`) never reach this table.

| Token scopes | HTTP | Outcome | Reason | `safeData` |
| --- | --- | --- | --- | --- |
| includes `report:read` | 200 | `success` | `RESOURCE_REPORT_RETURNED` | `{resource, action, report: {id, title, content}}` |
| includes `report:summary`, not `report:read` | 200 | `success` | `RESOURCE_SUMMARY_RETURNED` | `{resource, action, summary: {id, title, summary}}` |
| neither | 403 | `denied` | `RESOURCE_SCOPE_INSUFFICIENT` | `{}` |

Other token-mode answers: an uncatalogued resource or action is 404 `SAMPLE_RESOURCE_NOT_FOUND`; a `scenario` field that is non-empty after trimming is 400 `RESOURCE_SCENARIO_NOT_ALLOWED`. Every log line for a token-mode request that reached the verified handler (passed the verifier) carries `client_id`, `sub` and `jkt` from the verified identity. A request the verifier refused is logged as `protected resource request refused` with its HTTP status and IDs only. Neither service logs or returns a token, a DPoP proof, a token ID or any request header.

### Participant token adapter

For each `/demo` call in token mode the adapter calls `TokenSession.Authorize(ctx, "POST", <resource>/demo)` and sends the returned `Authorization` and `DPoP` headers. Nothing is cached: every call gets a fresh pair. The `scenario` field is not forwarded. The Resource answer maps as follows:

| Situation | Participant HTTP | Outcome | Reason |
| --- | --- | --- | --- |
| Lifecycle not `ready` (no session) | 503 | `unavailable` | `TOKEN_SESSION_NOT_READY` |
| `Authorize` fails (the error text is discarded) | 502 | `error` | `TOKEN_AUTHORIZE_FAILED` |
| Resource 401 | 403 | `denied` | `TOKEN_REJECTED` |
| Resource 403 | 403 | `denied` | `TOKEN_FORBIDDEN` |
| Resource 503 | 503 | `unavailable` | `TOKEN_RESOURCE_UNAVAILABLE` |
| Resource answer repeats a JSON member name in any object, at any depth (compared after unescaping) | 502 | `error` | `TOKEN_RESOURCE_DUPLICATE_MEMBER` |
| Resource answer contains this request's `Authorization` value, bare token or DPoP proof, or a standard or URL-safe base64 encoding of one (raw, in any decoded JSON string, or in the result about to be returned) | 502 | `error` | `TOKEN_CREDENTIAL_ECHOED` |
| Resource answer is not valid against the token-mode contract, including the strict success shape below | 502 | `error` | `TOKEN_RESOURCE_INVALID` |
| Resource 200 | 200 | `success` | the Resource's scope-table reason |
| Other documented Resource answers | as for `http-sample` | as for `http-sample` | the Resource's reason |

Token-mode success data must have the documented shape exactly: `resource`, `action` and either `report` (`id`, `title`, `content`) or `summary` (`id`, `title`, `summary`), with no other key. `id` is at most 64 bytes of `A-Z`, `0-9` and `-`; `title` is at most 128 bytes and the text at most 512; no whitespace-separated word may be longer than 32 bytes. This refuses an encoded credential carried whole in a free-form field. A credential split into short fragments is not detected; the bounds only limit how much can be carried. The credential checks run on the body before decoding and again on the result as it will be returned.

The bodies of 401, 403 and 503 answers are not read into the result. For every other answer the Resource's `explanation` is replaced by a fixed local text, so no upstream text is forwarded in token mode.

### Participant lifecycle and `GET /state`

In token mode `Start` runs the injected `Bootstrapper` in the background. Every state transition is recorded with a timestamp and a reason from a fixed vocabulary; a reason the bootstrapper passes that is not in the vocabulary is recorded as `unspecified`, so no upstream text reaches `/state`.

States: `idle`, `registering`, `presenting`, `acquiring_token`, `ready`, `failed_registration`, `failed_presentation`, `failed_token`, `failed_connector_unreachable`. `ConnectorBootstrap` never reports `registering`: its client is provisioned ([Token mode](#token-mode)).

Reasons: `step_started`, `step_completed`, `connector_unreachable`, `registration_rejected`, `presentation_rejected`, `token_rejected`, `nonce_retry_exhausted`, `upstream_error`, `timeout`, `bootstrap_error`, `retry_scheduled`, `retries_exhausted`, `reset`, `unspecified`.

If a run ends in an error without a `failed_*` state, the lifecycle records the failure state of the step in progress with reason `bootstrap_error`. Only `failed_connector_unreachable` is retried: up to `Config.BootstrapAttempts` runs (default 3), waiting `Config.BootstrapBackoff` (default 500 ms) doubled per retry, each wait recorded as `retry_scheduled`. After the bound the state stays `failed_connector_unreachable` with `retries_exhausted`. Every other failure is final until `/reset`.

`GET /state` returns:

```json
{"mode":"token","state":"ready","attempt":1,"lastErrorCode":"","history":[{"state":"presenting","reason":"step_started","at":"2026-10-21T09:00:00Z"},{"state":"acquiring_token","reason":"step_started","at":"2026-10-21T09:00:00Z"},{"state":"ready","reason":"step_completed","at":"2026-10-21T09:00:01Z"}]}
```

`lastErrorCode` is the reason of the most recent failure. In sample mode `/state` reports `mode: sample` and `state: idle`; the history is empty until the first `/reset`, after which it holds the `idle` / `reset` entry.

### `POST /reset`

`POST /reset` on the Participant waits for an in-flight bootstrap run to return (it is not cancelled, so a token acquisition is never cut short), then retires the ready session, if any: that session starts no further renewal, and a renewal it is running is waited for in the same way. It also stops any pending retry (no new run starts once a reset has begun), clears the history, `lastErrorCode` and the session reference, records `idle` / `reset` and starts a new bootstrap. It returns 200 with the state taken right after the reset, before the new run can change it: always `idle` with the single `idle` / `reset` entry. Resets are serialised. A reset that does not get its turn, or whose wait for the run does not finish, within `PARTICIPANT_REQUEST_TIMEOUT` returns 503 `{"reason":"reset_wait_timeout"}` and clears nothing (a session it was retiring may renew again); if it had already stopped pending retries, they stay stopped, and a later reset restarts the bootstrap. In sample mode it only records the reset.

`POST /reset` on the Protected Resource returns 200 with `status: reset`, `mode` and `seedVersion`. Its demo data is the read-only seed, so there is nothing to rebuild.

Neither reset touches replay, consumption or key state. The Participant's reset drops its session, so the new run acquires a new token with a fresh challenge and outcome; its DPoP key stays. The Resource's reset leaves its replay record as it is. Both reset endpoints are unauthenticated demo controls: expose them on restricted routes only.

### Seed data

The Resource's report data is in `services/protectedresource/seed/v1.json`, embedded at build time. It holds a `version` (now `v1`), the standard report, the alternative report and the summary. `/health` reports it as `seedVersion`. A change to the data is a new file with a new version, not an edit of `v1.json`.

### Deterministic runs

Request and correlation IDs and timestamps can be fixed only through unexported test hooks (`Server.now`, `Server.newID`) set from `_test.go` files. No environment variable or configuration field reaches them. With the hooks fixed, the tests check that two identical runs of `/health`, `/state`, `/demo` and `/reset` produce byte-identical responses on both services.

## How the services communicate

```text
Test caller / future journey runtime
  -> POST Participant:8085/demo
  -> Participant http-sample adapter
  -> POST Protected Resource:8086/demo
  <- sample JSON result, matched requestId and correlationId
```

Only Participant makes an outbound application call. Resource has no callback to Participant or other outbound application dependency. Participant forwards the documented JSON fields, with `Content-Type` and `Accept` set to `application/json`. In sample mode it does not forward bearer tokens, passwords or cookies; in token mode it sends only the `Authorization` and `DPoP` headers from its own `TokenSession`, never ones received from its caller. It does not retry requests and refuses redirects. The server-controlled Resource URL is not accepted as a request-body input.

Both demo endpoints accept one JSON object, at most 64 KiB, with these fields:

```json
{
  "resource": "sample-report",
  "action": "read",
  "scenario": "success",
  "requestId": "service-check-success-1",
  "correlationId": "service-check-run-1"
}
```

`resource` and `action` are required; the Resource sample catalogue supports `sample-report` / `read`. Omitted scenario defaults to success at Resource. IDs are optional, but should be supplied for traceable checks. Unknown body fields are rejected. The response includes IDs, `source`, `mode`, `outcome`, `reasonCode`, `explanation`, `timestamp` and `safeData`. Non-success results contain empty `safeData`.

For the standard Resource adapter with the HTTP connection enabled:

| Scenario | Resource HTTP | Participant HTTP | Outcome | Reason |
| --- | --- | --- | --- | --- |
| `success` | 200 | 200 | `success` | `SAMPLE_RESOURCE_RETURNED` |
| `denied` | 403 | 403 | `denied` | `SAMPLE_ACCESS_DENIED` |
| `unavailable` | 503 | 503 | `unavailable` | `SAMPLE_RESOURCE_UNAVAILABLE` |
| `error` | 500 | 502 | `error` | `SAMPLE_RESOURCE_ERROR` |
| `slow` | 200 if within deadlines | 200 if within deadlines | `success` | `SAMPLE_SLOW_RESOURCE_RETURNED` |

A Participant outbound deadline produces 504 / `SAMPLE_REQUEST_TIMEOUT`; a failed connection produces 503 / `SAMPLE_CONNECTION_FAILURE`. Resource's own timeout may instead be mapped to Participant's generic unavailable status. Do not rely on identical 5-second deadlines to demonstrate a particular timeout source. For ordinary slow-success checks retain the 2-second delay; for a Participant timeout check set its deadline shorter than the Resource delay.

These endpoint reason codes are not IF-01 security events and must not be relabelled as the successful-call, revoked-credential or wrong-scope security journeys in [Scenario decisions](scenarios.md).

## Local source smoke check

Start these from the repository root in separate Bash terminals:

```sh
PROTECTED_RESOURCE_ADDRESS=127.0.0.1:8086 PROTECTED_RESOURCE_MODE=sample \
PROTECTED_RESOURCE_ADAPTER_MODE=sample PROTECTED_RESOURCE_SLOW_DELAY=2s \
PROTECTED_RESOURCE_REQUEST_TIMEOUT=5s go run ./cmd/protected-resource
```

```sh
PARTICIPANT_ADDRESS=127.0.0.1:8085 PARTICIPANT_ADAPTER_MODE=http-sample \
PARTICIPANT_RESOURCE_URL=http://127.0.0.1:8086 \
PARTICIPANT_REQUEST_TIMEOUT=5s go run ./cmd/participant
```

PowerShell equivalents:

```powershell
# Terminal 1
$env:PROTECTED_RESOURCE_ADDRESS='127.0.0.1:8086'
$env:PROTECTED_RESOURCE_MODE='sample'
$env:PROTECTED_RESOURCE_ADAPTER_MODE='sample'
$env:PROTECTED_RESOURCE_REQUEST_TIMEOUT='5s'
$env:PROTECTED_RESOURCE_SLOW_DELAY='2s'
go run ./cmd/protected-resource
```

```powershell
# Terminal 2
$env:PARTICIPANT_ADDRESS='127.0.0.1:8085'
$env:PARTICIPANT_ADAPTER_MODE='http-sample'
$env:PARTICIPANT_RESOURCE_URL='http://127.0.0.1:8086'
$env:PARTICIPANT_REQUEST_TIMEOUT='5s'
go run ./cmd/participant
```

Then run the dependency-free Node.js 22+ checker from another terminal:

```sh
node scripts/smoke-application-services.mjs
```

It covers sample mode only. It checks both health endpoints, all five standard scenarios directly and through Participant, ID propagation, sample labels, reasons and safe-data shape. It exits nonzero on failure. Use `--participant-url` and `--resource-url` for explicitly approved test endpoints; it does not create deployments or configure credentials. Health only establishes that the service is running; Participant health does not probe Resource. The sample endpoint has no built-in authentication: use approved restricted routes, not an unrestricted public endpoint.

## Deployment and returned evidence

Deploy the two services in the shared OSC `zero-trust` namespace per [Application workloads](environments/application-workloads.md), as separate releases outside the platform umbrella. Images target `linux/amd64`, are published by the release workflow and selected by digest; the application-service chart (`deployment/helm/application-service`) installs each one. Network policy must allow the approved caller to Participant, Participant to Resource and required DNS; Resource needs no outbound application route. Observe namespace quotas and minimum requests. No cluster-scoped resources are needed by these applications.

Return the source revision, image digests, effective non-secret environment settings, both health results, scenario results and correlated JSON logs from both processes. The current deployment and its results are recorded in [Application service verification](application-services-verification.md). The UI/ORCE bridge is outside these services. Shared-OSC deployment and sample HTTP results establish application integration only, not final two-zone security acceptance.
