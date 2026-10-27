# Participant and Protected Resource services

Two Go sample services for application deployment and HTTP integration. It does not implement the Connector/guard authorization path, Keycloak login, workload identity, attestation or real API replacement. A sample `denied` result is deliberately selected test data, not a security decision. The responses remain marked `source: sample` and `mode: sample`; health reports `liveMode: unavailable`.

## Source and build

Use the repository root as the build context and retain its `go.mod` and `go.sum`. The services use the standard library only and add no module dependencies.

| Service | Entry point | Package | Default TCP port | Endpoints |
| --- | --- | --- | --- | --- |
| Participant | `cmd/participant` | `services/participant` | 8085 | `GET /health`, `POST /demo` |
| Protected Resource | `cmd/protected-resource` | `services/protectedresource` | 8086 | `GET /health`, `POST /demo` |

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
| `PARTICIPANT_ADAPTER_MODE` | `sample` | `sample` handles the result internally. `http-sample` calls Protected Resource over HTTP(S). |
| `PARTICIPANT_RESOURCE_URL` | Empty | Required for `http-sample`; base URL without `/demo`, credentials, query or fragment. The adapter appends `/demo`. |
| `PARTICIPANT_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

`configs/participant.env.example` enables the two-process local HTTP route. `configs/participant.osc.env.example` shows the separate-service deployment shape. It matches the Service the application-service chart (`deployment/helm/application-service`) creates. `127.0.0.1` cannot address a different pod.

### Protected Resource

| Variable | Code default | Meaning |
| --- | --- | --- |
| `PROTECTED_RESOURCE_ADDRESS` | `:8086` | HTTP listener; use `:8086` in a container and loopback for a host-only test. |
| `PROTECTED_RESOURCE_REQUEST_TIMEOUT` | `5s` | Positive duration bounding each resource request. |
| `PROTECTED_RESOURCE_SLOW_DELAY` | `2s` | Positive simulated delay; must be shorter than the Resource request timeout. |
| `PROTECTED_RESOURCE_MODE` | `sample` | Only `sample` is supported. |
| `PROTECTED_RESOURCE_ADAPTER_MODE` | `sample` | `sample` or `sample-alternative`; both are deterministic sample data. |
| `PROTECTED_RESOURCE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

The current sample services require no application secrets, database, persistent volume or Keycloak client secret. Registry credentials and ingress TLS secrets belong to deployment configuration; secret values must not enter this repository. The applications serve plain HTTP; HTTPS routes require the approved ingress configuration. Do not disable certificate verification for outbound HTTPS calls.

## How the services communicate

```text
Test caller / future journey runtime
  -> POST Participant:8085/demo
  -> Participant http-sample adapter
  -> POST Protected Resource:8086/demo
  <- sample JSON result, matched requestId and correlationId
```

Only Participant makes an outbound application call. Resource has no callback to Participant or other outbound application dependency. Participant forwards the documented JSON fields, with `Content-Type` and `Accept` set to `application/json`. It does not forward bearer tokens, passwords or cookies, does not retry, and refuses redirects. The server-controlled Resource URL is not accepted as a request-body input.

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

It checks both health endpoints, all five standard scenarios directly and through Participant, ID propagation, sample labels, reasons and safe-data shape. It exits nonzero on failure. Use `--participant-url` and `--resource-url` for explicitly approved test endpoints; it does not create deployments or configure credentials. Health only establishes that the service is running; Participant health does not probe Resource. The sample endpoint has no built-in authentication: use approved restricted routes, not an unrestricted public endpoint.

## Deployment and returned evidence

Deploy the two services in the shared OSC `zero-trust` namespace per [Application workloads](environments/application-workloads.md), as separate releases outside the platform umbrella. Images target `linux/amd64`, are published by the release workflow and selected by digest; the application-service chart (`deployment/helm/application-service`) installs each one. Network policy must allow the approved caller to Participant, Participant to Resource and required DNS; Resource needs no outbound application route. Observe namespace quotas and minimum requests. No cluster-scoped resources are needed by these applications.

Return the source revision, image digests, effective non-secret environment settings, both health results, scenario results and correlated JSON logs from both processes. The current deployment and its results are recorded in [Application service verification](application-services-verification.md). The UI/ORCE bridge is outside these services. Shared-OSC deployment and sample HTTP results establish application integration only, not final two-zone security acceptance.
