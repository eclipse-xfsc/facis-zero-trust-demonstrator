# API dock rows as executable BDD (2026-11-23)

Rows ZT-07 (API Dock) and ZT-77 (Mock Replaceable) are implemented as Go scenarios in the cluster mode
(`BDD_MODE=cluster`, steps in `internal/bdd/api_dock_rows_test.go`), on the local-services target of the
other authorization rows: the real `connector` binary on PostgreSQL and OpenBao, the Participant and
the Resource built from the environment as their binaries build them. The interfaces, the settings and
the commands are in [API dock](../../api-dock.md).

**ZT-07 passed. ZT-77 is kept pending** (review, 23 Nov: its live test replaces only the resource side with a real-world API, while the row asks for each mock; it stays pending until the participant side is a real-world integration too or the scope is agreed). **ZT-77 was not run**: it needs the provider's own API and a token for it, which was not
available on the day. Its scenario is skipped without the token file and is reported not run; the
stand-in does not decide it.

| | |
|---|---|
| Run | `apidock-20261123T144135Z`, target `local-services` |
| Commit | `310b2e3b` (code and pack; this record and its index row were not yet committed) |
| Where | project lead's workstation (Darwin arm64, Go 1.27.0), Docker: `postgres:16.10-alpine@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297`, `openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315` (dev mode, transit mounted). **No Kubernetes cluster**: no kube-system UID applies; no zone was touched |
| Result | 2 scenarios: ZT-07 3 steps passed; ZT-77 3 steps skipped (`bundles/bdd/apidock-cluster-report.json`) |
| Evidence | `bundles/bdd/evidence/bdd-zt-007/local-services/apidock-20261123T144135Z/` (git-ignored, delivered with the submission): each package's `go test -json` log and the journey's record `api-dock.txt` |

```bash
TOKEN_STORE_TEST_DATABASE_URL=postgres://... TRANSIT_TEST_ADDR=http://127.0.0.1:8200 TRANSIT_TEST_TOKEN=... \
BDD_TARGET=local-services BDD_RUN_ID=<run> BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/apidock-cluster-report.json \
  go test ./internal/bdd -godog.tags='@ZT-07,@ZT-77'
# ZT-77 runs only with:  API_DOCK_LIVE_TOKEN_FILE=/absolute/path/to/token
```

## Rows

| Row | Steps run | Decided from | Result |
|---|---|---|---|
| ZT-07 API Dock | `services/participant`: `TestAPIDockJourney`; `services/protectedresource`: `TestCloudDock`, `TestCloudScopeBoundary`, `TestCloudSettingsRejected`, `TestCloudInterfaceCheck`; `services/connector`: `TestServeBootstrapsTheRegistrarAndIssuesVerifiableTokens` | all passed, none skipped; `api-dock.txt` (below) | passed |
| ZT-77 Mock Replaceable | `services/participant`: `TestAPIDockLive` (the same journey with `https://api.ionos.com/cloudapi/v6` docked) | the test passed and `api-dock.txt` holds the journey lines for the `live provider` | **not run** (no token file) |

The record of the ZT-07 run:

```text
baseline: supplied participant -> Connector token -> supplied resource mock -> 200 RESOURCE_REPORT_RETURNED report FACIS-SAMPLE-REPORT-001
resource dock: cloud-api adapter on the local stand-in accepted by the configuration-time interface check
journey: supplied participant -> Connector token -> docked resource (local stand-in) -> 200 RESOURCE_REPORT_RETURNED report CLOUD-DATACENTERS: 2 data centers on the first inventory page of at most 100.
participant dock: replacement participant backend registered through DCR -> verified-presentation token -> docked resource (local stand-in) -> 200 RESOURCE_REPORT_RETURNED report CLOUD-DATACENTERS
core unchanged: one Connector process, JWKS digest 76e6d1f7dffe4088 and resource trust settings digest 6cb02e86088e18f8 before and after the dock
rejected at configuration time: an API answering another interface -> CLOUD_INTERFACE_REJECTED cause CLOUD_RESPONSE_INVALID, recorded, resource not started
rejected at configuration time: an adapter name the resource does not know
```

What each line stands on:

- **Resource dock.** The Resource is rebuilt with `PROTECTED_RESOURCE_ADAPTER_MODE=cloud-api` behind the
  same public URL; no other setting changes. The supplied Participant is not restarted and presents the
  token it already held; the answer passes its unchanged contract check, and the Resource's log names
  the adapter and the caller (`"adapter":"cloud-api","client_id":...`). The stand-in counted three
  calls: the interface check and the two protected calls.
- **Participant dock.** A second backend, not `services/participant`, is registered through the
  Connector's DCR and uses only the documented interface (challenge, verified-presentation grant,
  DPoP-bound token, proof per call); the Resource logs its client id on the cloud-backed answer.
- **Core unchanged.** One connector process for the whole test; its JWKS and the Resource's issuer,
  JWKS URL, audience and public URL are digested before and after.
- **Rejected at configuration time.** Resource side: a stand-in returning a collection of another type
  is refused by the check before the Resource is built, with the logged
  `CLOUD_INTERFACE_REJECTED` / `CLOUD_RESPONSE_INVALID` and exactly one call; `TestCloudInterfaceCheck`
  and `TestCloudSettingsRejected` cover the other causes and settings. Participant side: the connector
  binary refuses a registration without DPoP binding, a public client and metadata outside the
  interface with `registration_rejected`, each with its audit row `TOK-REGISTRATION-REJECTED` and rule
  (asserted inside the connector test from the `audit_event` table).

The stand-in follows the provider's public reference, checked on the day against
`https://api.ionos.com/docs/cloud/v6/`: server `https://api.ionos.com/cloudapi/v6`, `GET /datacenters`
with `depth` and `limit` (1 to 10000), `Authorization: Bearer <token>`, answer `{id, type: "collection",
href, items: [{id, type: "datacenter", href, metadata, properties}], offset, limit, _links}`, 401 for a
refused credential. With a deliberately invalid token the live endpoint answered 401 and the live test
failed closed (`CLOUD_INTERFACE_REJECTED`, cause `CLOUD_ACCESS_DENIED`); that run is not evidence of
the row.

## Limits

- ZT-07 is decided with a stand-in, not the provider. ZT-77 has no result until it is run with a token.
- The participant-side replacement is a second backend written for this proof against the documented
  interface. It is not a third-party product: when ZT-77 runs, the real-world API is the provider's on
  the resource side only. Whether that satisfies "each is replaced by a real-world API" is for the
  acceptance authority to decide.
- Not a cluster run and no mesh. The guard and the policy evaluator are not in this journey (the
  Participant calls the Resource, which verifies the token and the proof itself); that they are
  untouched rests on the change set, which edits only `services/protectedresource`, its command, tests
  and documents. The guarded path with a docked API has not been run.
- The role-carrying outcomes are IF-03 fixture outcomes signed by a run key, as in the other
  authorization rows.
- The chart fixture `ci/cloud-resource-values.yaml` is rendered and linted only. A deployment needs an
  admitted image with the adapter and an egress rule and mesh route to the provider; none exists yet.
- The cloud adapter refuses to start when the provider cannot be reached at start.

## Checks

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./internal/bdd ./services/... ./cmd/...` | pass |
| `go run ./cmd/bddpack -check` | pass |
| `go test ./internal/bdd` (strict) | pass |
| `BDD_MODE=catalogue go test ./internal/bdd` | pass |
| `BDD_MODE=cluster-dryrun go test ./internal/bdd` | pass |
| `go test ./services/protectedresource ./services/participant` (with the local services) | pass; `TestAPIDockLive` skipped |
| `scripts/ci/check-charts.sh deployment/helm/application-service` | pass |
| `golangci-lint run ./...` (pinned build) | 0 issues |
