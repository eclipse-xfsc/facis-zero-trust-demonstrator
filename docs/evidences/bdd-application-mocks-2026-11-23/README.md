# Application mock feed rows (2026-11-23)

The Participant and the Protected Resource now publish their steps on IF-01 v2 (`internal/appevents`).
ZT-75 runs as a Go scenario in the cluster mode and passed on local services. ZT-74 stays `@pending`.
The Annex wording is unchanged.

| Row | Status | Scenario | Result |
|---|---|---|---|
| ZT-75 Protected Resource Mock | implemented, `@cluster` | `features/go/policy.feature`, `@ZT-75 @BDD-ZT-075` | passed, 3 of 3 steps |
| ZT-74 Participant Backend Mock | pending | `features/go/authorization.feature`, `@ZT-74 @BDD-ZT-074` | not run |


> Update (23 Nov): ZT-74 was implemented afterwards on the kind mesh: [participant mock record](../bdd-participant-mock-2026-11-23/README.md).

## ZT-75

| Step | What it does |
|---|---|
| Given the protected-resource mock exposes responses for different access roles | prepares the evidence directory `bundles/bdd/evidence/bdd-zt-075/<target>/<run>` |
| When requests with different authorized and unauthorized roles are executed | runs `TestApplicationFeedEndToEnd` (`services/participant/tokenpath_test.go`) with `go test -json` against the real Connector binary, PostgreSQL and OpenBao |
| Then role-appropriate responses are returned and visualized AND unauthorized roles do not receive protected content. | refuses a skipped, missing or failed test, then decides from `feed.json`, the events the test read back from the feed bridge's `/v2/events` (`checkApplicationFeed`, `internal/bdd/application_mock_rows_test.go`) |

The test logs in four Participants at the Connector (reader, viewer, both scopes, and an authenticated
client whose role maps to neither scope), each calls the Resource with its own DPoP-bound token, and
three calls reach the Resource directly without a proof, with a replayed proof and with a token for
another audience. The producers' lines are posted to the bridge's `/ingest`, which validates them
against the v2 event schema, and are read back from `/v2/events`; both snapshot versions are validated.

The record of the run holds all nine accesses of the Resource:

| Access | Count | State | Reason |
|---|---|---|---|
| `access role=reader` | 2 | `success` | `APP-RESOURCE-REPORT-RETURNED` |
| `access role=viewer` | 2 | `success` | `APP-RESOURCE-SUMMARY-RETURNED` |
| `access role=reader_and_viewer` | 1 | `success` | `APP-RESOURCE-REPORT-RETURNED` |
| `access role=unauthorized` | 1 | `denied` | `APP-RESOURCE-SCOPE-INSUFFICIENT`, correlated to the Participant's `APP-TOKEN-FORBIDDEN` |
| `access role=not_evaluated` | 3 | `denied` | `APP-PROOF-ABSENT`, `APP-PROOF-REPLAYED`, `APP-AUDIENCE-MISMATCH` |

The negative case is decided from the recorded refusal (the reason code and its correlation), and the
test itself fails if a refused answer carries any protected content (HTTP 403 with empty `safeData`
for the unauthorized role; no report text in a verifier refusal).

- Mode: `BDD_MODE=cluster`, tag `@ZT-75`, by `PATH=/opt/homebrew/bin:$PATH scripts/verify-application-feed/verify.sh`.
- Target: `local-services` — PostgreSQL 16.10 and OpenBao 2.7.0 in Docker, pinned by digest, created and
  removed by the script. No Kubernetes cluster, so no kube-system UID.
- Run id: `application-feed-20261123T143137Z-e3ffe6`.
- Commit: `1aa5a08e` (events: `f3e6e9b2`).
- Cucumber JSON: `bundles/bdd/application-feed-20261123T143137Z-e3ffe6.json` (git-ignored).
- Evidence: `bundles/bdd/evidence/bdd-zt-075/local-services/application-feed-20261123T143137Z-e3ffe6/`
  (`services_participant.jsonl`, `feed.json` with 37 events; git-ignored).

## ZT-74 left pending

Its Then requires that the mock "behaves as a participant backend using the trusted channel". The
events exist and were read back from the feed in the run above (registration confirmed and rejected,
`presenting`, `acquiring_token`, `ready`, requests allowed and denied), but the Participant's call
reached the Resource over loopback HTTP. No run exists in which the Participant's own call crosses
the trusted channel; ZT-73 is pending for the same reason and ZT-04 and ZT-19 are pending. What is
missing: a run of the Participant through the channel, with its lines forwarded to the feed.

## Checks

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go run ./cmd/bddpack -check` | pass |
| `go test ./internal/bdd` | pass |
| `BDD_MODE=catalogue go test ./internal/bdd` | pass |
| `BDD_MODE=cluster-dryrun go test ./internal/bdd` | pass |
| `go test -race ./services/participant ./services/protectedresource ./internal/appevents ./internal/feedbridge` | pass |
| `golangci-lint run ./...` (pinned build) | pass, 0 issues |
| `scripts/ci/check-charts.sh deployment/helm/application-service` | pass |
| `npm run contracts` | pass: 12 schemas, 78 fixtures, 6 OpenAPI documents, 120 reason codes |
| `scripts/verify-application-feed/verify.sh` | pass, the run above |

## Limits

- "Visualized" is proven at the feed: the events are served by the bridge's `/v2/events` and
  `/v2/snapshot`. No browser rendering was observed, and the v1 feed leaves these v2-only sources out.
- The bridge handlers run in the test process, and the test posts the producers' lines to `/ingest`.
  No continuous forwarder from the container logs to the bridge is installed by this change.
- Local services only: no mesh, no guard, no zone. Deployed images do not carry the events until
  rebuilt; the feed-bridge image needs the updated v2 source pattern. No zone was modified.
- Roles in events come from verified scopes only. A request refused by the token verifier reports
  `not_evaluated`. Registration is the confirmation of a provisioned client by an authenticated
  challenge, not dynamic registration by the Participant.
- A `/state` read publishes nothing; status reaches the feed through lifecycle transitions.
