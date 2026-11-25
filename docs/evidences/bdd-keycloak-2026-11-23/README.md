# Keycloak, policy and token integration as executable BDD (2026-11-23)

Row `TDR-BDD-05` runs as a Go scenario in the cluster mode (`BDD_MODE=cluster`, steps in
`internal/bdd/keycloak_rows_test.go`). Its target is local services: a real Keycloak holding the
Helm-rendered `facis-ztd` realm, PostgreSQL and OpenBao, with the viewer boundary (`UIAuth`, the source
ORCE runs) and the real Go token path. No cluster and no mesh are involved, so there is no kube-system UID.

| | |
|---|---|
| Run | `ztd-keycloak-1795444910-46971`, target `local-services` |
| Commit | `9dd3d694` (clean tree apart from this record) |
| Where | project lead's workstation (Darwin arm64), Docker 28.5.1: `quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`, `postgres:16.10-alpine@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297`, `openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315` |
| Result | 1 scenario, 3 steps, all passed (`bundles/bdd/keycloak-ztd-keycloak-1795444910-46971.json`) |
| Evidence | `bundles/bdd/evidence/bdd-tdr-005/local-services/ztd-keycloak-1795444910-46971/` (git-ignored, delivered with the submission): `target.json`, `viewer.json`, `catalogue.json`, `vp-e2e.txt`, each package's `go test -json` log |

```bash
PATH=/opt/homebrew/bin:$PATH scripts/verify-keycloak/run.sh
```

The script creates three uniquely named containers, runs only `@TDR-BDD-05` and removes the containers,
the temporary certificate, the passwords and the token file on exit. It never calls kubectl. A missing
input fails the scenario and is named; the cluster dry run lists the row as not run.

## Row

| Step | What it runs | Decided from |
|---|---|---|
| Given the target Keycloak, policy and token services are reachable | checks the inputs (issuer, UI origin, persona passwords, PostgreSQL, OpenBao) and writes `target.json` | a missing input fails the step |
| When a valid and an invalid access flow are executed | `scripts/verify-keycloak/viewer.cjs`: code + PKCE logins of `bdd-operator` and `bdd-observer` against Keycloak over HTTPS, then commands through `UIAuth`; `TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao` with the operator's Keycloak access token as an extra case; `TestEndToEndPresentationGrantTokenProtectedCallAndRenewal` | the proofs' exit and `go test -json` results |
| Then the valid flow is authorized and the invalid flow is denied with traceable evidence | reads the records | `viewer.json`, `catalogue.json`, `vp-e2e.txt`; a test that is skipped, missing or failed fails the row |

Viewer decisions, each a `ui.authorization` record whose `correlation_id` is the response's `X-Request-ID`:

| Case | Status | Reason code |
|---|---|---|
| operator start | 200, dispatched once | `UI-AUTHORISED` |
| observer start | 403, not dispatched | `UI-NOT-AUTHORISED` |
| observer configuration | 403, not dispatched | `CFG-NOT-AUTHORISED` |
| operator after logout (Keycloak also refuses the refresh token) | 401, not dispatched | `LOGGED_OUT` |
| observer with an expired access token | 401, not dispatched | `EXPIRED` |

Machine decisions from the guard catalogue, each with the guard's event under the caller's correlation id:

| Case | Status | Reason code |
|---|---|---|
| allowed (control) | 200, forwarded; guard and policy events `allowed` | rule `m3-report-summary` |
| Keycloak viewer token | 401 | `TOK-INVALID`, detail `signature_invalid` |
| insufficient scope | 403; guard and policy events `denied` | `POL-RULE-DENY`, rule `m3-scope-required` |

`vp-e2e.txt` holds the verified presentation, the issued DPoP-bound token, the protected call and the
refusal of the revoked credential. The Keycloak token is therefore refused on the machine path, which
keeps accepting only the connector's own tokens: the OAuth2/DPoP path is unchanged apart from the added
test case, which runs only when `KEYCLOAK_GUARD_TOKEN_FILE` is set.

## Packaged ORCE image

> Superseded in the final tree (23 Nov): the ORCE image packaging commit was reverted; the image keeps its own authentication. The packaged-image results below are historical.

The image was built from the commit (`docker build --platform linux/amd64 -f
deployment/docker/orce/Dockerfile`) and started with generated credentials and example identity values.

| Request | Result |
|---|---|
| `POST /lifecycle` without credentials, and with a wrong password | 401 |
| `POST /lifecycle` with the HTTP user's Basic credentials | 400 (authenticated; empty command refused) |
| `GET /dev/ztd/oidc/login` | 303 to the configured issuer with the configured callback |
| `GET /dev/ztd/api/session` | 401 from the viewer boundary |
| `POST /dev/ztd/api/journey` without a session | 401 `LOGGED_OUT`, `X-Request-ID` equal to the logged `ui.authorization` record |
| `GET /dev/facis-demo/` | 200 |
| `/settings.js`, the journey route with a trailing slash, in upper case or percent-encoded, a traversal out of the UI directory | 401 |

The log held no error and the flows started.

## Checks

| Command | Result |
|---|---|
| `go build ./...`, `go vet ./...` | passed |
| `go run ./cmd/bddpack -check` | passed |
| `go test ./internal/bdd`, `BDD_MODE=catalogue`, `BDD_MODE=cluster-dryrun` | passed |
| `go test ./services/token-store/internal/server` | passed |
| pinned `golangci-lint run ./...` | 0 issues |
| `node --test tests/demonstrator/*.test.cjs` | 151 passed |
| `scripts/ci/check-charts.sh deployment/helm/orce` | passed, including the two refused identity values |

## Limits

- Local services only: no zone, no kind cluster, no mesh. The image was not deployed.
- The viewer proof runs the `UIAuth` source in a Node harness, not inside ORCE; the image test above
  covers the routes without a Keycloak login. No browser was used: the login form is submitted over HTTPS.
- The server's own import does not read the `userProfile` key the chart's import tool applies, so the
  proof carries the same profile as the realm component a stock export holds
  (`scripts/verify-keycloak/realm.cjs`). Persona passwords are random and exist only in that import.
- Expiry is exercised by moving the boundary's clock past the token's lifetime, not by waiting.
- The machine cases keep the fixture role outcomes of the existing integration tests.
- On IONOS the interim host routes `/dev` to another ORCE (see the ORCE chart's README), so the image's
  viewer routes are not reachable there through the ingress until that route changes.
