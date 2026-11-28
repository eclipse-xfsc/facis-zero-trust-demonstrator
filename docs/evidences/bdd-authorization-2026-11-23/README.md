# Authorization and policy rows as executable BDD (2026-11-23)

Four G3 rows of the families *authorization* and *policy* run as Go scenarios in the cluster mode
(`BDD_MODE=cluster`, steps in `internal/bdd/authorization_cluster_test.go` and
`internal/bdd/policy_cluster_test.go`). Their proof is the token path's integration tests run against a
real PostgreSQL and OpenBao: the real `connector` and `verification-service` binaries, the token store
(acquisition, renewal, substitution), the guard runtime, the policy evaluator and the token verifier. The
scenario runs the named tests with `go test -json`, fails on any test that is skipped, missing or failed,
and decides the row from the records the tests write (`catalogue.json`, `vp-e2e.txt`).

| | |
|---|---|
| Run | `authz-20261123T125446Z`, target `local-services` |
| Commit | `ee4b43c3` (clean tree) |
| Where | project lead's workstation (Darwin arm64, Go 1.27.0), Docker: `postgres:16.10-alpine@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297`, `openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315` (dev mode, transit mounted). **No Kubernetes cluster**: no kube-system UID applies; no zone was touched |
| Result | 4 scenarios, 12 steps, all passed (`bundles/bdd/authz-cluster-report.json`) |
| Evidence | `bundles/bdd/evidence/bdd-zt-0{06,21,22,76}/local-services/authz-20261123T125446Z/` (git-ignored, delivered with the submission): each package's `go test -json` log and the tests' records |

```bash
TOKEN_STORE_TEST_DATABASE_URL=postgres://... TRANSIT_TEST_ADDR=http://127.0.0.1:8200 TRANSIT_TEST_TOKEN=... \
BDD_TARGET=local-services BDD_RUN_ID=<run> BDD_MODE=cluster GODOG_CUCUMBER_OUT=bundles/bdd/authz-cluster-report.json \
  go test ./internal/bdd -godog.tags='@ZT-06,@ZT-21,@ZT-22,@ZT-76'
```

A missing input fails the scenario and is named; the cluster dry run lists the four rows as not run.

## Rows

| Row | Steps run | Decided from | Result |
|---|---|---|---|
| ZT-21 OAuth2 Server | `authelia`: `TestRegistration_RegisteredClientObtainsBoundToken`, `TestRegistration_RequiresAnAuthorisedToken`, `TestVP_ChallengeThenOutcomeIssuesABoundSignedToken`, `TestVP_EveryOutcomeRefusalCarriesItsCode`, `TestVP_ClientNotAllowedTheGrantIsRefused`, `TestDPoP_ValidProofIssuesBoundToken`, `TestDPoP_BoundClientWithoutProofIsRefused`, `TestInterface_TokenEndpointStatuses` (unknown client: 401 `invalid_client`); `renew`: `TestEndToEndPresentationGrantTokenProtectedCallAndRenewal` | all passed; `vp-e2e.txt`: presentation verified and outcome signed, the connector consumed it and issued a DPoP-bound token, the protected call 200; the revoked credential recorded `CRED-REVOKED`, the store refused the outcome, the connector consumed nothing | passed |
| ZT-22 Token Storage | `server`: `TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao`, `TestSubstitute_ValidTokenYieldsTheAuthorizationAndAFreshProofAcceptedByB`, `TestSubstitute_ExpiredOrFailedOnlyIsNoUpstream`; `renew`: the end-to-end test, `TestEveryRenewalPresentsTheCredentialAgainWithoutAPerson`, `TestARevokedCredentialEndsRenewalAtTheStore`, `TestIssuerDownFailsTheTokenAndSubstitutionHasNoUpstream` | all passed; `catalogue.json`: the allowed request forwarded under its correlation id with allowed guard and policy events (the test asserts the store's token replaced the participant's, same privilege); `missing proof` 401 `TOK-PROOF-INVALID`, `proof signed by the wrong key` 401 `TOK-JKT-MISMATCH`, `replayed proof` 401 `TOK-REPLAY`, `expired token` 401 `TOK-EXPIRED`, each with the guard's denied event under the caller's correlation id; `vp-e2e.txt`: renewal by a fresh presentation for a new challenge, new token issued, previous retired, protected call 200 | passed |
| ZT-76 Credential Based Access | `participant`: `TestTokenPathEndToEnd` (roles `report-reader` and `report-viewer` mapped by the connector into JWTs with `report:read` / `report:summary`, answered `RESOURCE_REPORT_RETURNED` / `RESOURCE_SUMMARY_RETURNED`); `authelia`: `TestVP_UnmappedClaimsAreDenied`; `renew`: the end-to-end test and `TestARevokedCredentialEndsRenewalAtTheStore` | all passed; `vp-e2e.txt`: a real SD-JWT credential verified, exchanged, protected call 200; the revoked credential refused (`CRED-REVOKED`, nothing consumed) | passed |
| ZT-06 Attribute/Credential Based Access Control | `server`: `TestGuardWithRealConnectorStorePolicyPostgresAndOpenBao` | `catalogue.json`: the participant whose outcome carries role `viewer` allowed by rule `m3-report-summary` (guard and policy allowed events, one correlation id, forwarded); the participant whose role maps to `other:read` refused 403 `POL-RULE-DENY`, rule `m3-scope-required`, with the guard's and the policy's denied events under its correlation id | passed |

## Limits

- Not a cluster run: the mode is `cluster` because the proof needs live services, but the target is local
  Docker. No mesh: the tests set the `X-Forwarded-Client-Cert` header a sidecar would set. The live
  counterparts are the [guard catalogue on kind](../guard-catalogue-kind-2026-11-22-r2/README.md) and the
  [guard bypass on zone B](../guard-bypass-zone-b-2026-11-22/README.md); neither was rerun here.
- The role-carrying outcomes of ZT-06, ZT-22 and of the two roles of ZT-76 are IF-03 fixture outcomes signed
  by a run key, not issued by the verification service; the real SD-JWT presentation, its verification and
  its revocation are the end-to-end test, with one role.
- The policy of ZT-06 is the policy evaluator's built-in rules, not Rego in the TSA (that is the
  [TSA policy proof](../tsa-policy/README.md), kind, evaluator only).
- DCR here is the real connector's registration endpoint called with a registrar token; DCR over SPIRE mTLS
  on a zone is the [read-only zone B record](../dcr-mtls-zone-b-2026-11-22/README.md).

## Left pending

| Row | Missing |
|---|---|
| ZT-20 Guarding Functionality | implemented separately on kind through the TSA Rego bundle over REST and gRPC: [record](../bdd-guarding-2026-11-23/README.md) |
| ZT-73 Authorized Upstreaming | implemented separately on zone B through the mesh-protected guarded path: [record](../bdd-upstreaming-2026-11-23/README.md) |
| ZT-74 Participant Backend Mock | the Participant publishes no registration, request or status events to the visualization feed |
| ZT-75 Protected Resource Mock | role-appropriate responses exist (`TestTokenModeScopeTable`, `TestTokenPathEndToEnd`) but the resource's answers are not published to the feed and no run shows them visualized |
| ZT-07 API Dock, ZT-77 Mock Replaceable | implemented separately: [API dock record](../bdd-api-dock-2026-11-23/README.md) (ZT-77 counts only with the live call) |
| TDR-BDD-05 | implemented separately on local services: [Keycloak record](../bdd-keycloak-2026-11-23/README.md) |
