# Identity policy set reviewed against the interface contracts

Review of 2026-11-22. It covers every mesh allow rule (Istio `AuthorizationPolicy`) the repository
renders for a zone, the rules running on zone A and zone B that day, and the rules of the three
M3 tracks not yet merged into the close-out. For each declared pair it names the contract that
gives the reason for the call and the evidence that the pair works and that callers outside it are
refused. It extends the table
[Pairs and the interface contracts](../../architecture.md#pairs-and-the-interface-contracts), which
predates the guard, feed bridge, TSA, connector and token store charts.

## Sources

| Source | Revision |
|---|---|
| Umbrella `deployment/helm/ztd` (allow matrix, `intraPlanePairs` empty), `zone-policy` and `ztd-openbao` rendered by `scripts/install-zone` for `zones/zone-a.yaml`, `zones/zone-b.yaml` and `ci/values.yaml`; `ztd-guard` for zone A (`guard.install`) | close-out `b24fbd12` |
| `guard`, `feed-bridge`, `tsa-policy`, `connector`, `token-store` rendered with their `ci/values.yaml` | close-out `b24fbd12` |
| `connector-gateway` (Connector routing) | `feat/m3-routing` at `dce608b5`, not merged |
| `verification-service` (presentation verification) | `feat/m3-vp` at `75ca18e8`, not merged |
| `tenant` and the guard's tenant mode | `feat/m3-tenants` at `e03f3fa6`, not merged; review again after the merge |
| Live rules, read only with `kubectl get` | zone A (`istio-system`, `ztd-data`, `ztd-mgmt`, `tenant-a`, `tenant-b`), zone B (`istio-system`, `ztd-data`, `ztd-mgmt`, `ztd-m3-b`), 02:30-02:45 UTC |

Every zone runs the mesh-wide `istio-system/default-deny` (an ALLOW policy with no rules) and a
mesh-wide `PeerAuthentication` `STRICT`; each component chart adds its own `STRICT` policy. A pair
exists only through an allow rule naming the caller's SPIFFE ID
(`spiffe://<trust domain>/ns/<namespace>/sa/<account>`), except where the table says otherwise.

## Pairs

"Kind" is a disposable kind cluster, "zone A" / "zone B" the participant clusters. A finding
number points to [Findings](#findings).

| # | Pair (caller → callee, port, operations) | Declared by | Contract reason | Evidence |
|---|---|---|---|---|
| 1 | `ztd-data/pdp-adapter` → `tsa-policy-engine` (all ports) | allow matrix `pdp-adapter-to-tsa` | IF-05 policy decision | ZT-55 plane-separation runs, zone A and zone B, 10 Nov (39 pass, 0 fail each; records delivered with the milestone, outside the repository). Caller account not created by any chart: F3 |
| 2 | `ztd-data/atls-gateway` → `cmcd` | allow matrix `atls-gateway-to-cmcd` | IF-07 attested channel (v0, not frozen) | same plane-separation runs; component not deployed |
| 3 | `ztd-data/atls-gateway` → `tcr` | allow matrix `atls-gateway-to-tcr` | IF-07 (trust-list resolve) | same; component not deployed |
| 4 | every identity of `ztd-data` → `otel-collector` 4317, 4318 | allow matrix `workloads-to-otel-collector` | IF-04 observability export, declared ZT-26 bypass | same plane-separation runs |
| 5 | `ztd-data/backend` → `verification-service` (all ports) | allow matrix `backend-to-verification-service` | IF-03 (`verification.v1`) | same plane-separation runs. The verification service's real caller is the token store's presentation hook: F3 |
| 6 | `ztd-data/ztd-connector` → OpenBao 8200 | allow matrix `connector-to-openbao` | no IF: the secret-store lane of the connector's signing key and Kubernetes-auth login ([Secrets](../../secrets.md#kubernetes-auth), ADR-0004) | [T6 kind](../m3-t6-openbao-kubernetes-auth/README.md). Zone B runs an older zone-policy without this row: F4 |
| 7 | `ztd-data/ztd-token-store` → OpenBao 8200 | allow matrix `token-store-to-openbao` | as 6 (store's key custody and login) | as 6 |
| 8 | `ztd-mgmt/ztd-openbao-bootstrap` → OpenBao server 8200 | `ztd-openbao` own pair | none: internal to the release ([Secrets](../../secrets.md#bootstrap)) | rendered on all three meshed zone files, live on zone B |
| 9 | `ztd-mgmt/ztd-verify-openbao` → OpenBao server 8200 | `ztd-openbao` own pair | none: internal (verification job) | as 8 |
| 10 | `ztd-participant` → `ztd-guard` 8080 `POST /demo` | guard chart `ztd-guard-caller` | IF-02 (a DPoP-bound access token presented at the zone's guarded entry); ZT-06/ZT-18 | zone B [guarded call](../guard-bypass-zone-b-2026-11-22/README.md); zone A [second instance](../guard-zone-a-2026-11-22/README.md); kind [catalogue](../guard-catalogue-kind-2026-11-22-r2/README.md) |
| 11 | `ztd-guard` → `ztd-policy-evaluator` 8080 `POST /decision` | guard chart `ztd-policy-evaluator-caller` | IF-05 input and decision | same three records |
| 12 | `ztd-guard` → `ztd-protected-resource` 8080 `POST /demo` | guard chart `ztd-protected-resource-caller` | IF-05 header propagation (an allowed request forwarded with `x-request-id`) | zone B guarded call, resource record under the guard's correlation id |
| 13 | `ztd-ui/ztd-ui` → `ztd-feed-bridge` 8090 `GET /snapshot`, `/events`, `/v2/snapshot`, `/v2/events` | feed-bridge chart `ztd-feed-bridge-callers` | IF-01 feed v1 and v2 | kind catalogue r2: UI read both versions |
| 14 | `ztd-guard` → `ztd-feed-bridge` 8090 `POST /ingest` | same policy, second rule | IF-01 v2 ingest | kind catalogue r2: producer posted |
| 15 | the listed IF-05 adapters (`callers`; empty by default, CI: `ztd-guard/ztd-policy-evaluator`) → `tsa-policy-engine` 8080 `POST /policy/policies/facis/guard/1.0/evaluation` | tsa-policy chart `tsa-policy-engine-caller` | IF-05 through the TSA adapter | [TSA policy, kind](../tsa-policy/README.md). Overlaps row 1: F3 |
| 16 | `ztd-participant` → `ztd-connector` 8080 `/oauth2/*`, `/.well-known/jwks.json` | zone B only, `ztd-connector-identities` (created by hand): F1 | IF-02 challenge, token, registration | [DCR over SPIRE mTLS, zone B](../dcr-mtls-zone-b-2026-11-22/README.md) |
| 17 | `ztd-token-store` → `ztd-connector`, same operations | as 16 | IF-02 token (acquisition and renewal of upstream tokens) | as 16: 1 410 mTLS requests from this identity |
| 18 | `ztd-guard`, `ztd-protected-resource` → `ztd-connector`, same operations | as 16 | IF-02 key set only (`/.well-known/jwks.json`); `/oauth2/*` is wider than the contract needs: F2 | as 16 |
| 19 | `ztd-guard` → `ztd-token-store` 8080 `/internal/substitute`, `/internal/replay-check` | zone B only, `ztd-token-store-identities` (by hand): F1 | token store API (`token-store.v1`) | zone B guarded call: the resource saw the token store's substituted upstream token |
| 20 | `ztd-connector`, `ztd-connector-schema`, `ztd-token-store`, `ztd-token-store-schema` → `ztd-postgres` 5432 | zone B only, `ztd-postgres-identities` (by hand): F1 | no IF: the store's database ([Token store](../../token-store.md#one-database-two-owners)) | zone B services ready and serving (rows 16-19) |
| 21 | `ztd-edge` → `ztd-participant` 8080 `/*` | zone B only, `ztd-participant-identities` (by hand): F1 | ZT-26 ingress through the Connector's entry | zone B guarded call through the public entry; routing records on `feat/m3-routing` |
| 22 | outside → `ztd-edge` 8443 (no principal: the caller is outside the mesh) | `ztd-edge` release (`connector-gateway`, ingress role) `ztd-edge-public` | ZT-26 declared public entry | routing records on `feat/m3-routing` (zone B entry adoption, 42 of 42 calls served) |
| 23 | `ztd-data/backend` → `ztd-connector-gateway` 8080 (egress role) | connector-gateway chart `ztd-connector-gateway-callers`, live on zone A | ZT-26 egress to the peer zone's entry | routing records on `feat/m3-routing` (zone A, 12/12) |
| 24 | `tenant-<t>/*` (any account of the tenant's namespace) → `tenant-data` 8080 | tenant chart `tenant-data-members`, live on zone A | ZT-53 tenant isolation; no IF | tenant records on `feat/m3-tenants` (kind 28 checks, zone A 21 checks, both PASS). Namespace-wide membership: F5 |

Rows 1-9 render identically for zone A, zone B and the CI zone; the guard rows 10-12 render for
zone A from its zone file and run on zone B from the guard chart (`ztd-m3-b`). No rule renders
`notPrincipals`, a DENY or a CUSTOM action.

## Unaffiliated mesh calls are refused

| Case | Where | Record |
|---|---|---|
| A meshed caller under the Participant's account calls the protected resource directly: `403 RBAC: access denied`; the resource's sidecar logs the denial with both SPIFFE IDs and its `rbac.denied` counter goes 0 → 1; nothing reaches the application | zone B | [guard bypass](../guard-bypass-zone-b-2026-11-22/README.md) |
| A pod without the mesh in a plane namespace is refused at admission (`proxy-takes-spire-socket`) | zone B | same |
| A meshed caller under another account calls the guard: `403 RBAC: access denied` | zone A | [second guard instance](../guard-zone-a-2026-11-22/README.md) |
| The Participant's identity reading the feed and another identity posting to `/ingest`: `403` from the bridge's sidecar | kind | [catalogue r2](../guard-catalogue-kind-2026-11-22-r2/README.md) |
| An impostor with a lane's pod labels under its own account, and a registered neighbour without a pair: refused by the destination's proxy, one log line with both SPIFFE IDs | kind, zone A, zone B | `mesh-default-deny` check of `scripts/verify-mesh-identity/verify.sh` ([what a run shows](../../workload-identity.md#what-a-run-of-the-proof-shows)) |
| Every data → management and management → data attempt outside the matrix, refused at the network layer (Hubble policy drop) and the mesh layer | zone A, zone B | ZT-55 plane-separation runs (`scripts/verify-plane-separation/verify.sh`), 10 Nov |
| Cross-tenant data, secret store and policy access, both directions | kind, zone A | tenant records on `feat/m3-tenants` |

## No policy names an address

| Check | Result |
|---|---|
| `scripts/ci/check-policy-addresses.sh` (every shipped zone file and the CI zone file) | PASS: zone A 57 policies (ztd, zone-policy, ztd-openbao, ztd-guard), zone B 51, CI 52, IONOS 4 (no mesh); no address |
| `scripts/ci/check-policy-l7-owner.sh` | PASS: every allow-matrix policy names its L7 owner, no Cilium L7 rule |
| The same address scan (`--manifest`) over the component charts the CI check does not render (`guard`, `feed-bridge`, `tsa-policy`, `connector`, `token-store`, `connector-gateway` egress and ingress, `tenant`, `verification-service`) | only the connector gateway's two lanes outside the mesh: the egress role's `toCIDR` to the peer entry and the ingress role's `ipBlock` for the entry's source ranges; both declared in the routing track (the peer entry holds no identity in this mesh, as the telemetry export's lane) |
| The same scan over the live policies (zone A 55 objects, zone B 61) | zone A: the gateway's peer lane (`ztd-connector-gateway-peer`, the zone B entry's address, masked here); zone B: the public entry `ztd-edge-entry` (`0.0.0.0/0` to 8443). No address in any mesh rule |

The address scan of the component charts is not in CI: F6.

## Findings

Reported, not fixed in this record.

- **F1 — Zone B's connector, token store, database and Participant rules are not in the
  repository.** `ztd-connector-identities`, `ztd-token-store-identities`, `ztd-postgres-identities`
  and `ztd-participant-identities` in `ztd-m3-b` were applied by hand (no Helm owner). The connector
  and token-store charts render a `STRICT` PeerAuthentication and no AuthorizationPolicy, so a zone
  installed from the repository under the mesh default deny admits no caller to either (fail
  closed), and the pairs 16-21 have no declaration to review in the repository.
- **F2 — The connector rule is wider than IF-02 needs.** The guard and the protected resource only
  fetch the key set, but the rule admits them to `/oauth2/*`, which includes `/oauth2/register`.
  Registration is still held by the registrar token; the mesh layer does not narrow it.
- **F3 — Three matrix rows name accounts no chart creates, and the real callers have no row.**
  `pdp-adapter` (row 1): the deployed IF-05 caller is `ztd-policy-evaluator`, admitted by the
  tsa-policy chart's own rule (row 15), whose `callers` list is empty by default and whose CI value
  names a namespace (`ztd-guard`) the guard chart does not use on the zones. `backend` (row 5): on
  `feat/m3-vp` the verification service is called by the token store's presentation hook, and its
  chart renders only a PeerAuthentication and a DestinationRule, so in a meshed zone the call
  `ztd-token-store` → `verification-service` is refused by the default deny until a pair names it.
  `atls-gateway` (rows 2, 3) belongs to IF-07, not frozen. The architecture table's notes "connector
  → token store: not yet declared" and "guard → gateway: not yet declared" are also out of date.
- **F4 — Zone B runs a zone-policy without the T6 OpenBao rows.** The lanes are held by
  `ztd-mgmt/ztd-m3-b-to-openbao` (connector and token store accounts of `ztd-m3-b`, 8200), approved
  on 2 Nov; rows 6 and 7 are not yet live on either zone.
- **F5 — Tenant membership is namespace-wide.** `tenant-data-members` admits `ns/<tenant>/sa/*`, so
  any account created in a tenant's namespace is a member. It holds the isolation between tenants;
  whether it is the intended membership is for the tenant track's merge review.
- **F6 — CI checks addresses only in the umbrella, zone-policy, ztd-openbao and (zone A) guard
  renders.** The other component charts were scanned by hand here.

## Reproduce

```bash
helm dependency build deployment/helm/ztd
bash scripts/ci/check-policy-addresses.sh            # bash 4 or later (mapfile)
bash scripts/ci/check-policy-l7-owner.sh
helm template guard deployment/helm/guard -n ztd-data -f deployment/helm/guard/ci/values.yaml > guard.yaml   # same for each chart
bash scripts/ci/check-policy-addresses.sh --manifest components guard.yaml ...
kubectl get authorizationpolicies.security.istio.io,peerauthentications.security.istio.io -A
```

## Follow-up on the close-out branch

The findings as the branch now stands; nothing here was re-run on a zone.

- **F1**: the charts declare the callers. The connector chart's `callers` render
  `ztd-connector-callers`, the token store's `runtime.callers` render `ztd-token-store-callers`
  (the guard, `POST /internal/substitute` and `/internal/replay-check`), its `database.mesh` renders
  `ztd-token-store-database` (the store's two accounts and the listed callers, the connector, on the
  database port), and the application-service chart's `callers` render `<name>-callers` (the
  Participant's entry). Empty lists render nothing, so a zone that sets none stays closed. Zone B's
  hand-applied rules are unchanged until its releases are upgraded with these values; the
  `ztd-connector-schema` account of zone B is created by no chart and is not declared.
- **F2**: `callers.keySet` (the guard, the protected resource) reaches `GET /.well-known/jwks.json`
  only; `callers.oauth` (the Participant, the token store) `/oauth2/*` and the key set.
- **F3**: `pdp-adapter-to-tsa` admits `ztd-policy-evaluator` (the guard chart's PDP adapter);
  `backend-to-verification-service` is `token-store-to-verification-service` (the token store's
  presentation hook, port 8080). The two `atls-gateway` rows stay as reserved lanes: they hold the
  ZT-55 roles Attestation and TRAIN (resolution) in the plane-separation design, and IF-07 is not
  frozen. The architecture's interface table no longer says "not yet declared" for the pairs the
  charts now declare.
- **F4**: live, unchanged.
- **F5**: `tenant-data-members` admits the tenant chart's `members` (default `ztd-participant`); the
  tenant's guard reaches its data service through the guard chart's own `tenant-data-caller`.
- **F6**: `scripts/ci/check-policy-addresses.sh` also renders and scans every other chart with its
  `ci/values.yaml` and each `ci/<variant>-values.yaml`.
