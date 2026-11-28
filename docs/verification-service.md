# Verification service

The verification service is the other end of the token store's
[presentation hook](token-store.md#presentation-hook): it implements the two endpoints of the
[verification contract](contracts/verification.v1.openapi.yaml) and turns one connector challenge
into one signed IF-03 outcome, which the connector's verified-presentation grant consumes. The code
is `services/verification-service`, the image `deployment/docker/verification-service`, the chart
`deployment/helm/verification-service`.

```
token store (hook)                     verification service                         zone B connector
POST /v1/requests {challenge,…}  ──▶  row in PostgreSQL (challenge UNIQUE)
holder builds the presentation
POST /v1/responses/{id} vp_token ──▶  row consumed, presentation judged
                                       (internal/presentation), outcome signed in
                                 ◀──  OpenBao transit
grant with the outcome  ───────────────────────────────────────────────────────▶  if03.Verify, token
```

## What it reuses and what it adds

The judgement is #52's and is not changed: `internal/presentation` (issuer trust, issuer
signature, envelope, disclosures, holder binding, validity, status reference), `internal/sdjwt`,
`internal/statuslist` and `internal/oid4vp`. The client contract and the hook are #60's
(`internal/verificationclient`). The service adds what a deployment needs around them:

| Concern | How |
|---|---|
| Single use | One PostgreSQL table, `verification_request`. A request is consumed by one `UPDATE … WHERE consumed_at IS NULL AND expires_at > now AND caller = $caller` before the presentation is judged, so of any number of concurrent answers one is judged. `challenge` is `UNIQUE`: a connector challenge opens one request, ever, across restarts and replicas. Rows are deleted 24 h after they expire. |
| Outcome custody | The outcome key is a transit key (`--signing-key`, created non-exportable as `ecdsa-p256` if missing), the key-custody pattern of the token store and the connector (#45). The service pins the version current at start; its `kid` is `<key>-v<version>`. Only the public key ever enters the process. |
| Consumers' trust | `verification-service trust-set` prints `{"<issuer>": {"keys": [<JWK>]}}`, the format of the connector's `--vp-trusted-issuers-file` and the store's `trusted_issuers`. |
| Trust in credential issuers | The issuers and their keys come from a file (`--issuer-keys-file`, the same trust-set format); an issuer is trusted only while the trust source lists it. The set is rebuilt every `--trust-refresh` (5 min), asking the trust source again each time. It fails closed: an issuer whose listing cannot be read is dropped, and a keys file that cannot be read or parsed (or is empty) withdraws every issuer and makes the service not ready until a refresh succeeds. |
| Trust source | **TRAIN:** `--tcr-url` and `--trust-scheme-pointers`. The TCR's `POST /tcr/v1/resolve` ([TSPA page, §4](tspa-publish-api.md)) is used only for what it alone does: walking the DNS chain from the pointers to the trust-list issuers' DIDs and their VC locations (`vcUri`). Its `vcVerified` is not relied on, since it never checks the VC's `expirationDate`. The service fetches each VC itself and checks it ([Trust-list VC check](#trust-list-vc-check)); the issuer is trusted when a list so verified holds an active service whose `ServiceTypeIdentifier` is the issuer. **FIXTURE:** `--trust-list-file`, a trust list in the JSON form TSPA serves, read from a file and matched the same way. It checks no signature, no hash and no DNS, the service logs a warning at start, and it exists only where no TCR is reachable. Exactly one of the two is accepted. |
| Caller identity | Every request must carry exactly one `X-Forwarded-Client-Cert` element whose `URI` is one of `--callers` (`internal/meshcaller`, the guard's authenticator); anything else is 403. A request is answered only by the identity that opened it. |
| Readiness | `/readyz` on the ops port is 200 while PostgreSQL answers and at least one issuer is trusted. |

## Trust-list VC check

For each VC location the TCR resolves, in this order, failing closed at every step
(`internal/trustlist/trustlist.go`):

1. The VC's `@context` is exactly the three pinned documents (W3C credentials v1, Ed25519 2020,
   JWS 2020; embedded in `contexts/`, fetched once on 2026-11-21, never loaded from the network) and
   the trust-list terms our TSPA's template defines. JSON-LD runs in safe mode: no term is silently
   dropped from what the proof covers.
2. Its `issuer` is the DID the TCR resolved, a `did:web`.
3. Its validity window: `expirationDate` or `validUntil` required and not passed, `issuanceDate` or
   `validFrom` not in the future.
4. The `JsonWebSignature2020` proof (EdDSA, a detached unencoded JWS over the SHA-256 of the URDNA2015
   canonical proof options and document) verifies with the Ed25519 key that the issuer's DID document
   (did:web, fetched over HTTPS) names as the proof's `verificationMethod` and lists under
   `assertionMethod`.
5. The trust list at `credentialSubject.trustlistURI` has the multihash `credentialSubject.hash`.

A verified VC is cached by the SHA-256 of its bytes for at most 5 minutes and never past its expiry.
Canonicalisation uses `github.com/piprate/json-gold` (Apache-2.0, pending Eclipse IP review,
[Dependencies](dependencies.md)). The check runs against a VC signed by our patched TSPA image
(`testdata/tspa/`, produced by `scripts/verify-tspa-vc/run.sh`) and against VCs signed in the tests
to cover each refusal: expired, no validity end, not yet valid, expiry or subject changed after
signing, bad proof, unpinned or changed context, DID document naming another key, issuer not the
resolved DID, and the VC, DID document, list or TCR not answering.

The upstream TSPA cannot produce a VC that passes: it never sets `expirationDate` and signs with a
key published in its own source. Only our image does ([TSPA page, §11](tspa-publish-api.md)).
**Trust lists published by the upstream TSPA image, on zone B before this change included, were
signed with that public key and must not be trusted.**

## Refusals

Every failure is told apart: by the signed outcome's status and IF-03 reason code where the
contract defines one, and by the `detail` the service records (table column and log record)
where two failures share a code. The caller sees only the contract's answer.

| Case | Answer | Outcome status / reason | Recorded detail |
|---|---|---|---|
| Issuer not trusted (no keys, or not listed by the trust source) | 200 | `failed` / `CRED-ISSUER-UNTRUSTED` | — |
| Credential revoked (status list entry set) | 200 | `revoked` / `CRED-REVOKED` | — |
| Status list unreadable | 200 | `failed` / `CRED-STATUS-UNAVAILABLE` | — |
| Key binding not by the credential's holder key | 200 | `failed` / `CRED-INVALID` | `holder-binding` |
| Credential expired | 200 | `failed` / `CRED-INVALID` | `credential-expired` |
| Not an SD-JWT VC presentation | 200 | `failed` / `CRED-INVALID` | `malformed-presentation` |
| Issuer signature, disclosure, type, missing role or status reference | 200 | `failed` / `CRED-INVALID` | `issuer-signature`, `disclosure`, `credential-type`, `credential-claims` |
| Form or `vp_token` malformed | 400 `CRED-REQUEST-INVALID` | none (request consumed) | `malformed-form`, `malformed-vp-token` |
| Request answered before | 404 `CRED-REQUEST-UNKNOWN` | none | `replayed` |
| Request unknown, expired, or opened by another caller | 404 `CRED-REQUEST-UNKNOWN` | none | `unknown`, `expired`, `other-caller` |
| Request expired while its answer waited on the row | 404 `CRED-REQUEST-UNKNOWN` | none (request consumed; expiry re-checked with a fresh clock, which is also the time judged with) | `expired` |
| Challenge offered a second time | 400 `CRED-REQUEST-INVALID` | none | `challenge-replayed` |
| Request body malformed or expiry out of bounds | 400 `CRED-REQUEST-INVALID` | none | `malformed-request` |
| No, another or more than one forwarded identity | 403 | none | log record `caller refused` |

A revoked credential is seen once the status list the service holds expires: its `ttl`, never more
than 60 s (`internal/statuslist`).

## Mesh identity, both ways

The contract leaves authentication to the deployment and the hook delegates it to the mesh; the
chart declares both directions:

- **Inbound:** a `PeerAuthentication` in `STRICT` mode for the service's pods, so only mesh mutual
  TLS reaches the API port, and the service's own check of the forwarded identity above. The
  forwarded header is trustworthy only where the sidecar replaces any value a client sent
  (`SANITIZE_SET`). **Required integration:** the zone-policy EnvoyFilter `xfcc-sanitize-set` of
  the integrated M3 base (`feat/m3-closeout`,
  `deployment/helm/zone-policy/templates/envoyfilter-xfcc-sanitize.yaml`), which sets it on every
  inbound sidecar. This branch's base does not have it: the caller check is valid only in a zone
  where that filter is installed, and must not be relied on anywhere else. The service also refuses
  two elements, what Istio's default `APPEND_FORWARD` would produce from a forged client value.
- **Outbound, at the caller:** a `DestinationRule` for the service's host with `ISTIO_MUTUAL` and
  `subjectAltNames: [spiffe://<trust domain>/ns/<namespace>/sa/verification-service]`, so the token
  store's proxy refuses any server certificate but this service's.
- **Identity matrix:** the service runs in the management plane as ServiceAccount
  `verification-service` with the label `app.kubernetes.io/name: verification-service`, the
  destination of the existing `backend-to-verification-service` lane. The token store, also in the
  management plane, is a same-plane caller; its pair goes into the umbrella's `intraPlanePairs` on
  the integrated base:

  ```yaml
  - name: token-store-to-verification-service
    from: { plane: management, podSelector: { app.kubernetes.io/name: ztd-token-store }, serviceAccount: ztd-token-store }
    to: { plane: management, podSelector: { app.kubernetes.io/name: verification-service }, ports: [{ port: 8080, protocol: TCP }] }
  ```

  Egress the service needs: PostgreSQL and OpenBao in its namespace, the TCR (management plane),
  and the status-list hosts named by `--status-prefixes`, which are outside the zone and need a
  declared egress rule per host.

## Configuration

`verification-service serve` takes every flag also as `VERIFICATION_SERVICE_<NAME>`; the chart sets
them from its values (`deployment/helm/verification-service/values.yaml`). Required: `--public-url`,
`--database-url`, `--openbao-url`, `--openbao-token-file`, `--signing-key`, `--issuer`,
`--callers`, `--issuer-keys-file`, `--accepted-vct`, `--status-prefixes`, and one trust source.
The database role needs `CREATE` on its schema: the service creates its one table at start.

## Verification

| What | Command | Real | Fixture |
|---|---|---|---|
| Handlers, refusals, single use under concurrency, callers | `go test ./services/verification-service/...` with `TOKEN_STORE_TEST_DATABASE_URL` | PostgreSQL | issuer, holder and status list generated per test (`verificationtest.Provision`); pinned trust list; outcomes signed with a process key |
| Trust sources | same package | json-gold, Ed25519, a VC signed by our TSPA image | TCR, DID document, VC and list served by a TLS test server; refusal VCs signed by the tests |
| End to end | `go test -run TestEndToEnd ./services/token-store/internal/renew/` with the database and `TRANSIT_TEST_*` variables; `VP_E2E_RECORD=<file>` keeps the transcript | the service binary, PostgreSQL, OpenBao transit, the token store's acquisition and renewal worker, the connector binary, a protected resource with `internal/tokenverify` | per-run issuer and holder, pinned trust list, status list from a test server; the mesh: the hook's transport sets the forwarded identity |
| Chart on kind | `scripts/verify-verification-service/verify.sh` | the image by digest, PostgreSQL and OpenBao in the cluster, readiness, `trust-set`, caller refusals, single use, PostgreSQL loss | no mesh (Istio CRDs inert); the script sets the forwarded identity through the pod proxy |

The recorded run is in [evidences/verified-presentation](evidences/verified-presentation/local-2026-11-21.md).

## Not yet shown

- A run under a live mesh: the DestinationRule refusing a wrong server certificate and the
  `STRICT` PeerAuthentication refusing plain text are Istio's, rendered and applied here but
  exercised only on a cluster with istiod and SPIRE.
- A run against a live TCR and our TSPA on zone B: it needs our TSPA image deployed there, its
  DID document served at `https://tspa.facis.cloud/.well-known/did.json`, and the trust list
  re-published with it.
- Rotation of the outcome key: the service pins the version at start, so a rotation needs a
  restart and the consumers' trust sets must carry the new key first.
