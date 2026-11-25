# Connector registration endpoint over SPIRE mTLS on zone B

Read on zone B (context `zerotrust-b`, namespace `ztd-m3-b`) on 2026-11-22 between 02:31 and
02:40 UTC, read only: `kubectl get`, `kubectl logs`, the sidecar's admin endpoint through
`pilot-agent request GET` and `SELECT`s through `psql`. Nothing on the cluster was created, changed
or deleted. `environment.json` names the pods, images and commit.

## What the records show

| Check | Result | Record |
|---|---|---|
| The callers' and the connector's sidecar certificates are SPIRE-issued | The connector, Participant, token store and guard each hold one leaf whose URI SAN is `spiffe://zone-b.trust.invalid/ns/ztd-m3-b/sa/<own account>`, issued by `O=FACIS ZTD, CN=zone-b.trust.invalid` (authority key id `36:B4:E2:8B:…`, the SPIRE CA with serial `7F5E0237…`), lifetime 4 h; `openssl verify` against the bundle SPIRE publishes (`spire-system/spire-bundle`) answers `OK` for all four | `svids.txt`, `spire-bundle-x509.txt` |
| The connector's proxy trusts only that bundle | The inbound validation context `ROOTCA` is Envoy's SPIFFE validator for the one trust domain `zone-b.trust.invalid`, holding exactly the four CA certificates of the SPIRE bundle (same serials) | `inbound-listener.json` |
| No plaintext path to the registration endpoint | Every inbound filter chain that serves traffic, including the one for port 8080 (`/oauth2/register`, `/oauth2/token`, `/oauth2/challenge`, `/.well-known/jwks.json`), is TLS with `require_client_certificate: true`; the only other chain is the capture port's loop guard (15006). PeerAuthentication `STRICT` mesh-wide (`istio-system/default`), for the namespace (`ztd-namespace-strict`) and for the connector (`ztd-connector`) | `inbound-listener.json`, `policies.yaml` |
| The policy names the callers | Under the mesh-wide `default-deny` (an ALLOW policy with no rules), `ztd-connector-identities` admits on port 8080, paths `/oauth2/*` and `/.well-known/jwks.json`, only the principals of `ztd-participant`, `ztd-token-store`, `ztd-guard` and `ztd-protected-resource` | `policies.yaml` |
| Traffic actually received | Since the pod started, 1 509 requests at the connector's proxy, every one `connection_security_policy="mutual_tls"` with one of those four SPIFFE IDs as source principal; RBAC allowed 1 522 (the counter was read a minute later), denied 0 | `inbound-stats.txt` |
| What the application served | Since 00:00 UTC: `POST /oauth2/challenge` 125, `POST /oauth2/token` 125 × 200 and 125 × 400 (the record carries no reason), `GET /.well-known/jwks.json` 34, probes; no `POST /oauth2/register` in that window | `connector-requests.txt` |
| Registration succeeds and a request outside the registrar's grant is refused with a specific error | Local, not on the zone: the conformance suite over real HTTP (`TestRegistration_*`, `TestInterface_Registration*`, `TestRegistrationAudienceCeiling`, `TestExclusiveAudienceRegistration`) and the connector binary against PostgreSQL and OpenBao in Docker (`TestServeBootstrapsTheRegistrarAndIssuesVerifiableTokens`: the registrar registers a client, which obtains a token the resource-side verifier accepts). Refusals: no or forged token 401 `invalid_token` with Bearer and DPoP challenges, a token without the registration scope 403 `insufficient_scope`, metadata beyond the registrar (a wider scope, the registration scope itself, an unoffered grant type) 400 `registration_rejected`. All PASS | `go-test-registration.txt` |

## Limits

- **No registration was made on the zone, and none is on record there.** The zone's clients
  (`ztd-participant`, `ztd-store`, `ztd-registrar`) were created at install on 27 Oct, the two
  verified-presentation clients 26 and 27 s before the registrar, so they were seeded and not registered
  through `/oauth2/register`; the zone's databases hold no `registration.*` audit row
  (`oauth2-clients.txt`). A live registration is a write and was not made under this read-only
  record.
- **The registration policy gate and its audit are not on the close-out base.** The gate in front
  of the library (rules `dcr.*`, reason `registration_rejected` with the broken rule named), the
  `registration.accepted` / `registration.refused` audit rows and the IF-01 `token_event` come
  with PR #41 (`ab0b4b4e`), which the close-out base does not contain. The refusals shown above are
  the library's own, behind the registrar token.
- **The callers' policy is not from the repository.** `ztd-connector-identities` was created on
  zone B with `kubectl create` on 2 Nov (`managedBy: kubectl-create`); the connector chart renders
  the PeerAuthentication but no AuthorizationPolicy. It admits `ztd-guard` and
  `ztd-protected-resource` to `/oauth2/*` although under IF-02 they need only the key set. Both
  points are in the [contract review](../m3-contract-review/README.md#findings).
- **No unaffiliated caller was tried against the connector here.** The receiver-side denial of a
  meshed caller outside the policy is shown on the same namespace for the protected resource
  ([guard bypass proof](../guard-bypass-zone-b-2026-11-22/README.md)); the connector's `rbac.denied`
  counter is 0 because no such call reached it.
- The trust domain is still the placeholder `zone-b.trust.invalid`; the record is read again once
  the zones are named.
