# Publishing to TRAIN: the TSPA trust-list API

*Established by the TSPA API verification for ZT-35 (gate G4), 2026-09-16/18. Re-confirmation against the client's instance is
pending (it depends on the client's XFSC stack).*

Source of truth: `eclipse-xfsc/train-trust-framework-manager` on GitHub, commit `ecd5fdc` (2025-05-25), which was
the `main` HEAD on 2026-09-16 and still is on 2026-09-19; the repository is not archived but has had no commit on
`main` since then. The original GitLab project `eclipse/xfsc/train/tspa` is archived and read-only (last activity
May 2025) but still readable, so the "404 against the wrong repository" mentioned in the verification brief did not come from it;
that earlier attempt is not characterised further here. Everything below was read from that commit plus
`eclipse-xfsc/train-shared` `6a0abe4` (the trust-list model) and, where marked, exercised against a local instance
built from those two commits.

## 1. Summary

**The publish API surface is confirmed and a measurement value round-trips locally** (§4–§7, §10). Three of the
four "done when" items are closed. What the artefact-chain design's open publication item still lacks is now named precisely:

1. **There is no field for the measurement.** TSPA's entry schema (`TSPSchema.json`) has no
   measurement/hash/TEEM attribute. The value can only ride in a free-form `Type`/`Value` pair. Until the project
   decides *which* pair, and the TCR/policy side agrees to read it, ZT-35's "upload the hash to TRAIN" is not
   implementable in a way the verifier can consume. Candidates, in order of how naturally they read:

   | Carrier | Path | For | Against |
   |---|---|---|---|
   | A | `TSPInformation.TSPCertificationList.TSPCertification[] {Type,Value}` | semantically "an attestation about the TSP"; used in the local round-trip as `TEEM-sha256` | list is typed as certifications (ISO, VAT) |
   | B | `TSPServices.TSPService[].ServiceDigitalIdentity.DigitalId.X509Certificate` | per-service, next to the DID the peer presents | field name says X509; only one slot per service |
   | C | `TSPInformation.TSPEntityIdentifierList.TSPEntityIdendifier[] {Type,Value}` | per-TSP identifiers | "identifier" is a stretch for a launch digest |
   | D | an extra key (schema has no `additionalProperties:false`) | clean name, e.g. `TEEM` | **ruled out by test (2026-09-18):** accepted with 201, then silently dropped on storage at all three levels tried (TSP root, `TSPInformation`, `TSPService`) — the entry is re-serialised from the shared Java model, which has no such fields |
   | (other) | any other free-text string of the entry (`ServiceDefinitionURI`, `ServicePolicySet`, `ServiceSchemaURI`, `ServiceSupplyPoint`, `TSPInformationURI`, …) | exists and survives storage | single-valued, named for something else; listed only for completeness — A–C are the structurally plausible ones |

   **Read-side constraint (verified in TCR source, `train-trust-validator` `ResolutionService.findIssuerProvider`,
   2026-09-18 — by code reading, see the scope note in §10):** the TCR selects the entry whose
   `TSPServices.TSPService[].ServiceTypeIdentifier` **equals the `issuer` string of the resolve/validate request**,
   and returns that whole entry as `trustList`. So:
   - the lookup key is `ServiceTypeIdentifier`, **not** `ServiceDigitalIdentity.DigitalId.DID` — the connector's
     identifier (whatever the peer presents, e.g. its DID) must be written into `ServiceTypeIdentifier`.
     Upstream convention agrees: every example trust list in the TSPA and TCR repos puts the issuer's DID there
     (`<ServiceTypeIdentifier>did:web:companyA.de</ServiceTypeIdentifier>`), despite the field's name;
     `DigitalId.DID` is informational. The round-trip payloads in `scripts/verify-tspa-api/payloads/` carry the connector's DID there
     (corrected 2026-09-18; the first run had `urn:facis:ztd:attested-tls`, which the TCR would never match);
   - any field of the entry is available to the connector after lookup, so carriers A–C are all reachable;
   - the TCR verifies the VC signature and the list hash (`vcVerified`) but **does not check the VC's
     `expirationDate`** (`DIDResolver.resolveVC` reads only `trustlistURI` and `hash`), so TSPA's static 2025
     expiry is harmless for the TCR path.

   The model is a reduced form of ETSI TS 119 612 (the EU trusted-list standard; TSPA's own
   `TrustList_DataModel_Design` cites it), and that standard defines exactly the place for framework-specific data —
   "TSP information extensions" and "Service information extensions", "to be interpreted according to the specific
   framework's rules" — but the TSPA/TCR implementation does not carry either. That leaves a third route next to
   A–C: implement the standard's extension elements in the shared model, TSPA and TCR, and contribute it upstream;
   cleaner, but development in another project.

   **Decision owner:** whoever owns the connector/attestation design (ZT-64/ZT-67 verifier side), not WP12.
   This document deliberately does not pick one. **The carrier used in the local round-trip
   (`TSPCertificationList`, `Type = TEEM-sha256`) is a test choice only, made so that a value could be written and
   read back; it is not a recommendation and the design decision remains open.**
2. **Client-side inputs still external** (the client's XFSC stack): TSPA base URL, framework name, OIDC issuer + a
   confidential client whose service account holds realm role `enrolltf`, Zone Manager reachability, and the
   TSPA version actually deployed.

Everything else in this document is the evidence behind those two statements.

## 2. What TSPA checks, and what it does not

Every acceptance TSPA performs is structural (JSON Schema, UUID uniqueness, URL/body UUID match). It does not
check that a write is meaningful for the read side, and its HTTP status does not reliably say what happened:

- a write **without a token** is answered `200` with an empty body, and nothing is written (§5);
- an entry whose `ServiceTypeIdentifier` holds anything other than the identifier the verifier will ask for is
  accepted, stored and signed, and **the TCR will never find it** (§1);
- the signed VC it emits carries an `expirationDate` already in the past (§8) and is still served as valid.

**Consequence for the WP12 pipeline step:** the HTTP status of the publish call is not a confirmation. After
every `PUT`/`PATCH` the pipeline must re-read `GET /{fw}/trust-list` and assert that the entry with the stable UUID
exists, that `ServiceTypeIdentifier` equals the connector's identifier, and that the measurement field carries the
value just deployed. Only that read-back is evidence of publication; see §7.1.

## 3. What TSPA is in the ZT-35 flow

ZT-35: each attested-TLS endpoint's CI/CD pipeline pre-generates its measurement (TEEM / launch digest)
and uploads it to TRAIN on deployment; the peer fetches the expected value from TRAIN (via the TCR) at
connection time. TSPA is the **write side** of TRAIN: it owns the trust framework, the trust list and the
signed Verifiable Credential (VC) that wraps the list. The TCR is the read side.

## 4. Endpoints (all under `http://<host>:16003/tspa-service/tspa/v1`)

The `tspa-service` prefix is the WAR context path (Dockerfile: `tspa-service.war`); the REST prefix is
`@RequestMapping("tspa/v1")` on both controllers.

| Step | Method + path | Auth | Purpose | Notes |
|---|---|---|---|---|
| 1 | `PUT /trustframework/{fw}` | `enrolltf` | Register the framework and publish its PTR to DNS | **Calls the Zone Manager first** (`ZoneManager.publishTrustSchemes`) and only then stores locally. Needs a reachable Zone Manager. Body: `{"schemes":["<fw>"]}` |
| 2 | `PUT /init/json/{fw}/trust-list` (or `/init/xml/...`) | `enrolltf` | Create the empty trust list and its first signed VC | Fails with `FileExistsException` if the list already exists. Does **not** require step 1 locally (only checks the store). |
| 3 | `PUT /{fw}/trust-list/tsp` | `enrolltf` | **Add one entry (TSP)** — the write for a new endpoint | 201 on success, 400 with schema errors, 404 if the list does not exist, error if the UUID already exists |
| 4 | `PATCH /{fw}/trust-list/tsp/{uuid}` | `enrolltf` | **Replace an entry** — the write for a redeploy with a new measurement | UUID in URL must equal UUID in body |
| 5 | `DELETE /{fw}/trust-list/tsp/{uuid}` | `enrolltf` | Remove an entry | |
| r | `GET /{fw}/trust-list` | none | Raw list (JSON or XML as initialised) | |
| r | `GET /{fw}/vc/trust-list` | none | Signed VC of the list — what the TCR consumes | |
| opt | `PUT /{fw}/did` · `DELETE /{fw}/did` | `enrolltf` | Publish/remove the URI(DID) record via Zone Manager | did:web triggers a well-known check |
| opt | `DELETE /trustframework/{fw}` · `DELETE /{fw}/trust-list` | `enrolltf` | Teardown | |

Health: `GET /tspa-service/actuator/health` (public).

Read side, for orientation (TCR `eclipse-xfsc/train-trust-validator`, commit `e27b1ed` of 2025-05-25, read 2026-09-18): `POST /tcr/v1/resolve`
{`issuer`, `trustSchemePointers`[, `endpointTypes`]} → DNS `PTR` at `_scheme._trust.<pointer>` → `URI` records →
DIDs → DID document service endpoints → trust-list VC (`trustlistURI`, `hash`) → list fetched, hash recomputed,
signature verified → entry with `ServiceTypeIdentifier == issuer` returned. DNSSEC validation is optional
(`tcr.dns.dnssec.enabled`). A Go client library ships in the TCR repo (`clients/go`).

## 5. Auth model

- Bearer JWT, validated as an OAuth2 resource server against `spring.security.oauth2.resourceserver.jwt.issuer-uri`
  (`application.yml`; upstream default points at a Fraunhofer realm — must be overridden per deployment).
- Authority required: **`enrolltf`**. Enforced twice: `SecurityConfig` matchers for `PUT`/`PATCH /tspa/v1/**`
  (lines 72–73) and `@PreAuthorize("hasAuthority('enrolltf')")` on every mutating controller method,
  **including all DELETEs** (TrustListPublicationController lines 179, 275; TrustFrameWorkPublishController 73, 138).
  Verified at runtime: `DELETE .../tsp/{uuid}` without a token did not remove the entry (evidence §7a → §7b: the
  authenticated DELETE afterwards still found and removed it). No unauthenticated deletion path was found.
- Where the authority comes from: `SecurityConfig` reads `realm_access.roles` from the token and maps each role
  1:1 to an authority (no `ROLE_` prefix). So `enrolltf` must be a **Keycloak realm role** on the caller
  (a client role is not read). The bundled realm export has `enrolltf` as a realm role granted to the
  service account of the confidential client `xfsctest` — the CI/CD pipeline shape is therefore
  `client_credentials` with a client whose service account holds `enrolltf`.
- GET endpoints are public (`anyRequest().permitAll()`).
- **Observed on the local instance (see evidence.md §6b):**

  | Caller | Result | Trust list |
  |---|---|---|
  | no `Authorization` header | **200 with an empty body** — controller never runs (no log line, list unchanged) | unchanged |
  | malformed token | 401 `{"error":"...Malformed token","status":401}` | unchanged |
  | valid token, `enrolltf` only as a **client** role (testuser) | 403, empty body | unchanged |
  | valid token, `enrolltf` as **realm** role (service account of `xfsctest`) | 201 / 200 | written |

  The 200-on-missing-token is an upstream quirk, not a bypass: `RestAuthenticationEntryPoint` hands the
  `InsufficientAuthenticationException` to the MVC `HandlerExceptionResolver`, and `CentralControllerAdvisory`
  only maps `InvalidBearerTokenException` (→ 401); nothing writes a status for the missing-token case, so Tomcat
  returns the default 200 with no body. A pipeline must therefore **not** treat 2xx as proof of publication —
  check the JSON body (`{"MapN":{"message":"TSP published...","status":201}}`) or re-read the list.
- Token `iss` must match `issuer-uri` byte-for-byte (standard Spring behaviour) — relevant when Keycloak is
  reached under different hostnames from the pipeline and from TSPA.

## 6. Payload shape (TSP = one entry = one connector)

Validated against `src/main/resources/templates/TSPSchema.json` before anything is written (400 with the
validation messages otherwise). Root `TrustServiceProvider` with **required** `UUID`, `TSPName`,
`TSPTradeName`, `TSPInformation` (Address with full PostalAddress, TSPCertificationList, TSPEntityIdentifierList,
TSPInformationURI) and `TSPServices.TSPService[]` (each with ServiceDigitalIdentity.DigitalId
{X509Certificate, DID} and a fully populated AdditionalServiceInformation). The schema is deep-required but has
no `additionalProperties: false`, so extra keys pass validation — **and are then dropped**: the entry is parsed
into the shared Java model (`train-shared`, `TSPCustomType` and children) and re-serialised, so anything the model
does not know is not stored (tested 2026-09-18 with extra keys at three levels: 201, nothing persisted).

**There is no measurement/hash field in the schema.** Candidate carriers, all free-form `Type`/`Value` pairs:
`TSPInformation.TSPCertificationList.TSPCertification[]` (used in the local round-trip as
`{"Type":"TEEM-sha256","Value":"<hex>"}`), `TSPEntityIdentifierList`, or `ServiceDigitalIdentity.DigitalId.X509Certificate`.
Which one the TCR-side policy will read is a design decision (see §9).

## 7. Idempotency and update semantics (from `TrustListPublicationServiceImpl`)

- `PUT .../tsp` is **create-only**: a second PUT with a UUID already in the list is rejected
  (`"TSP with UUID ... already exists"`, line 611–613). A PUT body carrying the same UUID twice is also rejected (584).
- Redeploy with a new measurement must therefore be `PATCH .../tsp/{uuid}` with the **same stable UUID**
  (URL and body UUID must match, line 757), or `DELETE` + `PUT`.
- `PUT /init/.../trust-list` is create-only as well (`"Trustlist is already Existing"`, line 261).
- Every mutation rewrites the whole list file and re-derives the VC; there is no ETag/version precondition
  and no request-level idempotency key. Concurrent pipelines writing the same list race on the file.
- Storage is `INTERNAL` (files under `/tmp/train-tspa/store/...`) or `IPFS`, per `storage.type.trustlist`.

### 7.1 What this means for the WP12 pipeline step (design requirement, not a note)

Every deployment republishes the *same* endpoint with a *new* measurement, and `PUT .../tsp` rejects an existing
UUID. So "upload the hash to TRAIN on deployment" cannot be a single PUT. The pipeline step must:

1. **Use a stable UUID per endpoint** (e.g. UUIDv5 over `cluster + workload`), never a fresh random one per run;
   otherwise the list accumulates stale measurements and the verifier has no way to know which is current.
2. **Update, not create:** `PATCH /{fw}/trust-list/tsp/{uuid}` with the full entry (the body's UUID must equal the
   URL's). Use `PUT` only on first publication, i.e. `PATCH` → on 400/404 for a missing entry fall back to `PUT`
   (or `PUT` → on 400 "already exists" fall back to `PATCH`). `DELETE`+`PUT` also works but leaves a window
   with no entry, which would make the peer refuse connections (ZT-70) during the deploy.
3. **Verify by reading back**, not by HTTP status: a missing token yields 200 with an empty body (§5), and
   success bodies are JSON with `"status":201/200`. Read `GET /{fw}/trust-list` (or the VC's `hash`) after writing.
4. **Serialize writers per framework:** every mutation rewrites the whole list file with no version precondition;
   two clusters deploying at once race. One publishing job per framework, or a lock in the pipeline.
5. **Expect the list to exist:** `PUT .../tsp` returns 404 if `/init/json/{fw}/trust-list` was never run; list
   creation is a one-time federation-setup step, not a per-deploy step.

## 8. Running it locally (what was needed beyond upstream's compose)

`docker compose up -d --build` from the TSPA repo root, plus `scripts/verify-tspa-api/docker-compose.override.yml`, which:
1. sets `SPRING_APPLICATION_JSON` on `tspa-service` to point `issuer-uri` at the compose Keycloak
   (`http://keycloak:8080/realms/gxfs-dev-test`), switch `trustlist.vc.signer.type` to `INTERNAL`
   (upstream default is an external TSA signer) and set `zonemanager.query.status=false`;
2. pins Keycloak to `26.0` and disables its curl-based healthcheck (no curl in the image);
3. **Build trap:** the trust-list model classes (`eu.xfsc.train.tspa.model.trustlist.*`) live in a separate repo,
   `eclipse-xfsc/train-shared`, wired in via `.gitmodules` (path `shared`) and `build-helper-maven-plugin`
   (`shared/src`). The GitHub copy has the `.gitmodules` entry but **no gitlink in the index**, so neither a plain
   clone nor `--recurse-submodules` fetches it and `mvn package` fails with `package ...model.trustlist does not exist`.
   Fix: `git clone --depth 1 https://github.com/eclipse-xfsc/train-shared.git shared` before building.

Token is requested from **inside** the docker network so that `iss` equals the issuer TSPA validates.
No Java/Maven needed on the host: the Dockerfile builds the WAR in a Maven stage.

**To reproduce the evidence** (from `scripts/verify-tspa-api/`):

```bash
git clone --depth 1 https://github.com/eclipse-xfsc/train-trust-framework-manager.git tspa
git clone --depth 1 https://github.com/eclipse-xfsc/train-shared.git tspa/shared
cp docker-compose.override.yml tspa/ && (cd tspa && docker compose up -d --build)   # first build ≈ 15 min
TSPA_REPO=./tspa bash roundtrip.sh      # writes evidence.md and bodies/ next to the script
```

`scripts/verify-tspa-api/tcr-findings/tcr-findings.md` holds an out-of-scope finding about the TCR; it is not
part of this verification's evidence.

### Runtime observations worth knowing before the client instance

- `GET /actuator/health` returns **503 DOWN** whenever the Zone Manager is unreachable: `ZonemanagerHealthCheck`
  probes `${zonemanager.Address}/status` unconditionally (the `zonemanager.query.status` flag is not read by it).
  The write API keeps working regardless. Relevant for Kubernetes readiness probes in the Helm chart (WP12).
- `PUT /trustframework/{fw}` failed with 500 locally because TSPA first fetches a Zone Manager token from the
  upstream default `zonemanager.token-server-url` (essif.iao.fraunhofer.de), whose TLS certificate **expired on
  2026-02-27** (`CertificateExpiredException` in the log). The upstream defaults are dead; the client's values are required.
- The signed VC (`GET /{fw}/vc/trust-list`) is built from `templates/VC.json`; TSPA overwrites `issuer`, `id`
  (`<issuer>#issuer-lists`), `issuanceDate`, `credentialSubject.trustlistURI` (from `request.get.mapping`) and
  `credentialSubject.hash` (multihash of the list), and signs with `JsonWebSignature2020`/EdDSA using
  `verificationMethod = <issuer>#<signer.key>`. **`expirationDate` is never set and stays at the template's
  `2025-06-15`**, i.e. already in the past; `credentialSubject.id` is the template's static `uuid:2632367287r82729`.
  Verified 2026-09-18 in TCR source: the TCR does not evaluate `expirationDate` when resolving the trust-list VC,
  so this does not break the TCR path; other consumers of the VC may differ.
- `request.get.mapping` must be the public base URL of TSPA in a real deployment: the TCR follows
  `credentialSubject.trustlistURI` to fetch the list.

## 9. The open publication item — what is closed and what remains

The project's artefact-chain design (2026-09-09) places reference measurements (launch digests) in its artifact class 3 and states:
*"Publication path = TSPA (Trust Framework Manager) + DNS zone manager — the TCR is the read side. TSPA's exact
publish API is UNVERIFIED (Blocked-external-verify): read the TSPA repo / ask the client before building the
launch-digest publication on it; until then that task is not Ready."*

The "read the TSPA repo" half is done by this document. **Proposed replacement for that statement in the design:**

> TSPA's publish API is **VERIFIED against source and a local instance (2026-09-16)**:
> `PUT /tspa/v1/{fw}/trust-list/tsp` (create) and `PATCH .../tsp/{uuid}` (update), Bearer JWT with Keycloak
> realm role `enrolltf`, entry schema `TSPSchema.json`, create-only PUT. Two items remain before the launch-digest publication can be built:
> **(a) Open-decision:** TSPA's entry schema has no measurement field — the carrier for the launch digest
> (candidates A–C in the verification brief, §1) must be chosen together with whoever consumes it on the read side
> (TCR → connector/cmcd comparison, ZT-64/ZT-67); **(b) Blocked-external (the client's XFSC stack):** client TSPA URL,
> framework name, OIDC client with `enrolltf`, Zone Manager reachability, deployed TSPA version.

Note for (a): the design's chain is *Git-versioned metadata → pipeline-signed → per-zone CMC estserver → cmcd, with
expected values published into TRAIN*. The value published to TRAIN must therefore be **derived from the same
signed reference metadata** the pipeline already produces for cmcd, not computed separately, or the two sources
of truth can disagree. Which representation of that metadata goes into the trust-list entry is the decision.

Closed now (no client instance needed): endpoint list, HTTP methods, auth mechanism and required authority,
payload schema, error/idempotency semantics, and a working local round-trip.

Still open — **first, and not external:**
- **decision**: which TSP field carries the TEEM and what the TCR/policy side reads (candidates in §1). This is a
  project convention to agree with the connector/attestation owner; nothing in TSPA forces it.

Still external (needs the client's XFSC stack):
- the client's TSPA base URL and framework name;
- an OIDC issuer + confidential client whose service account has realm role `enrolltf`, provisioned for the pipeline;
- Zone Manager availability (framework/DID publication cannot be exercised offline);
- confirmation that the client runs this same TSPA version (schema and paths could differ).

## 10. Round-trip evidence (local, 2026-09-16; re-run 2026-09-18)

Full request/response log in `scripts/verify-tspa-api/evidence.md`, generated by `scripts/verify-tspa-api/roundtrip.sh` against `tspa-service` built from
commit `ecd5fdc` (+ `train-shared` `6a0abe4`), Keycloak 26.0 with the bundled realm, framework `facis-ztd.local`.

| # | Call | Status | Meaning |
|---|---|---|---|
| 2b | PUT tsp before the list exists (token) | 404 | order matters: list first, then entries |
| 3 | PUT trustframework (token) | 500 | needs Zone Manager (external) |
| 4a | PUT init/json trust-list (token) | 201 | list + first signed VC created |
| 4b | PUT tsp, UUID U, `TEEM-sha256 = 1111…` (token) | 201 | **measurement written** |
| 4c | GET trust-list | 200 | **`1111…` read back** |
| 5a | PUT tsp again, same UUID (token) | 400 `already exists` | PUT is create-only |
| 5b | PATCH tsp/U, `TEEM-sha256 = 2222…` (token) | 200 | redeploy path |
| 5c | GET trust-list | 200 | `2222…` present, `1111…` gone |
| 5d | PATCH tsp/other-uuid with body UUID U | 400 | URL/body UUID must match |
| 6 | GET vc/trust-list | 200 | signed VC, hash of the list, expired `expirationDate` |
| 6b | auth matrix (no token / malformed / client-role only) | 200-empty / 401 / 403 | list unchanged in all three |
| 7b | DELETE tsp/U (token) | 200 | entry removed, confirmed by GET |

The value round-tripped is carried in `TSPInformation.TSPCertificationList.TSPCertification[]` as
`{"Type":"TEEM-sha256","Value":"<hex>"}` — a placement chosen for the test, not yet a project decision (§6, §9).

Re-run 2026-09-18 after correcting the payloads to put the connector's DID in `ServiceTypeIdentifier` (the TCR
lookup key, §1): every status and check identical to 2026-09-16; `scripts/verify-tspa-api/evidence.md` is from this run and its steps
4c/5c carry an explicit check that the read-back entry has `ServiceTypeIdentifier = did:web:connector-b.facis-ztd.local`.

**Scope of this evidence.** What the round-trip proves is that TSPA accepts, stores, updates, signs and returns the
entry. **That the TCR finds the entry by that value is confirmed by reading the TCR source
(`ResolutionService.findIssuerProvider`), not by execution**, because the stock TCR does not run against this
instance without additional infrastructure. Concretely: the VC issuer TSPA uses by default,
`did:web:essif.iao.fraunhofer.de`, no longer has a DID document (HTTP 404), so the TCR cannot verify the signature;
and switching the issuer to a self-contained `did:key` makes the TCR's `resolveDid` fail with a null
`getServices()` for documents without a `service` section (HTTP 500). An exploratory run with a locally patched
TCR exists outside this verification's scope and is recorded in `scripts/verify-tspa-api/tcr-findings/tcr-findings.md`; it is not evidence for the
"done when" criteria, which are all on the write side.
