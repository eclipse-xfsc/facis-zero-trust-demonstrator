# ADR-0011: Mock TEE evidence — format, release artefact, and provisioning

- **Status:** Accepted for the format decision and for what is published into TRAIN. Two dependent
  items remain open: how the verifier derives a peer's trust-list key, and the client's TSPA
  instance (see Open items).
- **Date:** 2026-09-22
- **Deciders:** Delivery team, from the mock-attestation format spike (2026-09-17 to 2026-09-18),
  the TSPA publish-API verification (2026-09-16 to 2026-09-18) and the trust-list traversal
  (2026-09-22). What "one sample artefact per vendor profile" means was confirmed with the
  project's technical reviewer on 2026-09-18.
- **Requirement basis:** ZT-71, ZT-31; ZT-35 and SRS § 5.2 (expected launch digests in TRAIN)
- **Related:** ADR-0010 — session attestation through `cmcd`. That number is allocated and the
  record is not yet written, so the references to it below name the decision's owner rather than a
  document that can be read today.
- **Supersedes:** the spike's working note of 2026-09-09, which is kept with the delivery team's
  spike material outside this repository and is now only the evidence log

## Context

ZT-71 requires that at signing time "a mock attestation is generated as JSON format for any TEE
vendor" — a release artefact distinct from the SBOM, the signature, and session-bound evidence.
ZT-31 requires the report to be TEE-style and its signature verifiable with common cryptography
libraries such as OpenSSL.

No TEE hardware is in scope for the demonstrator, so the document a real Trusted Execution
Environment would emit has to be produced in software. The question this record answers is the one
the spike was raised to settle: **does CMC's software driver already emit something usable, or do we
define a mock-attestation format of our own alongside it?** Settling it fixes the document that the
release pipeline stamps onto images and that the verifier checks — both build against the same
thing.

Three artefact classes are in play and are never conflated:

| Class | What it is | Produced by |
|---|---|---|
| 1 — release | Mock-attestation JSON, per image and per TEE vendor profile, attached to the release next to the signature and the SBOM | The signing workflow on the custom runner, post-build |
| 2 — session | Attestation reports produced live, bound to a TLS session | `cmcd`, on peer connection (ADR-0010, allocated) |
| 3 — reference measurements | Launch digests as Git-versioned metadata, pipeline-signed, served per zone by a CMC `estserver`, with expected values published into TRAIN's trust content | The pipeline and the provisioning chain |

Classes 1 and 2 run the same driver and verifier code. Only the trigger and the context available at
call time differ: class 1 is generated post-build with a pipeline-generated nonce and no TLS session,
so it carries no channel binding; class 2 is generated on peer connection, with the nonce derived
from the live session.

## Decision

### 1. Reuse CMC's formats rather than define our own

**Reuse.** The mock attestation uses CMC's `attestationreport` evidence and collateral types
unmodified, serialized as CMC serializes them. The only new code is the sample generator, the JSON
schema, and the checks. A thin wrapper adds two fields and nothing else — `mock` and `profile` —
because CMC's own objects have no field to mark a mock and adding one would change their shape.

**Reasons**

1. **One format for both artefact classes.** The release artefact and the session report from `cmcd`
   come from the same driver and verifier code. A format of our own would give two formats and a
   converter between them.
2. **The verifier already exists.** CMC's unmodified `verifier.VerifySw` accepts the `sw` sample and
   rejects copies with a changed measurement or a different key. Building would mean writing and
   maintaining a verifier of our own.
3. **ZT-71 and ZT-31 are met without CMC code.** The sample parses with `jq` and decodes with
   `base64`, and the `sw` signature verifies with OpenSSL alone.
4. **Moving to real hardware keeps the format.** The hardware profiles already use the types CMC's
   drivers emit, so a real TEE changes the evidence bytes, not the shape consumers read.
5. **The vendor profile needs no extra field.** It is read from `evidence.type` / `collateral.type`.

**Costs accepted**

- The evidence payload is opaque base64, so the measurement is not readable at the first `jq` step,
  and hardware evidence decodes to a binary struct. A `decoded` side object was considered and
  rejected: it wraps the format for readability alone.
- Coupling to CMC's types and to a pinned version. Contained by the pin and by keeping CMC's types
  behind our own Go interface.
- CMC's own `doc/api` schema is wrong about which fields are hex and which are base64, so it is not
  used. Our schema encodes what CMC's code actually does.

**Rejected alternative — build.** A vendor-neutral JSON of our own, with our own generator and
verifier. Rejected for reasons 1, 2 and 4: it duplicates what CMC already provides and diverges from
the session evidence that the inter-cluster channel actually verifies.

**Out of scope here:** how the release artefact is attached to the image — a separate JSON file or a
Cosign attestation. Tracked under Open items.

### 2. A sample artefact per vendor profile is a shape, and the hardware profiles are synthetic

One sample per evidence type that a driver in `cmcd`'s `drivers` config emits as `Evidence.type` —
`sw`, `tpm`, `snp`, `sgx`, `tdx`, `azure-tpm`, `azure-snp`, `azure-tdx` — validated by
[`mock-attestation.schema.json`](../contracts/mock-attestation.schema.json), with the samples in
[`contracts/samples/`](../contracts/samples/). Two things CMC defines stay out, for different
reasons: `IAS Evidence` is a real evidence type that no driver in the pinned tree emits, and IMA
measurement lists are a software inventory carried inside a `PCR Eventlog` rather than an evidence
type — `ima` is a per-driver boolean, not a member of `drivers`. The schema's `EvidenceType` is
where that rule is stated normatively.

- The **`sw` sample is real**: produced by CMC's software driver, which is pure software. It has
  exactly the format `swdriver` emits, its measurement is real and non-zero, and it passes
  `verifier.VerifySw` and an OpenSSL-only signature check.
- **Every other profile is synthetic** — random bytes stand where the hardware would put a quote, a
  signature or a certificate — and every sample is marked `"mock": true`.

The reasons for generating them rather than capturing them:

1. **No TEE hardware is in scope**, and nothing external is required to produce these samples. No
   driver available here can emit a genuine SNP report, TPM quote, or SGX/TDX quote.
2. **What has to be shown is that the schema covers every profile** — the JSON shape each type of
   evidence takes, not a real run of each driver. "Vendor" does not mean "a driver with hardware".

The intellectual-property review did not drive this choice: the samples are synthetic because no TEE
hardware is in scope, not to keep third-party material out of the repository. Whether captured
vendor evidence *could* be committed and redistributed has not been assessed, and would have to be
before any real sample replaces one here.

Two consequences follow and are binding: no CMC verifier will accept a synthetic sample, and a
synthetic sample **must never be presented as vendor evidence**. For those profiles the check is the
schema plus a round-trip through CMC's own types.

Of the two exclusions above, `IAS Evidence` is the one that could have been synthesized like the
hardware profiles, and deliberately was not: with no driver emitting it, its shape would have to be
invented rather than copied from a driver's output.

### 3. The report commits to the TLS exporter; it does not carry the exporter secret

ZT-31 requires that the report "MUST contain the TLS-exporter channel binding specified in RFC
9266", and its acceptance criteria repeat that every report contains that binding for the channel it
is sent through. SRS section 5.2 states the same duty operationally: the report "contains the
TLS-exporter secret associated with the underlying TLS connection", that value "MUST be included so
that its integrity is ensured by the attestation report, e.g. by including it in the report's user
data field", and the initiator "MUST ensure that the correct TLS-exporter secret is contained
within".

**The pinned CMC does not carry that secret.** It carries a commitment to it, and this record fixes
that reading.

In CMC v0.9.15 (commit `6754d3c`, "attestedtls: introduce new channel binding") each end exports 32
bytes from the TLS session with `ExportKeyingMaterial("EXPORTER-Channel-Binding")` — RFC 9266 — and
the prover signs the nonce `sha256(exporter ‖ its own TLS leaf certificate)`
(`attestedtls/attestation.go`, `bindReportNonce`). The verifier recomputes the value from its own
view of the session and rejects the report on mismatch. Each end requires the same of its peer: the
outbound report is bound to the prover's own certificate, and an inbound report is checked against
the peer's.

The reason is in CMC's own commit: the exporter secret is symmetric, so both ends derive the same
value. Used alone as the nonce — with mutually recognised certificate authorities and no further
policy — it let a peer replay a received report back at its sender. Mixing the prover's certificate
into the nonce makes each direction's expected value different.

Two consequences follow, and they differ in kind:

- **The field is not the issue.** SRS section 5.2 offers the user data field as an example ("e.g."),
  not a mandate. CMC binding through the report's nonce is a free implementation choice, not a
  deviation.
- **"Contains the TLS-exporter secret" is not met literally.** The report holds
  `sha256(exporter ‖ cert)`, not the exporter, so a verifier written to the letter of section 5.2 —
  looking inside the report for the raw exporter value — will not find it. What CMC's verifier does
  instead is recompute the expected value from its own view of the session and compare. The
  integrity duty ZT-31 states is met, and the construction is stronger than the one described,
  because it also closes the reflection case.

Proven with a real mutual aTLS handshake in the spike: both ends derive the same exporter, the two
directions' nonces differ, and a report bound to one session is rejected in another.

This deviation is declared in the [specification change index](../specifications.md) before gate G4.

### 4. What is published into TRAIN, in what form, and when it may be trusted

Reference measurements (class 3) travel as Git-versioned metadata, are signed by the pipeline, and
are served per zone by a CMC `estserver` to `cmcd`. A **single derived value per endpoint** is
published into TRAIN's trust content for the peer-side check ZT-35 and ZT-67 require. **The
publication path is the TSPA (Trust Framework Manager) together with the DNS zone manager; the TCR
is the read side.**

TSPA's publish API is **verified against source and a local instance**: `PUT
/tspa/v1/{fw}/trust-list/tsp` creates an entry and `PATCH .../tsp/{uuid}` replaces it, both behind a
Bearer JWT carrying the Keycloak **realm** role `enrolltf`. `PUT` is create-only, so a redeploy is a
`PATCH` against a **stable per-endpoint UUID**, never a fresh one. A write without a token is
answered `200` with an empty body and stores nothing, so **the HTTP status is not proof of
publication**: the pipeline re-reads the trust list and asserts the value it just wrote. What
remains external is the client's own instance — base URL, framework name, an OIDC client whose
service account holds `enrolltf`, and Zone Manager reachability.

**TRAIN cannot carry `cmcd`'s reference values, and the two must never be conflated.** A CMC
reference value for a container is not a scalar: the verifier matches on `rootfsSha256` and then
recomputes the template hash from the reference's own copy of the OCI runtime spec
(`ValidateTemplateHash`), whereas a trust-list field holds one string. TRAIN therefore carries a
single derived scalar — a second, coarser gate on top of CMC's own verification. Both must be
derived from the **same signed metadata in the same pipeline step**, or the two sources of truth
drift apart silently.

#### 4.1 The published value is the container measurement, not the image digest

**The value is the CMC container measurement — the template hash — of the component as deployed,**
that is `sha256(normalised OCI config ‖ rootfs hash)` as CMC computes it.

Three plausible-looking alternatives are rejected, and each rejection is load-bearing:

- **Not `rootfsSha256`,** although that is the field CMC's own verifier matches reference values on,
  which makes it look canonical. It does not move when only the OCI configuration changes. Measured
  across the spike's three tags: `v3` changes only the OCI configuration against `v2`, so the two
  share a `rootfsSha256` — `de19a1d3…` for both — while their template hashes differ,
  `0842477b…` against `b47b2a54…`. A verifier holding the previous `rootfsSha256` from TRAIN
  would accept a peer running a different configuration.
- **Not the aggregate** inside the signed payload. It is `extend`-chained over every container in
  the log, so a second measured workload changes it although the component did not. It is a property
  of a report, not of a deployment, so the pipeline cannot pre-generate it as ZT-35 requires. With
  one container it is exactly `extend(zeros32, templateHash)`, so nothing is lost: the aggregate is
  derived at verification time for the binding check in 4.4.
- **Not the OCI image digest.** That is what the signing workflow signs with Cosign; it is a
  different SHA-256 that also reads as "the digest of the image". Publishing it would satisfy no
  verifier, because it appears nowhere in an attestation report.

The template hash covers the rootfs **and** the normalised OCI configuration — `process.args`,
`process.env`, user, mounts, capabilities — while ignoring the fields `measure.Normalize` strips.
The two halves are not normalised alike: CMC strips the volatile fields from the configuration, but
the rootfs half is hashed from the filesystem as the measuring machine holds it, which is why the
value is reproducible only under the conditions the open item below sets out.
So the published value belongs to the component **as deployed**, not to the image: two deployments
of the same image with different environment variables have different measurements, and a
configuration change that ships no new image still requires a republication before rollout.

#### 4.2 Carrier and wire grammar in the trust list

TSPA's entry schema has **no measurement field**, and extra keys are accepted with `201` and then
silently dropped, because the entry is re-serialised from a shared model that does not know them.
The value therefore rides in an existing free-form `Type`/`Value` pair:

```json
"TSPInformation": {
  "TSPCertificationList": {
    "TSPCertification": [
      { "Type": "TEEM-sha256", "Value": "783431065396a0483425b016f6925a321dee6c2146c5ab7244833aa888ebb60c" }
    ]
  }
}
```

Binding on both ends:

1. `Type` is exactly `TEEM-sha256`. The algorithm lives in the `Type`, never in the `Value`: TSPA
   stores `Value` verbatim, and a self-describing `sha256:<hex>` form fails silently against any
   reader that hex-decodes.
2. `Value` matches `^[0-9a-f]{64}$` — lowercase, unpadded, no `0x`, no prefix, no whitespace. This
   is CMC's `HexByte` output, so the producer emits it without transformation. Readers validate the
   grammar and reject on mismatch rather than normalising; a liberal reader hides publication bugs
   until a strict reader appears at the other end.
3. **Set semantics.** An entry carries one *or more* `TEEM-sha256` pairs and the verifier accepts a
   report matching any of them. A rolling update runs two versions at once, and with a single
   published value there is always a window in which TRAIN contradicts part of what is running —
   which, by ZT-70, means denied connections rather than degraded ones. The pipeline publishes the
   union for the duration of the transition and **prunes back to the current value once the rollout
   converges**; without pruning the entry degrades into a permanent allow-list. Zero values means
   "not published" and fails closed.
4. A new algorithm takes a new `Type` (`TEEM-sha384`), never a re-encoded `Value`.

This is a project convention, not a standard: the reduced ETSI TS 119 612 model TSPA implements
defines extension elements for exactly this purpose, but neither TSPA nor the TCR carries them.
Implementing them upstream is the cleaner route and is not in scope here.

#### 4.3 The trust-list lookup key is the service type identifier

The TCR selects an entry by matching the resolve request's `issuer` against
`TSPServices.TSPService[].ServiceTypeIdentifier`. Despite its name, that field holds the subject's
identifier — upstream trust lists put the DID there — and
`ServiceDigitalIdentity.DigitalId.DID` is
informational and **is not** the lookup key. The pipeline writes the verifier's lookup string into
`ServiceTypeIdentifier`; a wrong value there is accepted, stored and signed, and the TCR simply
never finds the entry.

**Open:** how the verifying connector derives that string from the authenticated aTLS peer, which
presents an X.509 certificate rather than a DID. It must come from the handshake — not from the
report, which is what is being checked, and not from DNS, which is not authenticated to the peer.
Tracked under Open items and owned by the attested-channel work.

#### 4.4 The TRAIN comparison runs only after CMC verification has succeeded

The published value is compared against the measurement in the peer's **event log**, which arrives
from the peer alongside the evidence and is attacker-supplied on its own: a peer can send a report
whose event log claims any measurement. What authenticates it is the aggregate —
`extend(zeros32, templateHash)` must equal the SHA-256 inside the signed payload, which
`verifier.VerifySw` recomputes along with the signature and the nonce.

**The TRAIN check is therefore a post-check.** It runs after CMC verification returns success, never
instead of it and never in parallel. An implementation that reads the event log and consults TRAIN
without completing CMC verification is trivially bypassable — and would still pass a test
that only
swaps a measurement.

## Consequences

- The demonstrator carries one attestation document, not two, and no converter between them. When
  real hardware appears, only the evidence bytes change.
- Consumers must treat the evidence payload as opaque and **compare measurements, never evidence
  bytes**: the nonce and the ECDSA signature make the bytes differ on every run. This binds TRAIN's
  expected values and the release artefact alike.
- `verifier.VerifySw` trusts the key carried in the collateral. On real hardware the hardware
  evidence anchors that key; without hardware, a `sw` artefact is only self-consistent. If admission
  is to verify it cryptographically, the artefact has to be anchored — for example a Cosign
  attestation with the signing-runner key — and the reference values have to come from TRAIN rather
  than from the artefact itself. That is **new scope**: the release artefact as specified is checked
  for presence and schema.
- Any change to code, files or measured configuration needs a **new reference value published before
  rollout**, or the verifier rejects the legitimately updated container exactly as it rejects a
  tampered one. Because the measurement covers the normalised runtime configuration, this includes
  changes that ship no new image.
- The publishing pipeline **cannot compute the value by itself**. A plain hash of the rootfs is the
  wrong value (decision 4.1), so the step runs the same CMC container measurement that produces the
  reference metadata for `cmcd` — one computation, two consumers.
- A verifier may cache a TRAIN resolution, with a bounded lifetime, but **never a verification
  verdict**: the verdict depends on the session nonce, while the resolution does not.
- Acceptance testing has to cover two cases that a naive implementation passes: a
  **configuration-only
  change**, which alone distinguishes the published measurement from a rootfs hash, and a **forged
  event log** claiming the published measurement with an aggregate or signature that does not close.
- Completing an aTLS handshake needs signed metadata — at least an image description and a root
  manifest, JWS-signed and chaining to a configured root CA — and `cmc.NewCmc` requires a root CA, an
  endorser and an enroller even when the software driver uses none. This is a prerequisite for the
  provisioning chain and the attested channel, not an optional extra.

**What would reopen this decision:** CMC ceasing to be the attestation library; a requirement for a
vendor-neutral artefact that consumers outside the demonstrator must read without CMC's types; or
real TEE hardware entering scope with a driver CMC does not provide.

## Open items

- **How the release artefact is attached** — a JSON file alongside the image, or a Cosign
  attestation. ZT-10 requires "Cosign and an attestation flow which is valid for a mock TEE" on the
  signing runner.
- **How the verifier derives a peer's trust-list key** from the authenticated aTLS peer
  (decision 4.3). Owned by the attested-channel work; the publishing side cannot choose it alone,
  because the pipeline has to write the same string it will be asked for.
- **The client's TSPA instance.** Base URL, framework name, an OIDC issuer and confidential client
  whose service account holds the realm role `enrolltf`, Zone Manager reachability, and confirmation
  that the client runs the same TSPA version — paths and schema could differ. The API
  surface itself
  is no longer open.
- **Cross-machine determinism holds for a normalised checkout; it does not hold for a checkout.**
  The measurement's source is versioned configuration *plus a normalised computation environment*,
  and only the first half is under version control. CMC hashes the rootfs as a tar stream and
  normalises it only in time: `ModTime`, `AccessTime` and `ChangeTime` are zeroed, while `Uid`,
  `Gid` and the permission bits are taken from the filesystem as found, and a file's
  `security.capability` xattr is folded in as a PAX record (`measure/rootfs.go`). Git
  preserves none of those — it records content, paths and the executable bit alone, so ownership
  follows whoever checked the tree out and the remaining mode bits follow their `umask`. One
  fixture measured under three checkout owners and permission sets gives three template hashes.
  What closes the gap is normalisation before measurement — ownership flattened and the permission
  bits taken from the Git index rather than from the working tree — and it is checked rather than
  asserted: `tools/measurement-determinism/` measures a fixture on a hosted runner, in a container where the
  checkout belongs to root instead of the runner user, and on a checkout deliberately given another
  owner, other permission bits and a file capability — the three inputs Git does not record —
  and requires `configSha256`, `rootfsSha256` and the template hash to be identical on all three. It also requires the perturbed
  checkout to differ *before* normalisation, so the check cannot pass by the three machines
  happening to agree. Whole evidence is never compared: its nonce and signature differ on every run.
  This matters for ZT-35, because a published reference value that depends on who built it is not a
  property of the release.
  What remains open is the same treatment in the image build. `COPY` carries the mode it finds in
  the build context, so an unnormalised checkout puts the machine back into the measurement by
  another route, and the fixture is measured rather than built. The attestation component is not a
  dependency of the delivery module and the check fetches it at the pinned revision instead, so the
  licence gate has not yet seen it; adding it to `go.mod` is a separate step through IP review.
- **The evidence reports configured measurements, not what actually runs.** CMC provides the
  measurement functions but no trigger, and nothing measures the running container. The link is
  indirect: admission control admits only signed image digests (ZT-11), and the measurement
  published into TRAIN is required to be the one the deployed component would report — two
  different SHA-256 values, joined only by the pipeline that produces both. This is coherent for a
  mock TEE whose evidence is
  software-rooted, but the demonstrator's claims must say so, and it is to be raised with the client
  if runtime measurement is expected.

## References

- SRS, Annex A — ZT-31, ZT-71, ZT-10, ZT-11, ZT-35, ZT-67, ZT-70
- SRS § 5.2 — the attested-channel protocol flow: the report carries the TLS-exporter value, and
  the initiator checks the mocked TEE's launch digest against the expected value in the
  responder's TCR
- [`contracts/mock-attestation.schema.json`](../contracts/mock-attestation.schema.json) and
  [`contracts/samples/`](../contracts/samples/) — the schema and the eight samples this record
  fixes
- [`specifications.md`](../specifications.md) — the specification change index, where the
  channel-binding deviation in decision 3 is declared
- `eclipse-xfsc/train-trust-framework-manager` `ecd5fdc` and `eclipse-xfsc/train-shared` `6a0abe4` —
  the TSPA endpoints, entry schema and trust-list model behind decision 4; `train-trust-validator`
  `e27b1ed` — the resolver whose lookup rule fixes decision 4.3
- ETSI TS 119 612 — the trusted-list standard TSPA's model reduces, and the source of the extension
  elements decision 4.2 does not use
- The spike's working material, held with the delivery team outside this repository — the full
  evidence log: the real `sw` run, the measurement proof across three tags, the schema and sample
  checks, the mutual aTLS channel-binding handshake, the TSPA round-trip, and the trust-list
  traversal that fixes decision 4 (a re-runnable walk of one measurement from the versioned source
  to the verifier's comparison)
- `Fraunhofer-AISEC/cmc` v0.9.15, commit `6754d3c` — the pinned version, and the commit that
  introduced the channel binding described in decision 3
