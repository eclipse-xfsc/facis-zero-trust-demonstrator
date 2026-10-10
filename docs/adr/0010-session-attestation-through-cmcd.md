# ADR-0010: Session attestation through `cmcd` — pinned CMC behind the `internal/atls` interface

- **Status:** Proposed. The decisions below are implemented and proven locally; the record awaits
  review. Two items stay open independently of that review: the partner's sign-off of the
  interface (the interface-freeze process) and the run of the channel proofs on the target cluster.
- **Date:** 2026-10-01
- **Deciders:** Delivery team, from the attested-channel spike (2026-09-25 to 2026-10-01): the
  reading of the attestation component, the wrapper and its tests, the channel proofs against a
  real `cmcd`, and the freeze of the interface.
- **Requirement basis:** ZT-28 (mutually attested TLS 1.3, certificates checked against the
  cluster's identities), ZT-29 and ZT-30 (attestation request and response), ZT-31 (report format
  and channel binding), ZT-32 and ZT-33 (verification before application traffic; close on error),
  ZT-35 (peer hashes from TRAIN — hook only), ZT-50 (key algorithms), ZT-52 (fail closed);
  SRS § 5.2 and the SRS appendix ("the REQUIRED CMC daemon")
- **Related:** [ADR-0011](0011-mock-tee-evidence-format-and-provisioning.md) — this record is the
  "class 2 — session" artefact it names; [ADR-0004](0004-openbao-as-x509-key-value-store.md) — the
  zone PKI the channel's certificates come from; [ADR-0001](0001-service-mesh-mode-istio-ambient-with-cilium.md)
  — SPIRE identities stay in the mesh, see decision 5
- **Where it is implemented:** [Attested channel control](../attested-channel.md) (the interface,
  frozen at v1), `internal/atls`, and the evidence under
  [`docs/evidences/cmc-atls-channel-binding/`](../evidences/cmc-atls-channel-binding/README.md)

## Context

All traffic between the zones crosses a channel that is attested at both ends: a TLS 1.3 handshake,
then an exchange in which each end proves what software it runs, bound to that very TLS session
through the RFC 9266 exporter so that a report cannot be copied from one connection to another
(ZT-28, ZT-31). The SRS appendix sketches this with Fraunhofer AISEC's CMC library and names "the
REQUIRED CMC daemon" as the attester; the architecture draws one `cmcd` beside each zone's gateway.

Three things had to be settled before anything could be built on the channel:

1. **Which CMC, exactly.** CMC is a research library with a moving API. The demonstrator needs one
   known version, so that every proof, every finding and every workaround refers to the same code.
2. **How much of CMC the rest of the code may see.** CMC's types, its result callback and its error
   texts are its own; letting them spread through the gateway would couple every consumer to that
   one version.
3. **What CMC v0.9.15 actually does.** Reading it, and then testing it, showed behaviour that the
   channel cannot inherit as it is: a server-side deadline that is never cleared, a client-side
   attestation phase without any deadline, serial accepts, a result callback that fires before the
   verdict and treats `warn` as success, a goroutine leak on a failing peer, a message reader without
   a size bound, and a channel binding that reads only the first static certificate. The full list,
   with what is tested and what is mitigated, is the limitations table of
   [Attested channel control](../attested-channel.md).

No TEE hardware is in scope, so the evidence comes from CMC's software driver; the format of that
evidence and its provisioning are ADR-0011's. The SRS states "no special requirements for the TLS
certificates for the attestation protocol".

## Decision

### 1. Pin the upstream library, unmodified

`github.com/Fraunhofer-AISEC/cmc` **v0.9.15**, commit `6754d3c8992133830a3fb0e4c56c860c28e38c1e`
(2026-08-05, "attestedtls: introduce new channel binding"), required from upstream in `go.mod` with
no `replace` and no fork. That commit is the one that introduced the asymmetric report nonce
(`sha256(exporter ‖ prover leaf certificate)`), which the binding proof relies on.

**Rejected:** a fork carrying local fixes. Every defect found is worked around in the wrapper or
documented, so the pin stays on code the maintainers published and the fixes can be offered upstream
as patches rather than carried as divergence.

### 2. One importer, our own types, a frozen interface

Only the package `internal/atls` imports CMC; a `depguard` rule fails the build for any other
importer, and the package's exported API references no CMC type (checked by a test). The in-process
CMC (`libapi`) exists for tests only, behind `internal/atls/atlstest`, which a second rule keeps out
of non-test files. The exported surface is frozen at **v1** — listed in `internal/atls/api_v1.txt`
and guarded by a test — and registered as the IF-07 contract; the stability rules are in
[Attested channel control](../attested-channel.md#stability).

**Rejected:** using CMC's `attestedtls.Dial`/`Listen` directly from the gateway. It would spread
CMC's types, its callback and its error texts into every consumer, and the workarounds of decision 4
would have to be repeated at each call site.

### 3. One `cmcd` per zone, reached over gRPC

The attester is the zone's `cmcd`, reached over gRPC at a configured address, as the SRS appendix,
the architecture and ADR-0011's provisioning chain assume. The channel's own certificates and keys
are not created through `cmcd`: they are static files from the zone PKI (decision 5), so `cmcd`
needs no enrolment server to serve the channel. Messages are JSON-serialised (ZT-29, ZT-30).

**Rejected:** CMC in the gateway process (`libapi`). It re-initialises process-global TEE drivers on
every call and mixes zones' keys when two zones share a process (findings N4 and N5), and it would
put the attester's keys and metadata inside the gateway. It remains the test backend.

### 4. The wrapper fails closed and neutralises the known defects

A channel is returned only when the TLS 1.3 handshake with mutual certificate authentication
succeeded, the peer's certificate chains to the zone anchors and carries the expected identity,
CMC completed the mutual attestation without error and produced exactly one `success` result for
this connection, the peer's evidence is within its validity, and the configured peer verifier (the
TRAIN hook, ZT-35) accepted the peer. `warn` is a refusal; a missing result is "not attested";
every refusal closes the connection and returns one of the typed sentinels.

Against CMC v0.9.15 the wrapper: clears the handshake deadline after accept; bounds the client's
attestation phase by the caller's context; handshakes each connection in its own goroutine; caps
concurrent handshakes per process; and requires exactly one static certificate. The message
reader's missing size bound cannot be fixed from outside (CMC asserts a `*tls.Conn`); it is
contained by mutual TLS in front of it, the handshake cap and a memory limit on the pod, and is
reported upstream through the project's disclosure process.

### 5. Static certificates from the zone PKI; rotation by a new channel

Each process holds one static TLS certificate and key issued by its zone's PKI; dynamic certificate
callbacks are refused at configuration time, because the channel binding reads only
`tls.Config.Certificates[0]` (finding N3). A certificate is rotated by opening a new channel with
the new configuration, which fits the channel lifetime below. SPIRE provides the mesh identities
(ADR-0001) and is not wired into the channel while N3 stands. The peer identity is one exact SAN,
URI form recommended (`spiffe://<zone trust domain>/<name>`), DNS form accepted.

### 6. Channel lifetime; no keep-alive in the wrapper

TLS 1.3 does not renegotiate, so evidence never refreshes on a live channel. A channel is valid
until the earlier of its attestation time plus the configured lifetime (default 15 minutes) and the
validity end of the peer's evidence; the owner of the channel re-establishes it before then. The
wrapper sends no keep-alives and closes nothing on its own: detecting a half-open peer and
reconnecting are the owner's, with the read deadlines the connection supports. What each end
observes when a process dies, when a `cmcd` dies with a channel open or during a handshake, and when
a peer freezes, is recorded by the session-loss proof.

### 7. What this record leaves to others

Provisioning of the attester's metadata and the enrolment server (ADR-0011 and the provisioning
chain); resolution of the peer's expected measurement in TRAIN (behind the peer verifier); the
gateway process and the channel's lifecycle (rotation, drain, reconnect); an attester health check
(`cmcd` v0.9.15 has none; an additive `CheckAttester` stays possible without breaking v1).

## Consequences

- One version of CMC, one importer, one documented interface: a CMC upgrade is a single change
  whose regression tests say what changed, and consumers code against v1.
- The proofs of the channel — identical binding at both ends, refusal of a report bound to another
  session, recorded session loss — run against real `cmcd` processes and are committed as evidence,
  re-run by CI on every pull request that touches the channel. The run on the target cluster is
  pending; only that run closes them for acceptance.
- Costs accepted: CMC's error texts are matched by text (pinned by tests, so an upgrade that
  rewords an error fails the build); a frozen peer is invisible to the wrapper until the owner's
  traffic shows it; a dead `cmcd` is noticed at the next handshake; certificates cannot rotate in
  place.

**What would reopen this record:**

- a CMC release that fixes the limitations the wrapper works around — the regression tests fail on
  purpose and the pin moves, with decision 4 revisited;
- a fix of the single-certificate binding (N3), which would allow SPIRE-delivered, rotating
  certificates on the channel and revisit decision 5;
- TEE hardware in a zone, which changes the driver and the evidence but not this interface;
- the partner's sign-off asking for a different interface, handled as a deliberate v1.x change
  under the stability rules;
- the target-cluster run showing an error surface the session-loss proof did not.
