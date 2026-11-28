# TRAIN resolution at the handshake

The attested channel verifies a peer's evidence; what it cannot know on its own is whether the
measurement inside that evidence is the one the peer's zone published. That is TRAIN's part: the
pipeline publishes each component's expected measurement into the zone's trust list before it rolls
out ([TRAIN publication step](train-publish.md)), and the gateway, as the channel forms, resolves the
peer's entry through TRAIN's Trust Content Resolver (TCR), compares, and refuses on anything but an
equal value (ZT-35, ZT-18, ZT-64, ZT-67; SRS § 5.2). This page is the read side: the Go package
`internal/trainresolve`, where it sits, what it asks, how it decides, how long it remembers, and
what its proofs show.

## Where it runs

The channel package (`internal/atls`, interface IF-07) verifies the peer's evidence with the
attestation library and only then calls its configured peer verifier, with the peer's authenticated
identity and the measurements of its verified evidence; any error from the verifier refuses the
channel. `trainresolve.Verifier` is that verifier. It never verifies evidence, never reads a report,
never caches a verdict: it compares measurements the channel already verified with values TRAIN
holds (ADR-0011, decision 4.4: the TRAIN check is a post-check, after the attestation verdict).

The package depends on the standard library only, so it builds without the channel and is plugged
in by the gateway with one adapter:

```go
v := trainresolve.New(tcr, trainresolve.DefaultKey)
cfg.PeerVerifier = atls.PeerVerifierFunc(func(ctx context.Context, p atls.PeerAttestation) error {
    peer := trainresolve.Peer{Identity: p.Identity}
    for _, m := range p.Measurements {
        peer.Digests = append(peer.Digests, trainresolve.Digest{Hex: m.Digest, HashAlg: m.HashAlg})
    }
    return v.Verify(ctx, peer)
})
```

## The lookup: key and pointer

The TCR selects a trust-list entry by exact equality between the resolve request's `issuer` and the
entry's `ServiceTypeIdentifier` (ADR-0011, decision 4.3). What string the verifying gateway presents
was the open item of that decision: it must come from the handshake, not from the report (which is
what is being checked) and not from DNS (which is not authenticated to the peer). The channel hands
the verifier exactly such a string: `Identity`, the identity the peer's certificate matched, a URI
SAN in SPIFFE form, `spiffe://<zone trust domain>/<name>`.

`DefaultKey` therefore proposes the closure: **the key is the identity verbatim, and the
trust-scheme pointer is the host of the identity URI**, the zone's trust domain. The trust-list
file declares the same string as the zone's domain (`zones[].domain`), so the PTR record the
reconciler publishes for the zone is the record the TCR walks for the peer, with no mapping table
and no second lookup. The consequence for the publisher: a measurement record's
`serviceTypeIdentifier` is the component's identity, `spiffe://zone-b.example/gateway`, not a DID.
This is a proposal to the attested-channel owner, recorded in the pull request, not a decision of
this page; `KeyFunc` keeps the alternative open, and `WithPointers` serves deployments whose
identities carry no trust domain (DNS SANs) with configured pointers.

## The decision, in order

Each step fails closed; the first that fails is the verdict, with the reason code of its family
([reason codes](contracts/index.md), family `CHAN`):

| Step | Refusal | Code | Network |
|---|---|---|---|
| The identity yields a key and a pointer | the peer has no identity, or none can be derived | `CHAN-ZONE-UNKNOWN` | none |
| The peer presented a well-formed SHA-256 measurement: algorithm `SHA-256` under any spelling, 64 lowercase hex characters, the grammar of ADR-0011 4.2; an uppercase or prefixed digest is left out, not normalised | none usable | `CHAN-MEASUREMENT-MISMATCH` | none |
| TRAIN is consulted (the cache first) | the pointer resolves to no trust list | `CHAN-ZONE-UNKNOWN` | TCR |
| | the TCR cannot be reached, answers anything but 200, an oversized or unreadable body, an error for the DID, no endpoint, a credential it did not verify, an entry that does not name the key, a value outside the grammar, two different entries | `CHAN-TRUST-UNREACHABLE` | TCR |
| The entry carries at least one `TEEM-sha256` value | no entry under the key, or an entry without one (an issuer's entry, a pruned-to-nothing entry) | `CHAN-MEASUREMENT-UNPUBLISHED` | cache |
| One published value equals one presented digest (set semantics, ADR-0011 4.2: a rolling update publishes the union) | none equal | `CHAN-MEASUREMENT-MISMATCH` | cache |

`CHAN-TRUST-UNREACHABLE` is deliberately loud for `vcVerified: false`: a resolver that could not
verify the trust-list credential (the libsodium failure mode recorded for the upstream resolver)
would otherwise look like a peer problem. The entry the resolver returns is checked again here, for
the key and for the grammar: the resolver's match is not trusted on its own.

## What the resolver is asked, and what is read of its answer

`POST /tcr/v1/resolve` with `{"issuer": <key>, "trustSchemePointers": [<pointer>]}`, over a client
with no proxy, no redirects, TLS 1.3 at least and the zone's trust anchors as roots; the request's
context carries the deadline. Of the answer (`trustSchemePointers[].{pointer, dids, error}`,
`resolvedResults[].{did, resolvedDoc.{endpoints[].{vcUri, tlUri, trustList, vcVerified},
didVerified}, error}`, the field names of upstream's OpenAPI document) the package reads the
pointers' outcome, each endpoint's `vcVerified` and `trustList`, and of the entry its `UUID`, its
services' `ServiceTypeIdentifier` and `TSPInformation.TSPCertificationList.TSPCertification[]`,
selecting `Type == "TEEM-sha256"` exactly; `image-digest` and any other pair are ignored.
`didVerified` is required only when configured (`RequireDIDVerified`): the check needs a
did-configuration document at the framework's origin, which the client's instance may not publish.

## The cache and the window

A resolution, what TRAIN holds for a key, is cached for the TTL the [staleness
matrix](architecture.md#staleness-matrix) documents, **300 s**; a verdict never is, since the verdict
depends on the session and the resolution does not (ADR-0011, consequences). Absence is a
resolution too: a peer nobody published is cached for the same window, so it does not reach TRAIN on
every handshake, and becomes visible as soon as the window ends, like a change of value. A failure
is never cached, and nothing is served after the TTL.

| Moment | What the verifier does |
|---|---|
| T<sub>w</sub>, a handshake with a cold cache | asks the resolver once; concurrent handshakes for the same peer share that one resolution |
| within T<sub>w</sub> + 300 s | serves the cached resolution, whatever TRAIN holds by then |
| the entry is deleted or changed at T<sub>0</sub> ≥ T<sub>w</sub> | nothing changes for the verifier yet |
| the first handshake after T<sub>w</sub> + 300 s | asks the resolver again and sees the change: a removal refuses from here on |

So a removal bites at the latest 300 s after the cached copy was taken, never before the removal
itself; a channel already established keeps its outcome until it is re-established, 15 min at most,
which is the "about 20 min" of the matrix for an established channel.

The resolution runs detached from the handshake with its own budget (`ResolveTimeout`, 5 s inside
the channel's 10 s handshake): a handshake whose deadline ends first is refused now, fail closed,
while the resolution completes and warms the cache, so a cold resolution slower than one handshake
cannot refuse the same peer forever. Resolutions in progress are bounded (64) and the cache is
bounded (1024 entries); both are safety bounds, a zone talks to a handful of peers.

## What the proofs show

| Proof | Runs | Holds the verifier to |
|---|---|---|
| `go test ./internal/trainresolve ./cmd/train-resolve-probe` | the `Go tests` job of the CI workflow | the key derivation; the digest grammar and the algorithm spellings; every refusal in order with no network where none is due; the resolver's answer interpreted case by case (set semantics, other pairs ignored, zero values, absence, an unverified credential, pointer errors, an entry naming another key, values outside the grammar, two entries, every status, an oversized body, a redirect not followed, the request's exact body); the cache: served within the TTL, refetched at it, a change seen in both directions, a failure never cached, fifty concurrent verifications sharing one resolution, a caller's deadline refused while the resolution completes, a hanging resolver bounded, the bounds; the probe's exit codes, records and the transition it times |
| `scripts/train-resolve/resolve_test.sh` | the `TRAIN resolution at the handshake` job of the CI workflow, every pull request; seconds | the publisher's real entries in the TSPA stand-in, read through the resolver stand-in: accepted, from the cache, mismatch, no measurement, unknown zone, not published, zero values, a rolling update accepted on both versions and pruned, a removal refused within a short TTL and never before the deletion, an unverified credential, a resolver failing or down; no secret in any output |
| `scripts/verify-train-resolve/verify.sh` | `train-publish.yml` on kind (the TSPA image cached per upstream commit); locally, [`evidence.md`](../scripts/verify-train-resolve/evidence.md) is the last run | against upstream's real TSPA and real zone manager: the zones' PTR records walked, the publisher's entry under the peer's identity, every verdict with its code, the removal refused within the real 300 s window and never before the deletion, an issuer's entry found and refused as carrying no measurement, the resolver down, failing or unable to verify the credential |

What the proofs do not show: the real Trust Content Resolver (no TCR runs in this repository; the
stand-in copies its API over the real list and DNS, see `scripts/train-resolve/README.md`), and the
handshake itself: the probe hands the verifier the peer's identity and measurement as the channel
would, it does not extract them from an attester's result.

## Status

| Done when | Proven where | Still needs |
|---|---|---|
| The handshake succeeds only when TRAIN vouches for the peer's anchor and measurement | the measurement: the verifier accepts only a presented digest equal to a published `TEEM-sha256` value, on kind against the real list through the resolver stand-in | the verifier behind the channel's `PeerVerifier` in the gateway (the gateway work); the peer's anchor, for which the trust list has no agreed carrier yet; a real TCR |
| A peer presenting a measurement absent from TRAIN is rejected with a specific error | `CHAN-MEASUREMENT-UNPUBLISHED` (no entry, or none with a value) and `CHAN-MEASUREMENT-MISMATCH` (a value that differs), each with a reason naming what was compared | the same refusals observed inside a real handshake |
| A trust-list change takes effect within the cache window (tested) | on kind: an entry deleted while a verifier keeps verifying with the 300 s cache; the refusal timed, within the window and never before the deletion | nothing on this side |
| A TRAIN outage denies rather than allows | a resolver down, answering 502, or whose TSPA is down: `CHAN-TRUST-UNREACHABLE` within the handshake budget; a failure never cached | nothing on this side |

After the merge the ticket stays blocked, not done: the joint proof inside a handshake, the
client's TSPA and the partner's trust content are not here.

## For the client

Nothing here is specific to kind: the resolver's origin, its trust anchors and whether to require
the DID configuration are configuration. To resolve against the client's TRAIN, the following is
needed, in the order it blocks:

1. A Trust Content Resolver instance, its origin and the CA its certificate chains to; with libsodium
   in its image, or every answer carries `vcVerified: false` and every peer is refused.
2. The `_scheme._trust.<framework> URI` record pointing at the framework's DID, and a `did:web`
   document for the framework whose services carry the trust-list endpoints (and a `service` section
   at all: the upstream resolver fails on a document without one).
3. Measurement records whose `serviceTypeIdentifier` is the identity the peer presents, once the
   lookup-key proposal above is agreed.
4. `.well-known/did-configuration.json` at the framework's origin, if `RequireDIDVerified` is to be
   turned on.
