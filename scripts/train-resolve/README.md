# TRAIN resolution: the stand-in resolver and the fast cases

The gateway resolves what TRAIN expects of a peer with `internal/trainresolve`, through TRAIN's Trust
Content Resolver (TCR), and compares it with the measurement of the peer's verified evidence
([TRAIN resolution at the handshake](../../docs/train-resolve.md)). Nothing in this repository runs
a TCR, so the proofs use the stand-in here: the shape of the TCR's resolve API over a real or
stand-in trust list.

| File | Purpose |
|---|---|
| `fake_tcr.py` | `POST /tcr/v1/resolve` and `GET /actuator/health` as upstream's resolver answers them, with the trust list read live from a TSPA (`--tspa`); pointers resolved through DNS (`--dns-server`, the PTR at `_scheme._trust.<pointer>`) or given (`--pointer DOMAIN=FRAMEWORK`); `--vc-unverified` and `--fail STATUS` induce the outcomes a verifier must refuse |
| `resolve_test.sh` | the fast cases, in seconds and without a cluster: the TSPA stand-in of the publisher, the publisher writing and pruning real entries, this stand-in over it, and the probe (`cmd/train-resolve-probe`) verifying peers against them |

## What the stand-in copies, and what it leaves out

Copied from upstream's resolver (`train-trusted-content-resolver`, `openapi/tcr_openapi.yaml` and
`ResolutionService` at commit `e27b1ed`): the request `{issuer, trustSchemePointers}`; the answer
`{trustSchemePointers: [{pointer, dids, error}], resolvedResults: [{did, resolvedDoc: {endpoints:
[{vcUri, tlUri, trustList, vcVerified}], didVerified}, error}]}`; one DID per framework a pointer
claims; `trustList` as the first provider whose `TSPServices.TSPService[].ServiceTypeIdentifier`
equals the issuer exactly, omitted when none does; a pointer without a PTR record as a `dns_error`.

Left out on purpose, because they are the real resolver's and need a DID document, a signed
credential and DNSSEC the kind stack does not have: DID resolution, the did-configuration check
(`didVerified` is always false), the credential's signature and the list's hash (`vcVerified` is
true when the list and its credential were read, false with `--vc-unverified`), DNSSEC validation.
The resolver therefore proves how the gateway's code consumes a resolver's answer and what it does
with real trust-list content; it does not prove the resolver.

## What the client's resolver instance still needs

Recorded from the earlier exploration of the resolver (`scripts/verify-tspa-api/tcr-findings/`):

- the `_scheme._trust.<framework> URI` record pointing at the framework's DID, which no proof here
  publishes (the zones' PTR records are published by the reconciler's `--with-zones`);
- a `did:web` document for the framework whose services carry the trust-list endpoints, and a
  `service` section at all (the resolver fails on a document without one);
- libsodium in the resolver's image, or every answer carries `vcVerified: false` and the gateway
  refuses every peer;
- `.well-known/did-configuration.json` at the framework's origin if the gateway is configured to
  require `didVerified`;
- measurement records whose `serviceTypeIdentifier` is the string the gateway will present as the
  issuer: the peer's authenticated identity.
