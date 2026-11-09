# XFSC fixture package

Stand-ins for the XFSC credential services (issuer, wallet, verification, status list) so the
journeys in [Scenario decisions](../../../docs/scenarios.md) can be built and tested before the live
services are available. Everything here is synthetic and marked `"fixture": true`; a result built on
it is reported as **fixture-only**, never as live evidence.

## Layout

One file per operation and case: `<operation>/<case>.json`.

| Operation | `allow` | `deny` | `unavailable` |
|---|---|---|---|
| `issue` | `participant-reader` receives its credential | nothing issued to `participant-unpresented` | issuer unreachable |
| `present` | presentation answering the verifier's challenge | presentation with the wrong challenge | wallet unreachable |
| `verify` | IF-03 outcome `verified` | IF-03 outcome `revoked`, `CRED-REVOKED` | verification service unreachable |
| `status` | status list with the reader's bit clear | status list with the reader's bit set | status list unreachable |

Each file has the same members: `fixture`, `operation`, `case`, `input`, `output` (the artefact, or
`error` for an unavailable service) and `expect` (what the demonstrator must do with it).

## Status of this set

This set predates the credential profile the demonstrator verifies. It is kept for the scenario
decisions that reference it and for the wallet lane's storage proof, which publishes
`issue/allow.json`. The presentations a verifier is tested against live in
[`features/fixtures/oid4vp/`](../oid4vp/README.md): SD-JWT VC with a key-binding JWT and an IETF
Token Status List, which is what the live wallet stack issues and what the verification service
checks. New fixtures go there.

## Formats

- **Credentials and presentations** follow the W3C Verifiable Credentials Data Model 2.0. They carry
  no proof: how the live issuer secures them is not confirmed yet, and the fixtures do not guess it.
- **Status lists** follow W3C Bitstring Status List: 131 072 entries, GZIP-compressed,
  base64url-encoded with the multibase prefix `u`. The reader's credential is at index 42; the
  `deny` list has exactly that bit set.
- **Verification outcomes** are IF-03 payloads and validate against
  `docs/contracts/if03-verification-outcome.v1.schema.json`. Reason codes are from
  `docs/contracts/reason-codes.json`.

## Swapping to the live services

Each operation is replaced on its own, by configuration: point the adapter at the live endpoint and
keep the same `expect` as the acceptance check. What the swap still needs, per operation:

| Operation | Needed from the live service |
|---|---|
| `issue` | Issuer endpoint and version; the credential format and how it is secured |
| `present` | Wallet endpoint and the presentation request it accepts |
| `verify` | Verification endpoint and signing key (`kid`) for IF-03 outcomes |
| `status` | Status list URL and its update behaviour |

## Open points

- **Unreachable status list.** Closed: the registry now carries `CRED-STATUS-UNAVAILABLE` (fail
  closed, no token issued). An unreachable verification service still has no code of its own: the
  token store reports it as its own acquisition failure and issues nothing.
- **No IF-01 source for the issuer.** Issuance events cannot be shown on the feed until IF-01 gains
  a source for it.
