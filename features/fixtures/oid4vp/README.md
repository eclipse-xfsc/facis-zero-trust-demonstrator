# OID4VP conformance fixtures

Presentations a verifier must judge, each with the outcome it must produce. They exercise the
credential profile the demonstrator verifies: an SD-JWT VC (`dc+sd-jwt`) with selectively
disclosable claims, a key-binding JWT that ties the presentation to the connector's challenge
(the nonce) and to the audience the token is for, and revocation through an IETF Token Status
List. Everything here is synthetic and marked `"fixture": true`; a result built on it is reported
as fixture-only, never as live evidence.

## Layout

| Path | Content |
|---|---|
| `trusted-issuers.json` | The trust set a verifier is configured with: the fixture issuer and its one key, in the format the connector and the verification service share (`internal/if03.ParseIssuers`) |
| `status-lists/clear.jwt` | A status list with every entry clear |
| `status-lists/revoked.jwt` | The same list with the fixture credential's entry (index 42) set to invalid |
| `status-lists/expired.jwt` | A clear list whose `exp` is in the past |
| `cases/<name>.json` | One presentation and the outcome it must produce |

A case has `input` (`vp_token`, `nonce`, `audience`, `now`), `status_list` (which list the
verifier finds at the credential's status URI: `clear`, `revoked`, `expired`, `unavailable` when
nothing answers, `none` when the credential names no list) and `expect` (`status`, `reason_code`
when not verified, and the `claims` and `credential_refs` the outcome carries when the credential
was read).

## The cases

| Case | Presentation | Expected outcome |
|---|---|---|
| `valid` | role and entitlement disclosed, bound to the nonce and audience, status clear | `verified` |
| `valid-no-entitlement` | only the role disclosed | `verified` |
| `tampered-disclosure` | a disclosure's value changed after issuance | `failed`, `CRED-INVALID` |
| `tampered-issuer-signature` | the issuer JWT altered after signing | `failed`, `CRED-INVALID` |
| `tampered-kb-nonce` | key binding for another nonce | `failed`, `CRED-INVALID` |
| `tampered-kb-audience` | key binding for another audience | `failed`, `CRED-INVALID` |
| `tampered-sd-hash` | a disclosure dropped after the key binding was computed | `failed`, `CRED-INVALID` |
| `missing-key-binding` | no key-binding JWT | `failed`, `CRED-INVALID` |
| `kb-wrong-holder-key` | key binding signed by a key other than the credential's | `failed`, `CRED-INVALID` |
| `untrusted-issuer` | issuer not in the trust set | `failed`, `CRED-ISSUER-UNTRUSTED` |
| `untrusted-kid` | trusted issuer, unknown key id | `failed`, `CRED-ISSUER-UNTRUSTED` |
| `revoked` | valid presentation, status entry set | `revoked`, `CRED-REVOKED` |
| `status-unavailable` | valid presentation, status list unreachable | `failed`, `CRED-STATUS-UNAVAILABLE` |
| `status-expired-list` | valid presentation, status list past its `exp` | `failed`, `CRED-STATUS-UNAVAILABLE` |
| `expired-credential` | credential past its `exp` | `failed`, `CRED-INVALID` |
| `unaccepted-vct` | credential type the verifier does not accept | `failed`, `CRED-INVALID` |
| `no-status` | credential without a status reference | `failed`, `CRED-INVALID` |
| `role-missing` | valid presentation that discloses no role | `failed`, `CRED-INVALID` |

The four outcomes and the order of the checks are the policy in `internal/presentation`, which
the conformance test runs over this tree and the verification service applies to every
presentation it judges;
the [IF-03 section of the interface registry](../../../docs/api-docs.md#if-03--signed-verification-outcome)
states the mapping.

## Credential profile

What the cases exercise is exactly what the verifier accepts; a presentation outside it is
`CRED-INVALID`, whatever its merit elsewhere:

- The issuer JWT has header exactly `alg` `ES256`, `typ` `dc+sd-jwt` and `kid`; trust is by `iss`
  and `kid` in the configured set, never by `x5c` or a key in the token.
- `cnf` is exactly `{"jwk": <public P-256 JWK>}`; `_sd_alg` is absent or `sha-256`; `vct` is one
  the verifier accepts; `nbf` and `exp` are honoured with 30 s of skew.
- Disclosures are `[salt, name, value]` resolved against `_sd` at any depth of the claim set;
  decoys are fine; array element disclosures (`{"...": digest}`), reserved names and registered
  claims are refused; the envelope (`iss`, `cnf`, `status`, ...) is never a claim.
- The key-binding JWT has header exactly `alg` `ES256` and `typ` `kb+jwt`, is signed by the `cnf`
  key, and its payload is exactly `iat`, `aud` (a string), `nonce` and `sd_hash`; `nonce` is the
  connector's challenge, `aud` the audience, `iat` within [now − 300 s, now + 30 s].
- A disclosed, non-empty `role` is required; `entitlement` is optional and non-empty when present.
- `status.status_list{uri, idx}` is required: revocation is checked at every verification. The
  list is a `statuslist+jwt` signed by a key of the credential's issuer, with `sub` equal to the
  URI, fetched only from a configured prefix; `suspended` and every other non-zero entry count as
  revoked.

## Regenerating

```
go run ./cmd/sdjwt-fixture regenerate --out features/fixtures/oid4vp
```

Keys come from fixed scalars (`internal/sdjwt/sdjwtfixture`), salts from a fixed seed and every
instant from `--now` (default `2026-09-09T12:00:00Z`), so a regenerated tree has the same public
keys, digests, claims and expectations as the committed one; only the ECDSA signature bytes
differ. The scalars are in the source, so these keys are public knowledge: the fixture issuer must
never appear in a deployed trust set, and `cmd/sdjwt-fixture`'s test fails when this tree and the
generator drift apart. `cmd/sdjwt-fixture` also takes `--status-uri`, `--audience` and `--nonce`,
which a proof uses to bind the same cases to the list server and challenge it runs with.

## What they are not

- Not evidence: a verifier passing them has read a well-formed presentation; it has not talked to
  a wallet.
- Not the W-Stack's own test vectors: the wallet stack's exact claim paths and status-list type
  are confirmed against its deployment, and the cases follow when they differ.
- Not the legacy set in [`features/fixtures/xfsc/`](../xfsc/README.md), which predates the
  profile and is kept for the scenario decisions and the wallet storage proof.
