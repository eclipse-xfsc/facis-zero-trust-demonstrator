# Trust-list reconciliation against the real TSPA: evidence

Run of `scripts/verify-train-trust-list/verify.sh` on 2026-11-18T20:35:49Z against upstream's TSPA `ecd5fdc` built from its Dockerfile, on kind. The reconciler the run used: `reconcile.sh` sha256 `098509260956fa5f7ddae69be0f618ab9de10007c064e92c08ab719cba4cd12a`, `desired_state.py` sha256 `1becbd5d645b5e731d39d2cd16b06c89c2bc6492901156b702162699d675cd41`. Raw records: the `--out` directory (per step: stdout, stderr, requests and lists; `reconciliations.jsonl` with every evidence line of the run).

## Summary of the steps

| Step | Expected | Outcome | Exit |
|---|---|---|---|
| plan v1 | planned, two creates, no write | `planned` | 0 |
| apply v1 | applied, two PUTs | `applied` | 0 |
| apply v1 again | converged, no write | `converged` | 0 |
| apply v2 (renamed) | applied, one PATCH | `applied` | 0 |
| apply v3 (removed) | applied, one DELETE | `applied` | 0 |
| verify v3 | verified | `verified` | 0 |
| verify v2 after v3 | drift | `drift` | 1 |
| verify after the edit | drift | `drift` | 1 |
| apply after the edit | applied, one PATCH | `applied` | 0 |
| apply v4 (conflict) | conflict, nothing written | `conflict` | 1 |
| apply with testuser's token | write-rejected (403) | `write-rejected` | 1 |
| apply --with-zones | zones-not-published | `zones-not-published` | 1 |

**Verdict: all 43 checks passed.**

## 1. The TSPA, Keycloak and the lanes to them

- PASS: Keycloak reached through the port-forward issues tokens under the in-cluster name the TSPA validates
- PASS: the TSPA answers through the port-forward (GET /api/docs 200)
- PASS: the operator's token (service account of xfsctest) carries the realm role enrolltf
- PASS: testuser's token is valid but its realm roles lack enrolltf
  operator token claims: `{"iss": "http://keycloak:8080/realms/gxfs-dev-test", "azp": "xfsctest", "realm_roles": ["enrolltf", "offline_access", "uma_authorization", "default-roles-gxfs-dev-test"]}`; testuser: `{"iss": "http://keycloak:8080/realms/gxfs-dev-test", "azp": "xfsctest", "realm_roles": ["offline_access", "uma_authorization", "default-roles-gxfs-dev-test"]}`
## 2. The trust list exists before anything is reconciled

The operator creates it once with the kit's payload (`scripts/verify-tspa-api/payloads/trustlist-init.json`); the reconciler never does. A list left by an earlier run is removed first, so the run is repeatable.

- PASS: the trust list of facis-ztd.local is created by the operator (PUT init, 201)
- PASS: the list has no entry
  the empty list's VC hash: `QmWDJcgM5nnRFs3vC3CQEB7iLb9RbvuQsh4HNZGqh4wDXo`
## 3. The repository's file, applied as it is

`deployment/train/trust-lists/facis-ztd.local.json` declares two issuers for the framework `facis-ztd.local`. `plan` says what `apply` would write and writes nothing; `apply` writes it and reads the list back.

- PASS: plan: exit 0, outcome planned, two creates
- PASS: plan: the list is untouched

```
+ create issuer-a (did:web:issuer-a.facis-ztd.local) as c7d4af67-412e-594d-9437-f0b64453812c
+ create issuer-b (did:web:issuer-b.facis-ztd.local) as 9e031244-fd58-5a57-96b9-9885ca279894
```

- PASS: apply v1: exit 0, outcome applied
- PASS: apply v1: two PUTs answered 201
- PASS: apply v1: two entries, under the UUIDs the file derives
- PASS: apply v1: the entries carry the managed-by marker and the issuers' lookup keys
- PASS: apply v1: the source names the copy applied here and its sha256 (the copy is outside version control: no commit)
- PASS: plan of the repository's file: the evidence names the commit that last touched it and that it has no uncommitted changes
  source of the repository's file: `{"sha256":"2cc1230b932f5513354d8f07a1d553de7b6d5d090ef364fb50fed0cf91d99a42","commit":"8aca66c77051b0089dc1540f47500a4b1ee66500","uncommittedChanges":false}` (the commit is the one that last touched the file when the proof ran; the commit that ships this evidence comes after it)
- PASS: apply v1: the read-back carries the list's sha256 and the VC's hash
- PASS: apply v1: the signed VC the TCR consumes changed (its hash is the list's)
  evidence line: `{"outcome":"applied","plan":{"create":["issuer-a","issuer-b"],"replace":[],"delete":[]},"writes":[["PUT",201],["PUT",201]],"readBack":{"listSha256":"8b643ae354d841851cf950e77b21fd6bfecc7210fae7fd7bb02bf32a300d338b","vcHash":"QmXin2KDnonA4CAzoAZ8pS25SVgszRwQsxCMJbJiY92pAW","elapsedSeconds":0.103}}`
- PASS: apply v1 again: exit 0, converged, no write, the VC unchanged
## 4. The pipeline publishes a measurement entry into the same list

The publisher (`scripts/train-publish/publish.sh`) writes the connector's entry under its own UUID, without the reconciler's marker. The record is synthetic here (the measuring step is not part of this proof); what matters is that an entry the reconciler does not own sits in the list from now on.

- PASS: the publisher's publication is proven (exit 0, published)
- PASS: three entries: two issuers and the connector
- PASS: the connector's entry carries no managed-by marker
  the connector's entry: UUID `40888e80-0b00-5523-b9c6-4491d3cf4c55`, lookup key `did:web:connector-b.facis-ztd.local`
## 5. A pull request renames an issuer


```
~ issuer issuer-b: name changed
```

- PASS: rename: exit 0, applied, one PATCH of issuer-b's entry
- PASS: rename: the name changed, the UUID and the start time did not
- PASS: rename: the connector's entry is byte for byte what it was
- PASS: rename: the VC hash moved
## 6. A pull request removes an issuer


```
- issuer issuer-b (did:web:issuer-b.facis-ztd.local): its entry is removed; a verifier that cached the list keeps trusting it until the window closes
```

The entry is deleted and the list read back; the time between the first write and the read-back is the part of the window this side controls. What a verifier still trusts after that is bounded by its own cache: 300 s for the trust list (docs/architecture.md, staleness matrix), plus the lifetime of a channel already open.

- PASS: removal: exit 0, applied, one DELETE of issuer-b's entry
- PASS: removal: two entries remain, issuer-a's and the connector's
- PASS: removal: nothing in the list answers to the removed issuer's lookup key
- PASS: removal: the connector's entry is byte for byte what it was
- PASS: removal: the signed VC changed, so a TCR fetching it now gets a list without the issuer
- PASS: removal: the read-back proved the removal within the documented window (0.069s of 300s)
  first write to read-back: 0.069s; the documented window for a verifier's cached copy is 300s, plus a channel's lifetime
- PASS: verify: the list follows the file (exit 0, verified, no write)
- PASS: verify against the previous file: drift, exit 1, naming what apply would create
## 7. An entry edited by hand

Someone with the role changes issuer-a's entry directly. `verify` sees the drift; `apply` writes it back as the file says.

- PASS: the entry is edited by hand (PATCH 200)
- PASS: verify after the edit: drift, replace issuer-a
- PASS: apply after the edit: one PATCH, the name is the file's again
## 8. A pull request names a lookup key the connector's entry already holds


```
+ issuer issuer-b (did:web:issuer-b.facis-ztd.local): a new entry; verifiers trust it once their copy of the list refreshes
+ issuer rogue (did:web:connector-b.facis-ztd.local): a new entry; verifiers trust it once their copy of the list refreshes
```

- PASS: conflict: exit 1, outcome conflict, naming the issuer, the key and the entry that holds it
- PASS: conflict: nothing was written; the list is byte for byte what it was

```
! conflict: rogue names the lookup key did:web:connector-b.facis-ztd.local, already held by 40888e80-0b00-5523-b9c6-4491d3cf4c55 which the file does not own
outcome: conflict (the list does not follow <out>/files/v4-conflict.json; nothing is proven)
```

## 9. A token without the role, a write without a token

- PASS: testuser's token: exit 1, write-rejected, the TSPA answered 403, nothing changed
- PASS: a PATCH without Authorization is answered 200 with an empty body and stores nothing (docs/tspa-publish-api.md 5)
## 10. The zones, on a TSPA whose zone manager is unreachable

The kit runs no zone manager (docs/tspa-publish-api.md 8), so `PUT /trustframework` cannot publish the PTR records. The reconciler reports exactly that, after the issuers were reconciled and read back, and does not claim the zones.

- PASS: zones: exit 1, zones-not-published, none proven, the PUT recorded
- PASS: zones: the entries were read back before the zones were tried (the line carries the list's sha256)
  PUT /trustframework/facis-ztd.local answered 500; the PTR records for `zone-a.facis-ztd.local, zone-b.facis-ztd.local` were asked from `127.0.0.1`, which does not serve them
## 11. No secret in any record

- PASS: the client secret appears in no step output, record or request kept
- PASS: no bearer token appears in any step output, record or request kept
