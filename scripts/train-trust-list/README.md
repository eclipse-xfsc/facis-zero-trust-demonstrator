# train-trust-list

`reconcile.sh` makes one trust framework's TRAIN trust list follow the file that declares it
(`deployment/train/trust-lists/<framework>.json`, contract
[`train-trust-list.v1`](../../docs/contracts/train-trust-list.v1.schema.json)): the issuers the
framework trusts, one entry each, and the zones that claim it. The file changes by pull request;
the script writes the difference to the TSPA and proves it by reading the list back. The page is
[TRAIN trust lists](../../docs/train-trust-lists.md); the API it writes to is
[TRAIN trust-list publishing](../../docs/tspa-publish-api.md).

## Actions

| Action | Calls | Exit 0 when |
|---|---|---|
| `validate --file FILE` | nothing | the file satisfies the contract and its own rules (unique ids and lookup keys, zones declared) |
| `diff --from OLD --to NEW` | nothing | both files satisfy the contract (exit 2 otherwise); prints the change in words, one line per issuer or zone, for the pull request |
| `plan --file FILE` | `GET` the list | the plan was computed: what `apply` would create, replace, delete, in words on stderr and in the evidence line; exit 1 on a conflict or a duplicate |
| `apply --file FILE [--with-zones]` | `PUT`/`PATCH`/`DELETE` entries; with `--with-zones` `PUT /trustframework/{fw}` and `dig` for each PTR | the read-back shows the list follows the file (and each zone's PTR names the framework) |
| `verify --file FILE` | `GET` the list | the list follows the file; exit 1 otherwise (`drift`, or what stopped the plan: `conflict`, `unowned-entry`, `duplicate-entry`, `list-missing`, `tspa-error`, `transport-failure`) |

**What it owns.** Every entry it writes carries `{Type: managed-by, Value: train-trust-list/<framework>}`
in `TSPEntityIdentifierList`. It deletes only entries with that marker whose issuer left the file,
replaces only entries with that marker, and creates only where no entry exists; an entry under one
of its UUIDs that lacks the marker (someone took it over, or another writer derived the same UUID)
is `unowned-entry`, refused before any write. The pipeline's measurement entries
([train-publish](../train-publish/README.md)) and the client's own entries are never touched.
An entry's UUID is a UUID v5 of the framework and the issuer `id`, the same on every run: the first
write is a `PUT`, every later one a `PATCH` of that entry, and the live entry's `StatusStartingTime`
is kept so a change of text is not a new start. Renaming an issuer's `id` is a removal and a
creation; deletes run first, so a lookup key handed from the old id to the new is never held by two
entries at once.

**Conflict.** An issuer whose `serviceTypeIdentifier` another live entry already holds is refused
before anything is written: the TCR returns one entry per lookup key and does not say which. The
file is wrong whether that other entry is the pipeline's or the client's.

**The HTTP status is not the proof.** A `200` with an empty body is a write the TSPA did not run
(`write-unconfirmed`); after the writes the list is read again and planned again, and only an empty
plan is `applied`. When a writer races the reconciler between its read and its write (a `PUT`
answered "already exists", a `PATCH` answered 404), it reads and plans once more and writes what is
left (docs/tspa-publish-api.md, 7.1). The TSPA verified (`ecd5fdc`) answers a `PATCH` or a `DELETE` of
a UUID that is not in the list with 200, removing nothing and, for the `PATCH`, adding the entry
(`TrustListPublicationServiceImpl.tspUpdationLocalStore`: delete, then add); the 404 branch is for the
stand-in and for a version that is stricter.

## Configuration

| Variable | Meaning |
|---|---|
| `TSPA_URL` | the TSPA base URL up to its context path, e.g. `http://host:16003/tspa-service` |
| `OIDC_TOKEN_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | `client_credentials` at the issuer the TSPA trusts; the client's service account holds the realm role `enrolltf` (apply only) |
| `TSPA_TOKEN_FILE` | instead of the three above: a file with a bearer token already obtained |
| `TRAIN_DNS_SERVER` | with `--with-zones`: the name server `dig` asks for the PTR records |
| `TRAIN_TRUST_LIST_TIMEOUT` | seconds per HTTP call (default 30) |
| `TRAIN_TRUST_LIST_TEMPLATE` | another entry template (default `entry.tmpl.json`) |

The framework is the file's; the list is created once at federation setup, never here. The token
travels in a header file and the secret in a request body file, both under the run's private
temporary directory; neither appears on a command line, in a log or in a record.

## What a run leaves

`--out DIR` (default `.dev/train-trust-list`, git-ignored): `reconciliations.jsonl` gets one line per
run, `last/` the requests sent, the lists read and the VC. The same line is printed to stdout as
`EVENT_JSON=<json>`:

| Field | Meaning |
|---|---|
| `action`, `outcome` | `plan`/`apply`/`verify`; `planned`, `applied`, `converged` (nothing to write), `verified`, or why not: `drift` (verify: the list differs), `conflict`, `unowned-entry`, `duplicate-entry`, `list-missing`, `token-failed`, `write-rejected` (400, 401, 403), `write-unconfirmed` (200 with an empty body), `target-missing` (404 on a write), `transport-failure`, `tspa-error`, `not-converged` (the read-back still differs), `zones-not-published` |
| `source` | the file's path and sha256, the commit that last touched it and whether it had uncommitted changes (null outside a repository) |
| `plan` | the plan `apply` executed (for a failed read-back, the plan the read-back still showed): ids created, replaced, unchanged; UUIDs deleted; conflicts with the key and the entries holding it; duplicates; unowned entries; `converged` |
| `writes` | each write's method, UUID, status and the sha256 of the answer, in order |
| `zones` | with `--with-zones`: the domains requested, the status of `PUT /trustframework`, the domains whose PTR answered |
| `readBack.listSha256`, `readBack.vcHash`, `readBack.elapsedSeconds` | the list read back, the hash inside the signed VC, the seconds from the first write to the read-back; the read-back comes before the zones, so `zones-not-published` still carries a proven list |

Exit status: 0 proven (verify: the list follows the file), 1 not proven, a conflict, drift or an
unreachable TSPA, 2 a file or configuration refused before anything is called.

## Tests

```sh
scripts/train-trust-list/reconcile_test.sh
```

Against `fake_tspa.py` from `scripts/train-publish`, the stand-in with the API's write semantics,
now also answering `PUT /trustframework/{fw}` (500 for a scheme starting with `nozone`, a zone
manager the TSPA cannot reach). The cases are the ones the page lists; `dig` is stubbed. Needs bash,
curl, jq, python3 and sha256sum; seconds, no cluster, no network beyond localhost. The proof
against the real TSPA on kind is [`scripts/verify-train-trust-list/`](../verify-train-trust-list/README.md).
