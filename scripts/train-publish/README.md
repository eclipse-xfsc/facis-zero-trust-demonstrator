# train-publish

`publish.sh` publishes one attested component's reference measurement into TRAIN through the TSPA
trust-list API before the component rolls out, and prunes the entry back to the current value once
the rollout has converged. It is the pipeline step ZT-35 asks for, built on the API surface
[the TSPA page](../../docs/tspa-publish-api.md) verified and on what
[ADR-0011](../../docs/adr/0011-mock-tee-evidence-format-and-provisioning.md) decides is published,
in what form, and under which key.

The publisher measures nothing. It reads a
[measurement record](../../docs/contracts/measurement-record.v1.schema.json) the measuring step
wrote, publishes its value, and proves the publication by reading the trust list back.

## Actions

| Action | Writes | Proves |
|---|---|---|
| `publish --record FILE` | the entry with the **union** of the values already there and the record's, so a rolling update is accepted on both versions | the entry exists once, its lookup key is the record's, its values are exactly the union, its image digest is the record's |
| `prune --record FILE` | the entry with the record's value **alone**, once the rollout has converged | the same, with the single value |
| `verify --record FILE` | nothing | the record's value is published under the record's lookup key |

The entry's UUID is a UUID v5 of the zone and the component, the same on every run: the first
publication is a `PUT`, every later one a `PATCH` of that entry. The measurement rides in
`TSPInformation.TSPCertificationList.TSPCertification` as `{Type: TEEM-sha256, Value: <64 hex>}`,
one pair per value in force, next to `{Type: image-digest, Value: sha256:...}` pairs that follow the
same rule (both images run during a rolling update, so both digests are listed until `prune`); the
connector's identifier goes into `ServiceTypeIdentifier`, the field the TCR matches. Everything
else in the entry comes from `entry.tmpl.json`, which satisfies the TSPA's entry schema
(`tsp-schema.json`, a copy of upstream's `TSPSchema.json` at the verified commit).

**One writer per framework.** Every TSPA mutation rewrites the whole list with no version
precondition (docs/tspa-publish-api.md, 7.1): two pipelines publishing into the same framework at
once race. The script takes no lock, because a lock on one machine protects nothing across clusters;
the deployment flow that calls it runs one zone at a time.

**The HTTP status is not the proof.** A write the TSPA does not run (no usable token) is answered
`200` with an empty body and stores nothing, so an empty body is a failure on its own
(`write-unconfirmed`), and after every write the script reads the trust list again and asserts the
entry, the lookup key, the values and the digests; only that read-back makes the exit status 0. The
read decides between `PUT` and `PATCH`; when a writer races it, the script falls back once the other
way, as section 7.1 of the TSPA page asks. Any doubt (transport failure, a rejected write, a list
that does not exist, a read-back that differs) exits 1, so a deployment gated on this step does not
proceed.

## Configuration

| Variable | Meaning |
|---|---|
| `TSPA_URL` | the TSPA base URL up to its context path, e.g. `http://host:16003/tspa-service` |
| `TSPA_FRAMEWORK` | the trust framework whose list carries the entries; the list itself is created once at federation setup, never here |
| `OIDC_TOKEN_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | `client_credentials` at the issuer the TSPA trusts; the client's service account holds the realm role `enrolltf` |
| `TSPA_TOKEN_FILE` | instead of the three above: a file with a bearer token already obtained |
| `TRAIN_PUBLISH_TIMEOUT` | seconds per HTTP call (default 30) |
| `TRAIN_PUBLISH_TEMPLATE` | another entry template (default `entry.tmpl.json`) |

The token travels in a header file and the secret in a request body file, both under the run's
private temporary directory; neither appears on a command line, in a log or in a record.

## What a run leaves

`--out DIR` (default `.dev/train-publish`, git-ignored): `publications.jsonl` gets one line per
run, and `last/` the request sent and the lists read, with no token in them. The same line is
printed to stdout as `EVENT_JSON=<json>`, the line form `scripts/lifecycle.sh` relays as progress
(the wrapper owns the final `RESULT_JSON`), and is the publication's evidence record:

| Field | Meaning |
|---|---|
| `action`, `outcome` | `publish`/`prune`/`verify`; `published`, `pruned`, `verified`, or why not: `list-missing` (no trust list), `token-failed`, `write-rejected` (400, 401, 403), `write-unconfirmed` (200 with an empty body: the TSPA did not run the write), `target-missing` (404 on the write), `transport-failure`, `tspa-error`, `duplicate-entry` (the list needs repair), `not-published` (the read-back differs) |
| `uuid`, `serviceTypeIdentifier`, `image` | the entry, its lookup key and the image the value was measured for |
| `before`, `after` | the `TEEM-sha256` values found before and written (or expected) after |
| `tspa.method`, `tspa.status`, `tspa.bodySha256` | the write as the TSPA answered it |
| `readBack.listSha256`, `readBack.vcHash` | the list read back and, when served, the hash inside the signed VC the TCR consumes |

Exit status: 0 proven, 1 not proven or unreachable, 2 a record or configuration the script refuses
before calling anything.

## Tests

```sh
scripts/train-publish/publish_test.sh
```

`fake_tspa.py` stands in for the TSPA with the write semantics read from its source: every entry
validated against the real entry schema (`tsp-schema.json`; types and required fields are all it
constrains), create-only `PUT`, `PATCH` with a matching UUID, `404` without a list, `200` with an empty body for an unusable
token, `401` malformed, `403` without `enrolltf`, and a token endpoint that hands out a token with
the role, one without it, and one the write side ignores. The cases cover each outcome above, the stable
UUID, the old version still verifying during a rollout, a new image during a rollout, re-publishing
the same record (with a good token, and with one the TSPA ignores), a token already obtained, a
writer racing the publisher each way, a template the schema refuses, an unreachable TSPA, records
and configuration refused before any call, and that no secret or token reaches any output, the
stand-in's request log included. Not covered: a transport failure on the write itself. Needs bash 5, curl, jq, python3 and sha256sum; seconds, no
cluster, no network beyond localhost.

The proof against the real TSPA on kind, the publisher gating the rollouts of a stand-in component
through the days of the story, is [`scripts/verify-train-publish/`](../verify-train-publish/README.md);
its `evidence.md` is the last local run. `scripts/lifecycle.sh` runs the two steps around a deploy when
`LIFECYCLE_PUBLISH_RECORD` names a record ([docs/train-publish.md](../../docs/train-publish.md)).
