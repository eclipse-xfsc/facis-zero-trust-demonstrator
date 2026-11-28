# verify-train-publish

Proof of the TRAIN publication step ([`scripts/train-publish/publish.sh`](../train-publish/README.md))
against the real TSPA, on kind: upstream's image built from its Dockerfile at the pinned commit,
upstream's Helm chart and test realm, all from the kit under
[`scripts/verify-tspa-api`](../verify-tspa-api/README.md). The publisher runs on the host, through
port-forwards, the way the pipeline will run it against the client's instance: a token from the
issuer the TSPA trusts, the trust list read and written over HTTP, nothing inside the cluster
but the TSPA, Keycloak and the component.

```sh
TSPA_REPO=/path/to/train-trust-framework-manager scripts/verify-train-publish/verify.sh
```

Needs `kind`, `kubectl`, `helm`, `docker`, `curl`, `jq`, `python3`, `sha256sum`, `git` and `go`
(the measurement step builds the attestation component's code). The first run builds the TSPA
image, about fifteen minutes; later runs reuse it and take about three. `TSPA_REPO` is the clone the
kit documents, with `train-shared` in its `shared/`. The evidence goes to `evidence.md` next to the
script (`TRAIN_PROOF_EVIDENCE` moves it), the raw records of the run to `.dev/train-publish-proof`
(`--out DIR` moves them), the attestation component's checkout to `.dev/cmc`
(`TRAIN_PROOF_CMC_WORK`). The exit status is non-zero when any check failed.

## What one run does

1. **Two real measurement records.** `tools/measurement-determinism/measure-with-cmc.sh` measures
   the fixture bundle with the attestation component's own code at its pinned commit, twice: as it
   is, and after one value of `config.json` changed. The records name the stand-in's image by
   digest. The rootfs hash is the same in both, the configuration hash and the TEEM value differ:
   the change the story has, a new version with the same image.
2. **The trust list exists before anything is published.** The operator creates it once with the
   kit's payload; the publisher never does (`list-missing` otherwise).
3. **A stand-in component** (`stand-in.yaml`): one pod from the image pinned by digest, mounting
   the measured `config.json` from a ConfigMap, twenty seconds to readiness so both generations
   run at once long enough to be observed.
4. **The gate, for every row of `matrix.tsv`.** `publish` with the record; only when it exits 0,
   the rollout to the record's version, then `prune` once it has converged. The induction changes
   the publisher's environment for the publish step alone.

| Row | Day of the story | Induction | Expected |
|---|---|---|---|
| `first-publication` | normal day | none; no entry, no pods | `published`, a `PUT`, rollout converges, prune leaves `{v1}` |
| `wrong-secret` | day 2 | wrong `OIDC_CLIENT_SECRET` | `token-failed`, exit 1, no write, rollout not started, pods and list unchanged |
| `token-without-role` | day 2 | a valid token whose realm roles lack `enrolltf` | `write-rejected` (403), rollout not started |
| `malformed-token` | day 2 | `not.a.jwt` | `write-rejected` (401), rollout not started |
| `lane-closed-refused` | day 5 | a closed port | `transport-failure` within the timeout, rollout not started |
| `lane-closed-blackhole` | day 5 | a black-holed address, 5 s timeout | `transport-failure` within the timeout, rollout not started |
| `new-version` | normal day, days 3 and 4 | none; the second record | `published`, a `PATCH` of the same entry with `{v1, v2}`; while the old pod runs and the new one is not ready, the entry carries both; prune leaves `{v2}` |
| `republish-same` | day 3 | none; the same record again | `published`, a `PATCH`, the set unchanged, still one entry |

After the matrix: `verify` of the current record passes and `verify` of the pruned one fails
(`not-published`); a `PATCH` sent without `Authorization` is still answered 200 with an empty body
and stores nothing (docs/tspa-publish-api.md 5), re-observed with curl because the publisher cannot
be made to omit the header; and no secret, token or JWT appears in any record, log or the evidence.

For every row that rolls out, the proof also checks what the ticket asks for, in the only form it
can be claimed: every ready pod's `imageID` is the digest the record names and the entry carries,
and the `config.json` inside the running pod is, byte for byte, the file the measurement was
computed over. The published value is the one computed for the image and the configuration that
are running; the running container itself is not measured (ADR-0011, open items).

## What it does not prove

- The client's TSPA: URL, framework, OIDC client and Zone Manager are still unanswered on the
  client's side; every parameter is configuration, nothing here is specific to kind.
- The lifecycle wrapper itself: the proof drives the same two steps around the rollout that
  `scripts/lifecycle.sh` runs with `LIFECYCLE_PUBLISH_RECORD`; the wrapper's own gate is held by
  `scripts/lifecycle_test.sh` against stubs, not by a rollout on kind.
- The TCR reading the entry: the lookup key is asserted on the list, not resolved through a TCR.
- A transport failure on the write itself (the lanes are closed before the first read).

`evidence.md` is the last local run. The kit's `keycloak.yaml` pins Keycloak's issuer to its
in-cluster name (`KC_HOSTNAME`), so a token requested through a port-forward carries the `iss` the
TSPA validates; the kit's own round trip is unaffected (it asked from inside the cluster, under
that name).
