# TRAIN publication step

Before an attested component rolls out, its reference measurement is published into TRAIN; once
the rollout has converged, the entry is pruned back to that one value. ZT-35 makes this a pipeline
duty: a peer resolves the expected measurement from TRAIN the moment the new version serves
traffic, and a value it cannot find is a refused connection, not a degraded one. This page is the
step as it exists: what travels, where it is written, how a deployment is gated on it, what the
proofs show and what still waits on the client. The write API it rests on is
[TRAIN trust-list publishing](tspa-publish-api.md); what is published, in what form and under which
key is [ADR-0011](adr/0011-mock-tee-evidence-format-and-provisioning.md), 4.2 and 4.3.

## The chain

```text
measuring step            publisher (publish)         lifecycle step              publisher (prune)
measures the component    reads the record,           server dry-run,             writes the record's
as it will run, writes    writes {old, new} into      helm upgrade --wait         value alone, reads
a measurement record      the entry, reads it back    (both versions run)         it back
        │                        │                           │                          │
        ▼                        ▼                           ▼                          ▼
   record.json ──────────▶ TRAIN entry {old,new} ──────▶ new pods ready ──────▶ TRAIN entry {new}
                                                      a peer's TCR resolves the entry at any point
```

The TRAIN entry changes before the pods and again after them, and every change is read back
before it is believed. A publication that cannot be proven stops the deployment before Helm runs
anything, so TRAIN never lacks the value of a version that runs. The other direction, TRAIN
accepting a value that is not running yet or no longer, is the union every rollout passes through;
it outlives the rollout only when Helm fails after a proven publication or a prune is not proven,
both reported, and the next proven publication prunes it.

## The record

The publisher measures nothing. It consumes a
[measurement record](contracts/measurement-record.v1.schema.json) the measuring step writes:
component, zone, the connector's `serviceTypeIdentifier`, the image by digest, and the measurement
(`TEEM-sha256`, the CMC template hash with its `configSha256` and `rootfsSha256`), with the commit
and tool that produced it. Two values in one record are the same thing seen from two sides: the
image digest names the bytes admission admitted, the measurement is what the component reports in
its evidence, and only the pipeline that produces both ties them together (ADR-0011, open items).
On `main` nothing measures the real images yet; the determinism check's fixture is the only real
measurement, and producing records for the components is the measuring side's work.

## The entry

One entry per endpoint, under a UUID v5 derived from the zone and the component, so the first
publication is a `PUT` and every later one a `PATCH` of the same entry; the list never accumulates
stale entries and the verifier never has to guess which is current. The measurement rides in
`TSPInformation.TSPCertificationList.TSPCertification` as `{Type: TEEM-sha256, Value: <hex>}`, one
pair per value in force; `{Type: image-digest, Value: sha256:…}` pairs follow the same rule, so a
reader can tie the entry to the image a pod reports. `ServiceTypeIdentifier` carries the
connector's identifier, the field the TCR matches. `publish` writes the union of the values already
there and the record's; `prune` writes the record's alone; `verify` only reads back. Details,
outcomes and configuration: [scripts/train-publish](../scripts/train-publish/README.md).

## The gate in the lifecycle step

`scripts/lifecycle.sh` runs every release: server-side dry-run, then
`helm upgrade --install --rollback-on-failure --wait`. With `LIFECYCLE_PUBLISH_RECORD` naming a
record, two steps join it:

| When | Step | On failure |
|---|---|---|
| after the parameters are validated, before the dry-run | `publish` | the deployment fails before Helm runs anything: `publishNotProven` (the read-back did not prove it, or the TSPA could not be reached), `publishRefused` (the publisher refused the record or its configuration, or the record file does not exist), `systemError` (the publisher is not installed beside the script). No failure names a field: the record is the script's environment, not a field of the command |
| the dry-run or the upgrade fails after a proven `publish` | — | `dryRunRejected`, `valuesSchemaRejected` or `deployFailed` as before, the message adding that the TRAIN entry keeps the previous and the new measurement; the entry accepts both, as during a rollout, until the next proven publication prunes it or an operator does |
| after the release is ready | `prune` | `pruneNotProven`: the release stays deployed and ready and the result still carries its revision and inventory; the entry was not proven pruned (it may hold both values, or the read-back alone may have failed), and the step reports a failure so the leftover is seen and `prune` is run again |

An uninstall leaves the TRAIN entry as it is: removing a component's measurement from TRAIN is an
operator's decision, not a side effect of removing a release (the publisher has no delete). The
zone installer runs every release through the same script with the environment it inherits, so
`LIFECYCLE_PUBLISH_RECORD` is set for the one deploy it describes, never exported around the
seven releases of a zone.

Both steps appear as `EVENT_JSON` progress (`publish`/`prune`, `running`/`succeeded`/`failed`),
and the publisher's evidence line for each lands in `RESULT_JSON` under `publication.publish` and
`publication.prune`, on a failed result too, since a publication that was not proven is the reason
for it ([result schema](lifecycle-result.schema.json)). The `ztd-lifecycle` node relays the field.
The publisher's own variables (`TSPA_URL`, `TSPA_FRAMEWORK`, `OIDC_TOKEN_URL` with
`OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`, or `TSPA_TOKEN_FILE`) come from the environment the
script runs in; the node passes its process environment through, so today the record and the TSPA
parameters are the lifecycle node's environment, not a field of the deploy command. A per-command
record is a later change of the node's contract. The ORCE image ships the publisher beside the
lifecycle script (`/opt/ztd/scripts/train-publish/`); a script installed without it reports
`systemError` rather than a publication that was not proven.

A prune that fails leaves the safe direction of error: the entry accepts the version that was
approved before as well as the new one, which is what it did during the rollout. The failure is
reported rather than swallowed because ADR-0011 does not want that union to become permanent.

## What the proofs show

| Proof | Runs | Holds the step to |
|---|---|---|
| `scripts/train-publish/publish_test.sh` | the `TRAIN publication step` job of the CI workflow, every pull request; seconds | every outcome of the publisher against a stand-in that copies the API's write semantics and validates entries against upstream's entry schema; stable UUIDs; the union during a rollout; both race directions; no secret in any output |
| `scripts/lifecycle_test.sh` | `train-publish.yml`, when the step or its inputs change; seconds | without a record nothing changes; `publish` proven before the dry-run and `prune` after the release is ready, both evidence lines in the result; a publication not proven or refused stops the deployment before Helm; a prune not proven is `pruneNotProven` with the release deployed |
| `scripts/verify-train-publish/verify.sh` | `train-publish.yml` on kind (the TSPA image cached per upstream commit); locally, [`evidence.md`](../scripts/verify-train-publish/evidence.md) is the last run | against upstream's real TSPA: two real measurement records (same rootfs hash, another configuration hash), the publisher gating a stand-in's rollouts through the induced days of `matrix.tsv`; every ready pod's `imageID` equals the published digest and the `config.json` inside it is the file measured |

What the last row can claim, and no more: the value in TRAIN is the one computed for the image
and the configuration that are running. The running container is not measured; nothing in the
attestation component triggers that, and the ADR leaves it as an item to raise with the client.

## Status

| Done when | Proven where | Still needs |
|---|---|---|
| Each attested component publishes its expected measurement to TRAIN before it rolls out | on kind, with a stand-in component and real measurements of the fixture bundle (`verify-train-publish/evidence.md`) | measurement records for the real components (the measuring side); the client's TSPA |
| The pipeline step gates the rollout on the publication | `lifecycle.sh` with the stand-in (`lifecycle_test.sh`); the same two steps around real rollouts on kind | a release deployed with `LIFECYCLE_PUBLISH_RECORD` set, once a component has a record; the record as a field of the lifecycle command in the ORCE node |
| The published digest matches the running image | on kind: pod `imageID` equals the published digest, the configuration inside the pod is the one measured | the same check on the components once they carry records |
| The read side resolves the entry and compares | — | the attested-channel work (ZT-64, ZT-67): the TCR lookup and the comparison; the agreement on the carrier and the lookup-key string |

After the merge the ticket stays blocked, not done, until the client's instance confirms the
rows below.

## For the client

Nothing here is specific to kind: the TSPA base URL, the framework, the OIDC client and the
token endpoint are configuration. To run the step against the client's TRAIN, the following is
needed, in the order it blocks:

1. The TSPA base URL (up to its context path) and the trust framework whose list carries the
   demonstrator's entries; whether the list exists, or who runs `PUT /init/json/{fw}/trust-list`
   once (the publisher never does).
2. An OIDC issuer the TSPA trusts and a confidential client for the pipeline whose service account
   holds the realm role `enrolltf` (a client role is not read); the token endpoint's URL and the
   client's credentials delivered as secrets, never in a file of this repository.
3. Confirmation that the instance runs the TSPA version verified here (commit `ecd5fdc`), or the
   differences in paths and schema.
4. Reachability of the TSPA from where the lifecycle step runs, and of its Zone Manager, which
   `PUT /trustframework` and `/actuator/health` depend on.
