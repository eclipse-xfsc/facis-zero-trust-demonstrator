# Attestation evidence provisioning

The demonstrator has no TEE hardware, so each zone's attestation evidence comes from CMC's software
driver ([ADR-0011](adr/0011-mock-tee-evidence-format-and-provisioning.md)). This page is how that
evidence is provisioned (ADR-0011's class 3, ZT-31, ZT-63): its measured values and its reference
values both come from one file per zone in Git, the reference values are signed in the pipeline and
served by the zone's `estserver`, and the zone's `cmcd` signs evidence over the measured values. A
measurement changes only through a reviewed change to that file.

## The source in Git

`deployment/attestation/<zone>.json`, one file per zone:

| Field | Meaning |
|---|---|
| `zone` | the zone, a DNS label; it must match the file name |
| `validity_days` | how long signed metadata stays valid from its signing, 1 to 365 |
| `components[].name` | a measured container, a DNS label, unique in the zone |
| `components[].rootfs_sha256` | the digest of its root filesystem, 64 lower-case hex digits |
| `components[].oci_config` | its OCI runtime configuration (`ociVersion` and `process.args` required, unknown fields refused) |

The component in each file is the zone's attested-channel gateway. Its image is not built yet, so
its `rootfs_sha256` is a mock value, the SHA-256 of the text
`facis-ztd <zone> atls-gateway rootfs 1`, recomputable by anyone. When the gateway image exists, the
value becomes the digest of its root filesystem.

## From the file to the evidence

| Step | Tool | Output |
|---|---|---|
| 1. Render | `attestation-provision render --zone FILE --out DIR` | `unsigned/manifest.json` (reference values: each component's rootfs digest and OCI configuration, trust anchor `SW`), `unsigned/image-description.json`, `measurements.json` (the container measurement log), `expected.json` (each template hash and the aggregate) |
| 2. Sign | CMC's `metatool sign`, pinned with CMC | the signed manifest and image description, JWS with the signer's chain |
| 3. Serve | the zone's `estserver`, `httpFolder` | the signed metadata over TLS at `https://<estserver>/metadata-signed/` |
| 4. Attest | the zone's `cmcd`: `metadata` the URL above, `ctr: true`, `ctrDriver: sw`, `ctrLog` the measurement log | evidence signing `sha256 = extend(…extend(0³², template₁)…, templateₙ)` |
| 5. Check at startup | `attestation-provision check --zone FILE --cmcd ADDR --ca FILE` (`provision.Check`) | a fresh report from the zone's `cmcd`, verified against the metadata CA; its verified template hashes and signed aggregate must be those the file gives |

A component's template hash is `sha256(configSha256 ‖ rootfsSha256)`, with `configSha256` computed
by CMC's own `verifier.CalculateSpecHash`; the render step uses CMC's types and hashing
(`internal/atls/provision`), so its output is what CMC's verifier recomputes. The template hash is
the value ADR-0011 § 4.1 publishes into TRAIN. CMC's runtime measurement of a real container
normalises its configuration first (it removes or rewrites fields such as `hostname` and `root`),
so the hash of a configuration in these files is not the hash a runtime would produce for the same
raw configuration; a real gateway image will need its reference configuration taken from such a
measurement.

Two components with the same measurement are refused when the file is loaded: CMC matches events to
reference values by measurement and names a verified event after the first reference that matches,
so the two could not be told apart.

Step 5 is what a zone's gateway does before it serves: it does not trust its own `cmcd` to verify
itself, it verifies the report against the metadata CA in process and requires the measured values
to be those in Git: every verified event, each template hash, and the aggregate the evidence
signs, read from the verified evidence with CMC's own JWS parser. The caller bounds the wait for
`cmcd` (the command defaults to 30 s). The command exits 0 on success, 2 when a report was obtained
and rejected, and 3 when no report could be obtained.

`cmcd` falls back to its cached metadata when the `estserver` cannot be reached. In a lasting
deployment, evidence can then still verify with cached metadata that has not expired: the check
establishes that the metadata is valid and signed by the metadata CA, not that it is the newest the
pipeline signed. The proof clears the cache before every start, so its fetches come from the
`estserver`.

## Proof, repeatable from zero

`scripts/attestation-provision/prove.sh` starts from an empty directory: it builds `cmcd`,
`estserver` and `metatool` at the CMC version `go.mod` pins, creates a throwaway PKI (metadata CA and
pipeline signer, EST CA and the `estserver` TLS certificate, all ECDSA P-256), and for every zone
file runs steps 1 to 5 with one `estserver` and one `cmcd` per zone as plain processes. Then:

- the first zone's rootfs digest is changed as a commit would change it, the zone is provisioned
  again, and the signed aggregate differs; the new evidence passes the startup check against the
  changed file and fails it against the original;
- the zone's reference values are signed by a key outside the metadata CA, and the startup check
  obtains the report and rejects it as a failed verification; a fresh report over the same
  metadata passes when that signer's CA is trusted instead, so the refusal is the CA's doing.

Each refusal must come with a report (exit status 2) and the expected reason, so an unreachable
`cmcd` cannot pass for a refusal.

The `estserver` serves the metadata and accepts no enrolment: enrolment needs a token and the token
store is empty. The software driver needs none; it creates its own key.

The workflow `.github/workflows/attestation-provision.yml` runs the package's unit tests and the
proof on every pull request that touches them, and uploads the run's records.

## Not covered here

- **The gateway's own check and its deployment** are on their page,
  [Attested-channel gateway](atls-gateway.md): the gateway calls `provision.Check` at startup with
  the configuration file the zone installer takes from Git, and the attester runs in the management
  plane from the pipeline-signed material handed to it as a Secret (`deployment/helm/cmcd`), reading
  the signed metadata from files; the `estserver` stays a step of the pipeline and of this proof, not
  a workload of the zone.
- **The pipeline's signing key.** The proof and the workflow sign with a key created for the run.
  Where the pipeline's long-lived metadata signing key is held, and how the zones receive the
  metadata CA, is not decided here.
- **TRAIN.** Publishing the template hash into the trust list (ADR-0011 § 4) is a separate step.
- **Real measurement.** Nothing measures a running container: the measurement log is rendered from
  Git, which is what makes the evidence a mock.
