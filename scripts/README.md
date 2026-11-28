# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

| Script | What |
|---|---|
| `lifecycle.sh` | deploy or uninstall one Helm release: server-side dry run, then upgrade with rollback; the ORCE lifecycle node runs it |
| `install-zone/install.sh` | install, upgrade, render or uninstall a cluster from its zone file, each release through `lifecycle.sh`: a participant zone (ten releases, the telemetry collectors last) or the demonstrator cluster (the observability backends); `telemetry-client-certs` copies each zone's client certificate |
| `dev/kind-cilium-up.sh` | the local kind cluster with Cilium chained (`cni.exclusive=false`) |
| `dev/kind-cert-manager-up.sh` | cert-manager on kind (pinned), for the demonstrator role that shares the cluster |
| `verify-umbrella/verify.sh` | evidence for the umbrella chart alone on kind |
| `verify-train-allow-list/verify.sh` | the TRAIN allow list of the zone entry (ZT-18) on local Docker services: our TSPA image publishes a trust list naming one counter-connector; the listed one is served, an unlisted or withdrawn one refused, and every one refused while the TSPA is stopped ([TRAIN allow list](../docs/connector.md#train-allow-list-of-the-zone-entry-zt-18)) |
| `verify-tsa-policy/verify.sh` | the TSA policy proof on kind: allow under bundle v1, deny under v2 without restart, refused bundles, rollback, decision log ([TSA policy evaluation](../docs/tsa-policy.md#proof)) |
| `supplychain/publish-tsa-bundle.sh` | pack, sign, push and sign a Rego bundle for the TSA; prints its digest reference |
| `verify-mesh-identity/verify.sh` | evidence that the mesh identities are SPIRE's, the whole zone on kind |
| `verify-plane-separation/verify.sh` | executes the plane-separation allow matrix against an installed zone and attributes every refusal to its layer (network, mesh); `verify-plane-separation/plan.sh` the part that reads no cluster (rows, cross-check, probe plan, per-row decision), sourced; `verify-plane-separation/verify_test.sh` its offline cases |
| `verify-atls-gateway/verify.sh` | two kind zones, each a participant zone through `install-zone` with the attester (`ztd-cmcd`) and the attested-channel gateway (`ztd-atls-gateway`) built from the working tree and provisioned as the pipeline does: a call each way over the mutually attested channel with both ends' records compared, a plain-TLS stranger refused at the entry, the attester away and back, the configuration tampered and restored ([docs/atls-gateway.md](../docs/atls-gateway.md)) |
| `lib/` | sourced by the cluster proofs, never run: `proof.sh` (CI refusal, context guard, run directory, check accounting, redaction), `probe.sh` (placement, probes and outcome classes, denial log, Cilium reads, capture-rule lift, routing check), `doc-table.sh` (the heading-based reader of the architecture document's tables, shared with `check-plane-separation.sh`) |
| `verify-observability/verify.sh` | evidence that the observability stack collects, carries, stores and alerts within 30 s; kind, or a zone with the demonstrator cluster |
| `verify-observability/test-alert-rules.sh`, `check-rendered-images.sh` | the alert rules and the detection budget; the observability images pinned and licensed (no cluster, CI) |
| `verify-cni-chaining-upgrade/verify.sh` | evidence that the CNI chain (Istio after Cilium) survives a Cilium upgrade, from the zones' version to the pin, on a disposable kind cluster |
| `mesh-mode/check-upstream-state.sh` | the upstream-state record behind ADR-0009 and its reopen check |
| `ci/check-charts.sh` | the chart quality gate: lint, render and (release) server dry-run of every chart; `ci/check-charts_test.sh` its cases |
| `ci/check-policy-addresses.sh` | no address in a policy: renders the umbrella, `zone-policy` and `ztd-openbao` with every shipped zone file and the CI zone file and fails on any `ipBlock`, CIDR rule or address literal in a NetworkPolicy, CiliumNetworkPolicy or AuthorizationPolicy; `ci/check-policy-addresses_test.sh` its cases |
| `ci/check-policy-l7-owner.sh` | one L7 owner per path: the same renderings, failing on any Cilium policy with a port field that sends traffic to Cilium's L7 proxy (an `http`, `kafka`, `l7` or `l7proto` rule, `listener`, `serverNames`, `terminatingTLS`, `originatingTLS`), on any Cilium Envoy configuration and on any allow-matrix policy without its `ztd.facis.io/l7-owner`; `ci/check-policy-l7-owner_test.sh` its cases (the shared render path is `ci/render-zones.sh`) |

## Guard policy-hook proofs (`verify-policy-hook/`)

`verify-policy-hook/verify.sh` proves the behaviour of the guard's policy hook against a real
Envoy — the hook on `ext_authz`, with `ext_proc` as the config-only alternative. It builds and runs
`cmd/policy-hook-probe`: the echo upstream, the hook (deciding from the contract fixtures) and the
probe as plain processes, Envoy as one container from the image pinned in `tools/pins.env`. The
five proofs and what each passes on:

| Proof | Passes only when |
|---|---|
| On allow, header mutation substitutes the upstream credential | the upstream received the token store's `Authorization` and `DPoP` values and not the caller's, no `x-facis-*` or forwarding header, the trace context unchanged, and a request id the guard generated that the decision event carries as its correlation id |
| On deny, the caller gets the status, the headers and a JSON body with the reason code and the OID4VP link | each refusal carries the status the reason-code registry gives its code, `application/json`, `x-facis-reason-code`, a request id, and the fixture's error, reason code, rule and link |
| The same input set over `ext_proc` yields the same decisions; the switch is a change of the filter block only | status, headers, body and upstream headers are identical for every case, and the two bootstraps are identical outside the markers |
| The hook's added latency is measured | the three bootstraps — no hook, `ext_authz`, `ext_proc` — were measured at every concurrency with no error; the numbers are recorded, not judged |
| The filter fails closed and never hangs when the hook dies or stops answering under load | every request in the window ended; every request started after the strike was refused with 503 and `POL-PDP-UNAVAILABLE`; none outlived the timeout plus the margin; the restarted hook answered again with no manual step |

```sh
scripts/verify-policy-hook/verify.sh                 # writes .dev/policy-hook-evidence/ (about two minutes)
scripts/verify-policy-hook/verify.sh --out /tmp/run  # writes /tmp/run instead
scripts/verify-policy-hook/verify.sh --verify DIR    # runs nothing: checks the records already in DIR
```

It needs `go`, `git`, `jq`, `docker` and bash 5, and leaves the records, `verdict.txt` and
`environment.json` (commit, Go, the Envoy image and digest, the Envoy API and gRPC modules,
Docker, date, host kind) in the output folder, which git ignores; logs stay in a temporary
directory. On Linux the
container shares the host's network; elsewhere Envoy reaches the host processes through
`host.docker.internal` and its ports are published on `127.0.0.1`.

| Variable | Effect |
|---|---|
| `POLICY_HOOK_HOST_KIND` | what `environment.json` records the run as: `local` (default) or `ci` (default on GitHub Actions) |
| `POLICY_HOOK_ENVOY_IMAGE` | use this image instead of `ENVOY_IMAGE` from `tools/pins.env` |
| `POLICY_HOOK_PROBE_ARGS` | extra arguments for the probe, for example `--requests 500 --concurrency 1,8` |

No record is committed. The workflow `.github/workflows/policy-hook.yml` runs the script on every
pull request that touches the hook, uploads the records as an artefact and writes the verdict to
the job summary; those are the numbers of a Linux host. `envoy/` holds the three bootstrap
templates the probe renders.

## Attestation evidence provisioning (`attestation-provision/`)

`attestation-provision/prove.sh` provisions every zone's mock attestation evidence from its file in
`deployment/attestation/`, from zero: the pinned `cmcd`, `estserver` and `metatool`, a throwaway
PKI, one `estserver` and one `cmcd` per zone as plain processes, and the gateway's startup check
against each `cmcd`. It then changes one measurement and shows the evidence change, and refuses
reference values signed outside the metadata CA. Needs go, jq and openssl; `--out DIR` keeps the
records and logs. See [docs/attestation-provisioning.md](../docs/attestation-provisioning.md).

## Attested channel proofs (`atls-probe/`)

Three scripts prove the behaviour of the attested channel (`internal/atls`) between separate
processes and against real `cmcd` attesters. They run everything as plain processes on one machine
— no container, no cluster: two `cmcd` (one per zone, built from the CMC version `go.mod` pins) and
the probe `cmd/atls-probe`.

| Script | Proves | Passes only when |
|---|---|---|
| `atls-probe/prove-mutual-handshake.sh` | Two processes complete a mutually attested handshake and derive the same channel binding | both records show an established channel with verdict `success`, each end saw the expected peer, and both hold the same 32-byte binding |
| `atls-probe/prove-tampered-binding.sh` | A report bound to another TLS session is refused | a relay between client and server forwarded the attestation exchange, both ends refused with `ErrBindingMismatch`, and no application data crossed |
| `atls-probe/prove-session-loss.sh` | Session loss is recorded: server killed, client killed, `cmcd` killed with a channel open and during a handshake, server frozen (half-open) | every scenario ran from an established channel and left its findings, with one reconnect attempt each |

```sh
scripts/atls-probe/prove-mutual-handshake.sh                   # writes docs/evidences/cmc-atls-channel-binding/mutual-handshake/
scripts/atls-probe/prove-tampered-binding.sh
scripts/atls-probe/prove-session-loss.sh                   # about one minute
scripts/atls-probe/prove-mutual-handshake.sh --out /tmp/run    # writes /tmp/run/mutual-handshake/ instead
scripts/atls-probe/prove-mutual-handshake.sh --verify DIR      # runs nothing: checks the records already in DIR
scripts/atls-probe/summary.sh [DIR]              # the verdicts under DIR as a Markdown table
```

They need `go`, `git`, `jq` and bash 5. Each run:

1. builds `cmcd` and the probe into a temporary directory;
2. generates fresh fixtures there, valid for one hour — a CA, a certificate and key, signed
   metadata and a `cmcd` configuration per zone — with the env-gated test
   `TestWriteFixtures` of `internal/atls/atlstest` (`ATLS_FIXTURE_DIR`);
3. starts one `cmcd` per zone on a free port and checks that each produces reports with metadata
   that both verify (`TestCmcdReports`, `ATLS_FIXTURE_CMCD_CHECK`);
4. runs the probe processes and checks the proof on their JSON records;
5. writes the records, the logs, `environment.json` (commit, Go and CMC versions, date, host kind)
   and `verdict.txt` to the evidence folder, and removes the temporary directory with its keys.

The scripts stop every process they started, also when interrupted. In the copied logs the
temporary directory appears as `<work>` and the host name as `<host>`; private keys never leave the
temporary directory.

| Variable | Effect |
|---|---|
| `ATLS_HOST_KIND` | what `environment.json` records the run as: `local` (default), `ci` (default on GitHub Actions) or `target-cluster` |
| `ATLS_CMCD_BIN` | use this `cmcd` binary instead of building one |
| `ATLS_SESSION_LOSS_LIMIT` | seconds a surviving end is given to observe an error in `prove-session-loss.sh` (default 15) |
| `ATLS_KEEP_WORK` | keep the temporary directory, keys included, for inspection |

The evidence in the repository is produced by running the scripts locally and committing the
result. The workflow `.github/workflows/atls-channel-binding.yml` re-runs them with `--out` outside
the checkout to verify that the proofs reproduce; it never writes the committed evidence.

`lib.sh` holds what the three scripts share and is not run on its own.

## Token-store chart lifecycle and readiness (`verify-token-store/`)

`verify.sh` proves the token-store chart's lifecycle and the service's readiness on a throwaway
kind cluster: the image built from the working tree, a registry on the kind network, PostgreSQL
and OpenBao from the pinned images inside the cluster with the connection URL in a Secret; then an
install that applies the schema to an empty database and brings the service up ready; the service
not ready and still alive while PostgreSQL, then OpenBao, is gone, and ready again when each is
back; a caller's `x-request-id` and trace context on the service's records, every request record
correlated, no credential among them, no restart; the pod as its own ServiceAccount with the
identity label; an upgrade that changes nothing, an uninstall with `schema.dropOnUninstall` that
leaves the schema empty, and a default uninstall that keeps it; then, in runtime mode with a
least-privilege service token, the store's key custody: the key created in transit by `token-store
keys ensure` and registered by reference and thumbprint only, the thumbprint recomputed with
openssl, export refused, `keys rotate` retiring the previous version with transit no longer signing
with it, and readiness failing closed with OpenBao gone while no key material or token reaches the
database or the records. Records and the verdict go to `--out` (default the git-ignored
`.dev/token-store-evidence/`). Needs docker, helm, kind, kubectl, curl, jq and openssl; `BIN=` names
the directory `scripts/tools/install.sh kind kubectl` installed to. The
`Token store` workflow runs it on every change to the store, its image, its chart or the pinned
images. Design: [Token store](../docs/token-store.md).

## Token-store failure catalogue (`verify-token-store-failures/`)

`verify.sh` proves the token store's failure matrix on a throwaway kind cluster: the store from the
chart in runtime mode on PostgreSQL and OpenBao from the pinned images, the real connector from the
working tree as the peer zone's issuer with one route registered through dynamic client
registration, and the script as the guard, substituting and replay-checking with the forwarded
client certificate the sidecar would set. One failure at a time: a caller and a target the routes
refuse, a replay storm, PostgreSQL unreachable and PostgreSQL crash-recovered, OpenBao unreachable,
the issuer down through a renewal, every token expired, a renewer that died holding its claim. Each
row is recorded with the status, the reason code, the readiness words and the audit rows the
design documents for it; recovery is the dependency coming back, and every statement the script
ran against the database is listed. Records, `matrix.tsv` and the verdict go to `--out` (default
the git-ignored `.dev/token-store-failures/`); the matrix is in its
[README](verify-token-store-failures/README.md). Needs docker, helm, kind, kubectl, curl, jq and
openssl. The `Token store` workflow runs it as its own job.

## Connector chart and registration path (`verify-connector/`)

`verify.sh` proves the connector chart and its registration path on a throwaway kind cluster: both
images built from the working tree, PostgreSQL and OpenBao from the pinned images with the
connector's Secrets and transit key prepared; the connector chart installed, its hook applying the
schema with the token-store image, and ready on all four checks; not ready (`schema_behind`) once
the newest migration is reverted, and ready again after an upgrade whose hook applies it; a client registered by a pod running
`connector register` out of the connector's image, with credentials of the right shape and the
secret in no record; a registration the policy refuses, exit 1 with its specific error; exactly the
two `registration.*` rows in `audit_event` and the two IF-01 events on the connector's stdout,
correlated with the two requests; no secret, token or header in any record; the pod as its own
ServiceAccount with the identity label and no restart; a clean drain; and an uninstall that leaves
the schema in place. Records and the verdict go to `--out` (default the git-ignored
`.dev/connector-evidence/`). Needs docker, helm, kind, kubectl, curl and jq, and the pinned Istio CRDs
for the chart's PeerAuthentication (`BIN=`'s `istio-crds/`, or fetched); `BIN=` as above. The
`Connector` workflow runs it on every change to the connector, its image, either chart, the proof
or the pinned images. Design: [Connector service](../docs/connector.md).
