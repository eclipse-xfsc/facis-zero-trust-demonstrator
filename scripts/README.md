# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

| Script | What |
|---|---|
| `lifecycle.sh` | deploy or uninstall one Helm release: server-side dry run, then upgrade with rollback; the ORCE lifecycle node runs it |
| `install-zone/install.sh` | install, upgrade, render or uninstall a zone as its seven releases in order, each through `lifecycle.sh` |
| `dev/kind-cilium-up.sh` | the local kind cluster with Cilium chained (`cni.exclusive=false`) |
| `verify-umbrella/verify.sh` | evidence for the umbrella chart alone on kind |
| `verify-mesh-identity/verify.sh` | evidence that the mesh identities are SPIRE's, the whole zone on kind |
| `check-crypto-baseline.sh` | the cryptographic register (`docs/crypto-baseline.md`) against the repository: accepted mechanisms, the text each row quotes, and a scan of the Go code and the deployment configuration for the patterns the page lists; it cannot find a missing row |
| `verify-crypto-baseline/verify.sh` | the keys and certificates the configuration generates: the admission provider's certificates, the SPIRE server's rendered CA key type, and a Keycloak container upgraded from its default keys by the chart's realm |
| `verify-tls13/verify.sh` | the public-ingress TLS scenario (behind TDR-BDD-07) against a Traefik on kind: it fails on the controller as its chart installs it, which accepts TLS 1.2, and passes once `deployment/ingress/traefik-tls-options.yaml` is applied |
| `verify-access-runner/verify.sh` | the privileged-operations runner on kind with a Keycloak over TLS: every operation, every refusal and real-time grant expiry (`docs/privileged-access.md`) |
| `verify-orce-errors/verify.sh` | a malformed lifecycle command against a container of the ORCE image (`ORCE_IMAGE`), with this checkout's flow and settings: a JSON refusal, the error object in the flow context, and no log line that is not a JSON record |
| `mesh-mode/check-upstream-state.sh` | the upstream-state record behind ADR-0009 and its reopen check |
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

## Token-store chart lifecycle and readiness (`verify-token-store/`)

`verify.sh` proves the token-store chart's lifecycle and the service's readiness on a throwaway
kind cluster: the image built from the working tree, a registry on the kind network, PostgreSQL
and OpenBao from the pinned images inside the cluster with the connection URL in a Secret; then an
install that applies the schema to an empty database and brings the service up ready; the service
not ready and still alive while PostgreSQL, then OpenBao, is gone, and ready again when each is
back; a caller's `x-request-id` and trace context on the service's records, every request record
correlated, no credential among them, no restart; the pod as its own ServiceAccount with the
identity label; an upgrade that changes nothing, an uninstall with `schema.dropOnUninstall` that
leaves the schema empty, and a default uninstall that keeps it. Records and the verdict go to
`--out` (default the git-ignored `.dev/token-store-evidence/`). Needs docker, helm, kind, kubectl,
curl and jq; `BIN=` names the directory `scripts/tools/install.sh kind kubectl` installed to. The
`Token store` workflow runs it on every change to the store, its image, its chart or the pinned
images. Design: [Token store](../docs/token-store.md).
