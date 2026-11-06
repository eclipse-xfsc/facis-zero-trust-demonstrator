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
