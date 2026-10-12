# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

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
