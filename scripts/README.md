# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

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
