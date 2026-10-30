# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

## Token-store chart lifecycle (`verify-token-store/`)

`verify.sh` proves the token-store chart's lifecycle on a throwaway kind cluster: the image built
from the working tree, a registry on the kind network, PostgreSQL from the pinned image inside the
cluster with its connection URL in a Secret; then an install that applies the schema to an empty
database, an upgrade that changes
nothing, an uninstall with `schema.dropOnUninstall` that leaves the schema empty, and a default
uninstall that keeps it. Records and the verdict go to `--out` (default the git-ignored
`.dev/token-store-evidence/`). Needs docker, helm, kind and kubectl; `BIN=` names the directory
`scripts/tools/install.sh kind kubectl` installed to. The `Token store` workflow runs it on every
change to the store, its image, its chart or the pinned images. Design: [Token store](../docs/token-store.md).
