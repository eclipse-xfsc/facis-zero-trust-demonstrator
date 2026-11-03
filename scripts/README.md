# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

| Script | What |
|---|---|
| `lifecycle.sh` | deploy or uninstall one Helm release: server-side dry run, then upgrade with rollback; the ORCE lifecycle node runs it |
| `install-zone/install.sh` | install, upgrade, render or uninstall a zone as its eight releases in order, each through `lifecycle.sh` |
| `dev/kind-cilium-up.sh` | the local kind cluster with Cilium chained (`cni.exclusive=false`) |
| `verify-umbrella/verify.sh` | evidence for the umbrella chart alone on kind |
| `verify-mesh-identity/verify.sh` | evidence that the mesh identities are SPIRE's, the whole zone on kind |
| `mesh-mode/check-upstream-state.sh` | the upstream-state record behind ADR-0009 and its reopen check |
| `ci/check-charts.sh` | the chart quality gate: lint, render and (release) server dry-run of every chart; `ci/check-charts_test.sh` its cases |
| `ci/check-policy-addresses.sh` | no address in a policy: renders the umbrella, `zone-policy` and `ztd-openbao` with every shipped zone file and the CI zone file and fails on any `ipBlock`, CIDR rule or address literal in a NetworkPolicy, CiliumNetworkPolicy or AuthorizationPolicy; `ci/check-policy-addresses_test.sh` its cases |
