# verify-cni-chaining-upgrade — the CNI chain across a Cilium upgrade

The mesh depends on the Istio CNI plugin being chained after Cilium on every node (`cni.exclusive=false`,
[ADR-0009](../../docs/adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md)). A Cilium upgrade
restarts the Cilium agent on every node, and the agent rewrites the node's CNI configuration when it
starts; the Istio CNI node agent then appends its plugin again. ADR-0001 and ADR-0009 require the
chaining order to be checked again after every Cilium upgrade. This proof performs a real upgrade on a
disposable kind cluster and checks the chain, and what the chain is for, on both sides of it.

```bash
scripts/verify-cni-chaining-upgrade/verify.sh            # creates ztd-cni-upgrade, runs, deletes it
scripts/verify-cni-chaining-upgrade/verify.sh --help
```

Needs Docker, kind, kubectl, helm, the `cilium` CLI, istioctl, jq, openssl and python3 with PyYAML
(the same tools as `scripts/verify-mesh-identity`). It uses its own cluster and never touches another:
it refuses to start when a cluster of its name exists, names the cluster's context on every command,
and leaves the caller's current context as found. Never run by CI.

## What a run shows

1. **The cluster and the zone.** `scripts/dev/kind-cilium-up.sh` creates the cluster (one control plane,
   two workers) with Cilium at `FROM_CILIUM_VERSION`, the zones' version (1.19.6), chained with
   `cni.exclusive=false`. `scripts/install-zone/install.sh` installs the zone with
   `deployment/helm/ztd/ci/values.yaml`, whose `cni.cilium.version` records the repository's pin
   (1.20.2), not `FROM`: this proof does not compare the recorded version with the running Cilium
   (the mesh identity proof does), and three stand-ins of
   `scripts/verify-mesh-identity/fixtures/stand-ins.yaml` are applied: `pdp-adapter` and `data-plain` in
   the data plane, `tsa-policy-engine` in the management plane.
2. **Before the upgrade.** On every node, the CNI configuration read through the node's Istio CNI agent
   lists the Istio plugin after Cilium (`scripts/verify-mesh-identity/lib/cni-chain.sh`, the reading the
   mesh proof uses); a node no agent reads fails. Cilium runs with `cni-exclusive=false`. The
   allow-matrix lane `pdp-adapter` → `tsa-policy-engine` answers 200 through both proxies, and
   `data-plain`, a data-plane pod without a lane, is refused.
3. **The upgrade.** `helm upgrade cilium cilium --repo https://helm.cilium.io/ --version $TO_CILIUM_VERSION --reset-then-reuse-values` (the chart by its repository URL, not through a local Helm repository named `cilium`; the release's own settings, `cni.exclusive=false` among them, over the new chart's defaults; plain `--reuse-values` also keeps the old chart's defaults, and the 1.20 chart does not render with them), then
   a wait for the rollout of `ds/cilium` with every pod on the new image and ready, then a wait for the
   Istio CNI agent to be ready on every node. Each wait is bounded by `TIMEOUT` and fails the run when it
   runs out. The record gives the time from the upgrade to the Cilium rollout and from the rollout to the
   Istio agent's readiness, so a long gap is visible.
4. **After the upgrade.** The same checks, and a pod created after the upgrade: `pdp-adapter` is deleted
   and created again, and its proxy must present a certificate carrying its own SPIFFE ID
   (`spiffe://<trust domain>/ns/ztd-data/sa/pdp-adapter`), issued by the SPIRE CA and chaining to the
   bundle read from the SPIRE server, and its lane must answer 200. A configuration file the Istio agent
   has repaired proves nothing about the pods created while it was not; the new pod shows that
   redirection into the proxy works after the upgrade.

## Inputs

| Variable | Default | Meaning |
|---|---|---|
| `FROM_CILIUM_VERSION` | `1.19.6` | the Cilium chart the cluster starts with: the zones' version (`docs/environments/osc.md`) |
| `TO_CILIUM_VERSION` | `CILIUM_CRDS_VERSION` of `scripts/tools/pins.env` (1.20.2) | the Cilium chart it is upgraded to: the repository's pin |
| `KIND_CLUSTER` | `ztd-cni-upgrade` | the disposable cluster; refused when it exists |
| `KIND_NODE_IMAGE` | `KIND_NODE_IMAGE` of `scripts/tools/pins.env` | the node image (Kubernetes 1.35, supported by Cilium 1.19 and 1.20) |
| `KEEP_CLUSTER` | unset | `1` keeps the cluster at the end |
| `TIMEOUT` | `600` | seconds each wait of the upgrade may take |
| `ZTD_EVIDENCE_DIR` | a new directory per run (below) | the run directory; refused inside the repository |
| `FAULT` | unset | **test only**: `drop-istio-plugin` (below) |

`FAULT=drop-istio-plugin` shows that the proof fails when the chain is broken. After the upgrade it pauses
the Istio CNI agent of the first worker node (`SIGSTOP`, so the agent cannot repair the file before it is
read) and removes the Istio plugin from that node's CNI configuration. The run must exit non-zero, and its
record must name the node and the plugin order read there. The agent is resumed at the end of the run, and
the cluster is deleted unless `KEEP_CLUSTER=1`.

## Run directory and exit status

Like `scripts/verify-mesh-identity`: `evidence.md` and `environment.json` are written to
`${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-cni-chaining-upgrade/kind-<cluster>/<UTC start>/`, or to
`ZTD_EVIDENCE_DIR`, never inside the repository; the last line of the output is that directory alone
(`tail -n 1`). `environment.json` records the commit, both Cilium versions and images, the two times of the
upgrade, the Kubernetes version and node image, the tools, any fault and the number of failed checks. The
exit status is the number of failed checks (capped at 124), 0 when every check passed, 125 when the run was
refused before it created anything, 130 or 143 when interrupted.

## When to run it

At every change of the pinned Cilium version (`CILIUM_CRDS_VERSION` in `scripts/tools/pins.env`, the
default of `scripts/dev/kind-cilium-up.sh`) and of the zones' version (`docs/environments/osc.md`), with
`FROM_CILIUM_VERSION` and `TO_CILIUM_VERSION` set to the two versions concerned
([CI/CD](../../docs/ci-cd.md#cilium-upgrades)). On the participant clusters the provider upgrades Cilium;
there the re-check after an upgrade is the chain section of `scripts/verify-mesh-identity`.
