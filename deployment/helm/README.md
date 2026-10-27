# Helm charts

Helm is the deployment engine for everything the demonstrator installs (TDR ADR 001). Each chart
documents its values in its own README.

| Chart | Path | Status | README |
|---|---|---|---|
| BDD pool | `deployment/helm/bdd-pool` | in use (kind and IONOS) | [bdd-pool/README.md](bdd-pool/README.md) |
| Admission provider | `deployment/helm/admission` | new; installed after Gatekeeper | [admission/README.md](admission/README.md) |
| Admission pool | `deployment/helm/admission-pool` | new; admission-proof namespaces and tester identity | [admission-pool/README.md](admission-pool/README.md) |
| Lifecycle fixture (test data, never released) | `features/fixtures/charts/lifecycle-fixture` | in use by the acceptance scenarios | [README](../../features/fixtures/charts/lifecycle-fixture/README.md) |
| ORCE | — | planned; until then ORCE is installed from `deployment/orce-minimal/` | — |
| Umbrella chart for a zone | `deployment/helm/ztd` | in use on kind; design in [docs/umbrella-chart.md](../../docs/umbrella-chart.md) | [ztd/README.md](ztd/README.md) |
| Zone policy | `deployment/helm/zone-policy` | in use on kind | the workloads' registration with SPIRE, mesh-wide STRICT mTLS, the identity-band checks |
| Secret store (OpenBao) | `deployment/helm/ztd-openbao` | in use on kind; the eighth release of a zone | [ztd-openbao/README.md](ztd-openbao/README.md): `managementNamespace`, `cilium.enabled`, `openbao.*` (upstream chart 0.28.3, locked), `bootstrap.image`, `external.address`, `external.verifyTokenSecret` |
| Upstream SPIRE and Istio charts (values only) | `deployment/helm/values` | in use on kind | [values/README.md](values/README.md) |

## A zone

A zone is eight Helm releases, installed in order by `scripts/install-zone/install.sh` from one zone
file: the umbrella `ztd` (management and data planes and the two control-plane namespaces, baseline
deny network policies with the declared openings, the allow matrix, the hook-weight bands); the
upstream charts `spire-crds`, `spire`, `istio-base`, `istiod` and `istio-cni`, installed as they ship
and pinned by version with the values files in `values/` (that README lists every value set and
why); `zone-policy`; and `ztd-openbao`, the secret store, last so that its pods are created with a
mesh identity. Every release after the umbrella reads the zone facts it needs from the umbrella's
defaults with the zone file on top.

Workload identity exists before any workload starts because of the identity path, not because of an
install order (`docs/umbrella-chart.md`).

## Quality gate

Every pull request lints and renders every chart under `deployment/helm/` and
`features/fixtures/charts/` with Helm v4.3.0 (the `charts` job in `.github/workflows/ci.yml`); a
chart whose values have no defaults is checked with its `ci/values.yaml`. The lifecycle workflow
itself runs a server-side dry-run before every install (`scripts/lifecycle.sh`). The release
workflow adds a server-side dry-run against a disposable cluster before any candidate is built (the
`chart-gate` job in `.github/workflows/release.yml`, TDR-BDD-11), and proves with two deliberately
broken charts (`features/fixtures/broken-charts/`) that a chart failing lint or the dry-run is
refused. When a release is published, the `release-charts` job of `ci.yml` runs the gate once more on
a disposable cluster, then packages the charts at the release version and attaches them to the
release (`docs/ci-cd.md`, Chart release). All three jobs run `scripts/ci/check-charts.sh`; a chart
with dependencies is built from its committed `Chart.lock`.

```bash
for chart in deployment/helm/*/ features/fixtures/charts/*/; do
  values=(); [ -f "$chart/ci/values.yaml" ] && values=(-f "$chart/ci/values.yaml")
  helm lint "$chart" "${values[@]}" && helm template "$chart" "${values[@]}" >/dev/null
done
```
