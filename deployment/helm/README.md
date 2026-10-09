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
| Upstream SPIRE and Istio charts (values only) | `deployment/helm/values` | in use on kind | [values/README.md](values/README.md) |

## A zone

A zone is seven Helm releases, installed in order by `scripts/install-zone/install.sh` from one zone
file: the umbrella `ztd` (management and data planes and the two control-plane namespaces, baseline
deny network policies with the declared openings, the allow matrix, the hook-weight bands); the
upstream charts `spire-crds`, `spire`, `istio-base`, `istiod` and `istio-cni`, installed as they ship
and pinned by version with the values files in `values/` (that README lists every value set and
why); and `zone-policy`.

Workload identity exists before any workload starts because of the identity path, not because of an
install order (`docs/umbrella-chart.md`).

## Quality gate

Every pull request lints and renders every chart under `deployment/helm/` and
`features/fixtures/charts/` with Helm v4.3.0 (the `charts` job in `.github/workflows/ci.yml`); a
chart whose values have no defaults is checked with its `ci/values.yaml`. The lifecycle workflow
itself runs a server-side dry-run before every install (`scripts/lifecycle.sh`). A server-side
dry-run as a CI gate before a release is promoted (TDR-BDD-11) is not in place yet; that row is
pending in the [catalogue](../../docs/bdd-catalogue.md).

```bash
for chart in deployment/helm/*/ features/fixtures/charts/*/; do
  values=(); [ -f "$chart/ci/values.yaml" ] && values=(-f "$chart/ci/values.yaml")
  helm lint "$chart" "${values[@]}" && helm template "$chart" "${values[@]}" >/dev/null
done
```
