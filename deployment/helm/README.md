# Helm charts

Helm is the deployment engine for everything the demonstrator installs (TDR ADR 001). Each chart
documents its values in its own README.

| Chart | Path | Status | README |
|---|---|---|---|
| BDD pool | `deployment/helm/bdd-pool` | in use (kind and IONOS) | [bdd-pool/README.md](bdd-pool/README.md) |
| Admission provider | `deployment/helm/admission` | new; installed after Gatekeeper | [admission/README.md](admission/README.md) |
| Admission pool | `deployment/helm/admission-pool` | new; admission-proof namespaces and tester identity | [admission-pool/README.md](admission-pool/README.md) |
| Token store | `deployment/helm/token-store` | new; the authorization database's schema as a migration hook, and the service with its probes and identity, its endpoints to follow | [token-store/README.md](token-store/README.md) |
| Connector | `deployment/helm/connector` | new; standalone DCR behind the connector's registration policy with every decision audited, the verified-presentation grant, DPoP token issuance and JWKS, with its probes and identity; installed after the token-store chart, or applying the schema itself (`schema.enabled`); live proof pending | [connector/README.md](connector/README.md) |
| Application service | `deployment/helm/application-service` | in use (OSC shared namespace) | [application-service/README.md](application-service/README.md) |
| Admission reconciler (app-of-apps) | `deployment/helm/admission-gitops` | new; rendered by Argo CD from Git, never installed with helm (design in [deployment/argocd/README.md](../argocd/README.md)) | [admission-gitops/README.md](admission-gitops/README.md) |
| Lifecycle fixture (test data, never released) | `features/fixtures/charts/lifecycle-fixture` | in use by the acceptance scenarios | [README](../../features/fixtures/charts/lifecycle-fixture/README.md) |
| ORCE | `deployment/helm/orce` | new; ORCE on IONOS behind the public ingress, deployed by `deploy-ionos.yml` | [orce/README.md](orce/README.md) |
| Umbrella chart for a zone | `deployment/helm/ztd` | in use on kind; design in [docs/umbrella-chart.md](../../docs/umbrella-chart.md) | [ztd/README.md](ztd/README.md) |
| Zone policy | `deployment/helm/zone-policy` | in use on kind | the workloads' registration with SPIRE, mesh-wide STRICT mTLS, the mesh default deny with one allow rule per declared pair by identity and the denial log, the identity-band checks |
| Secret store (OpenBao) | `deployment/helm/ztd-openbao` | in use on kind; the eighth release of a zone | [ztd-openbao/README.md](ztd-openbao/README.md): `managementNamespace`, `cilium.enabled`, `openbao.*` (upstream chart 0.28.3, locked), `bootstrap.image`, `external.address`, `external.verifyTokenSecret` |
| Attested-channel gateway | `deployment/helm/atls-gateway` | new; the zone's attested entry and exit (ZT-28, ZT-65), both roles, startup check against the zone's evidence; proven between two zones on kind | [atls-gateway/README.md](atls-gateway/README.md) |
| Attester (cmcd) | `deployment/helm/cmcd` | new; CMC's cmcd with the software driver over the pipeline-signed material, in the management plane | [cmcd/README.md](cmcd/README.md) |
| IF-01 feed bridge | `deployment/helm/feed-bridge` | new; the feed in the mesh, the UI's identity only | [feed-bridge/README.md](feed-bridge/README.md) |
| TSPA re-publication | `deployment/helm/tspa-republish` | in use on zone B (`ztd-train`) | [tspa-republish/README.md](tspa-republish/README.md) |
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

`guard/` packages the namespace-local Envoy guard, real IF-05 evaluator and
Resource identity/network controls. See [guard runtime](guard/README.md). It is
standalone and must not be uninstalled while leaving the Resource reachable.
