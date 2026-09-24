# lifecycle-fixture

The release the cluster acceptance scenarios deploy until the umbrella chart is ready
(TDR-BDD-01..04, and TDR-BDD-06 as the target of its controlled error). It is test data, never
released; every evidence directory produced with it records `"fixture": true`, and the scenarios
that use it are named `[fixture release]`. A fixture pass is not acceptance of the umbrella release.
See [docs/bdd.md](../../../../docs/bdd.md#the-release-under-test).

## What it installs

A namespaced chart with no CRDs and no cluster-scoped objects, so the least-privilege deployer of
the BDD pool can install and remove it:

| Object | Notes |
|---|---|
| `ConfigMap` | holds `message` |
| `Deployment` | the `pause` image pinned by digest; readiness is a completed rollout |
| `Service` | port 80 to target port 8080, so the acceptance check resolves the target port rather than assuming it |

## Values

Every value is **required** and has no default (`values.yaml` is empty on purpose): a missing or
wrong value is a rejected deployment, which is what TDR-BDD-02 exercises. `values.schema.json`
enforces the rules below; `ci/values.yaml` is the valid baseline used by chart QA and by the
scenarios.

| Value | Rule | Baseline |
|---|---|---|
| `message` | non-empty string | `lifecycle fixture` |
| `replicas` | integer, 1 to 3 | `1` |
| `image.repository` | non-empty string | `registry.k8s.io/pause` |
| `image.digest` | `sha256:` and 64 hex digits | the pinned `pause` digest |

No other key is accepted (`additionalProperties: false`).

## Check

```bash
helm lint features/fixtures/charts/lifecycle-fixture -f features/fixtures/charts/lifecycle-fixture/ci/values.yaml
helm template t features/fixtures/charts/lifecycle-fixture -f features/fixtures/charts/lifecycle-fixture/ci/values.yaml
helm template t features/fixtures/charts/lifecycle-fixture     # fails: the required values are missing
```
