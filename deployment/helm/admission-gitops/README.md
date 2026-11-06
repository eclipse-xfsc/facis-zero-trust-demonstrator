# admission-gitops

The admission policy of a zone as Argo CD Applications: an `AppProject` and three children that
keep the constraint templates, the exemptions and the constraints of `deployment/admission` equal to
Git. Argo CD renders this chart itself, from the parent Application that
`scripts/argocd/install.sh` creates with the zone's values; it is never installed with `helm`
directly, and the chart gate lints and renders it like every other chart. The design, the lanes and
the operations are in [deployment/argocd/README.md](../../deployment/argocd/README.md).

## Values

| Key | Default | Meaning |
|---|---|---|
| `git.repoURL` | this repository on GitHub | the repository the children track; also the only source the project allows |
| `git.targetRevision` | `main` | the revision the zone follows |
| `argocd.namespace` | `argocd` | where the Applications and the project live |
| `destination.server` | `https://kubernetes.default.svc` | the cluster reconciled into: always Argo CD's own |
| `gatekeeper.namespace` | `gatekeeper-system` | where the exemptions Config lives; the only writable namespace of the project |
| `trust.repositories` | the project's registry | the zone's trusted repository prefixes, patched into `ztd-allowed-repositories` |
| `sync.retry` | 10 tries, 10s doubling to 3m | retry of a failed sync, for a constraint whose template's CRD is not established yet |

`ci/values.yaml` places the Applications in the `default` namespace for the chart gate's server
dry-run, which runs on a cluster without an `argocd` namespace.
