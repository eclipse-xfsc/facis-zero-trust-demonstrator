# Admission policy from Git

Gatekeeper decides admission from the constraint templates and constraints present in the cluster,
and cannot fetch them from anywhere itself. Until here they reached a zone by hand:
`scripts/admission/install.sh` applies the files of [deployment/admission](../admission/README.md)
with kubectl, nothing puts a constraint back when it is changed in the cluster, and nothing shows the
drift. This directory makes the path from Git to the cluster real (ZT-12): an Argo CD in every zone
keeps the templates, the exemptions and the constraints equal to the revision the zone follows,
reverts what is changed by hand, and exports the state of the sync.

## Layout: one parent, three children

Argo CD reconciles *Applications*: each names a path in a Git repository at a revision and a
destination, and Argo CD keeps the destination equal to the path. The layout is an app-of-apps:

| Application | Source | What it keeps equal to Git |
|---|---|---|
| `ztd-admission` (parent) | [deployment/helm/admission-gitops](../helm/admission-gitops/README.md), rendered as a Helm chart with the zone's values | the project and the three children below |
| `admission-templates` (wave 0) | `deployment/admission/templates/` | the ConstraintTemplates, cluster-scoped |
| `admission-exemptions` (wave 0) | `deployment/admission/exemptions.yaml` | Gatekeeper's `Config` in `gatekeeper-system` |
| `admission-constraints` (wave 1) | `deployment/admission/constraints/` (a kustomize base) | the constraints, with the zone's trusted repository prefixes patched into `ztd-allowed-repositories` |

Every one of them syncs automatically, prunes what left Git and heals what was changed in the
cluster (`selfHeal`), so a policy merged to the revision appears in the cluster on the next
reconciliation (at most three minutes, the controller's polling interval plus jitter) and a
hand-edited constraint is put back within seconds of the change being seen. The installer creates
the parent only; the parent renders the rest, so a change to the children is a change to the chart in
Git, never to the cluster.

The children are cut by layer and not one per policy because the order between layers is what
matters: Gatekeeper creates the CRD of each constraint kind from its template, so the constraints
sync after the templates (sync waves on the children, a retry with backoff on the constraints for a
template and its constraint merged together), and the one value that differs per zone, the
repository prefix, lives in one constraint.

An `AppProject`, `ztd-admission`, confines the children: the one source repository, the
`gatekeeper-system` namespace as the only writable one, and only the kinds the policy consists of
(ConstraintTemplate, the constraint kinds, Config). A child cannot be pointed elsewhere by an edit to
a child, since the parent puts the child back.

## One Argo CD per zone

Each zone runs its own Argo CD, reconciling its own cluster through the in-cluster API address, and no
Argo CD holds a credential for another cluster. One instance managing both zones would put the
cluster-admin credential of zone B inside zone A, across the boundary the demonstrator exists to
show (docs/architecture.md, section 6); a zone is also meant to stand on its own. The price is that a
zone is handed its policy once, by the installer, and the two zones follow the same revision because
both are told the same one.

## What runs, and what it may do

The pinned Argo CD chart (`scripts/tools/pins.env`: chart version and SHA-256, images by digest) with
[argocd-values.yaml](argocd-values.yaml): the application controller, the repo server, the API server
and redis. Dex, the notifications and the ApplicationSet controllers are off; the UI is not exposed
and is reached with `kubectl -n argocd port-forward svc/argocd-server 8080:443` when needed.

**Rights.** The chart's default gives the controller `*` on everything. Here the controller reads
everything (its resource cache, and the state it reports) and writes only the three Gatekeeper API
groups the policy consists of; the API server reads only. Argo CD's own objects stay under the
namespaced roles the chart creates.

**Network.** The `argocd` namespace is default-deny in both directions, as every plane namespace of
the umbrella chart is, with these lanes:

| Lane | Rule | Why |
|---|---|---|
| ingress, between components | the chart's own policies | controller and API server to the repo server and redis; metrics ports from any namespace |
| egress, within the namespace | `allow-intra-namespace-egress` | the same, from the other side |
| egress, DNS | `allow-dns-egress` | to CoreDNS in `kube-system`, ports 53 and 8053 |
| egress, Git | `allow-git-egress` | the repo server only, HTTPS only, anywhere: the repository is on a public host |
| egress, the Kubernetes API | added by the installer | under Cilium a CiliumNetworkPolicy to the `kube-apiserver` entity ([kube-api-lane.cilium.yaml](kube-api-lane.cilium.yaml)), the only form that selects the API server there; elsewhere a NetworkPolicy to the addresses given (`KUBE_API_CIDRS`: the endpoint of the `kubernetes` Service and its cluster address; kind's CNI enforces policy and needs it, as the e2e script shows) |

On a Gardener cluster the namespace also carries `apiserver-proxy.networking.gardener.cloud/inject=disable`,
as the umbrella's namespaces do: without it the platform points every pod at a node-local proxy that
sits outside the API lane.

**Observability.** The controller exports `argocd_app_info{name, sync_status, health_status, ...}`,
one series per Application, on `argocd-application-controller-metrics:8082/metrics`; the repo server
and the API server export on 8084 and 8083. The metrics Services carry the `prometheus.io/scrape`
annotations, so the zone's collector picks them up once it is installed (ZT-27); until then the
installer reads the series itself and refuses to finish without one `sync_status="Synced"` per
Application.

## Install

After Gatekeeper and the provider (`scripts/admission/install.sh`), with the chart archive from
`scripts/tools/install.sh <dir> argocd-chart`:

```bash
BIN=<dir> TRUST_REPOSITORY=<host/path> CILIUM=1 \
NAMESPACE_LABELS=apiserver-proxy.networking.gardener.cloud/inject=disable \
scripts/argocd/install.sh
```

`TRUST_REPOSITORY` is the zone's trusted repository prefix, the value the provider was installed
with. `REPO_URL` and `REVISION` (default: this repository on GitHub, `main`) are what the zone
follows; a pull request is proven on a cluster by pointing a zone at its branch, then re-running the
installer with the defaults once it is merged. The script is idempotent and stops at the first check
that fails: an image not pinned by digest, an Application not `Synced/Healthy`, the zone's prefix
missing from the constraint, or the sync status missing from the metrics.

## Operations

- **Changing the policy** is a pull request to `deployment/admission/`; nothing is applied to a zone
  by hand. `kubectl -n argocd get applications` shows each Application with its sync status and the
  revision it is at.
- **Proving the revert:** `scripts/argocd/drift-check.sh` edits the naming constraint's pattern in
  the cluster and reports the seconds until the value from Git is back; the injected pattern still
  admits the `ztd-` names, and it is live for seconds.
- **Break-glass:** `kubectl -n argocd scale statefulset argocd-application-controller --replicas 0`
  stops reconciliation at once and removes nothing; `--replicas 1` resumes it, and the next
  reconciliation reverts whatever was changed meanwhile.
- **Removing the reconciler.** `kubectl -n argocd delete application ztd-admission` is a cascade: the
  children go, and with them the templates, the constraints and the exemptions they manage, which
  leaves the zone without admission policy. To remove Argo CD and keep the policy in place, remove the
  `resources-finalizer.argocd.argoproj.io` finalizer from the four Applications first, then
  `helm uninstall argocd -n argocd` (the CRDs are kept, `crds.keep`).

## Tests

- `scripts/argocd/kind-e2e.sh`: a throwaway kind cluster with Gatekeeper and Argo CD, handed the
  policy of a Git revision; every Application `Synced/Healthy`, the catalogue in the cluster equal to
  the checkout, the zone's prefix patched in, a hand-edited constraint put back, a hand-edited child
  Application put back by the parent, and the sync status in the metrics. The `admission-gitops` job
  of `.github/workflows/ci.yml` runs it against the revision under test, fetched from the repository
  it came from.
- The chart is linted and rendered by the chart gate like every chart under `deployment/helm/`; the
  gate's cluster serves Argo CD's Application and AppProject CRDs for the server dry-run.
