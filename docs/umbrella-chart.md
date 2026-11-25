# Umbrella chart

The zone is laid down once, by one chart, before any component is installed. Everything that
follows — identity, mesh, admission, the platform services, the demonstrator workloads — installs
into the layout the umbrella made, and the jobs those components bring run in the order its
hook-weight bands prescribe. The chart is `deployment/helm/ztd`; this page is its design, and the
chart's `README.md` documents its values.

## What the chart lays down

**Two planes, as namespaces.** Management components (SPIRE server, ArgoCD, OpenBao, Harbor, TSPA,
estserver, admin APIs) live in management-plane namespaces; the demonstrator workloads live in
data-plane namespaces. The chart creates `ztd-mgmt` and `ztd-data`, plus any namespace a component
task adds through `planes.extra`, and labels each with `ztd.facis.io/plane` and the mesh label for
the zone's mode. Nothing crosses a plane without being named.

**The two control planes, as management-plane namespaces.** A meshed zone lists `spire-system` (the
SPIRE server, controller-manager, agents and CSI driver) and `istio-system` (istiod and the Istio
CNI agent) in `planes.extra` with `mesh: false`: they get the plane label, the default deny and the
baseline lanes, and **no injection label**, so no control-plane pod receives a sidecar. The chart
creates them, because the releases that install into them run through the lifecycle step, which
never creates a namespace. Why both are in the management plane is in
[Workload identity](workload-identity.md#where-the-control-planes-live).

**The node collectors' namespace.** A participant zone lists `ztd-otel-node` in `planes.extra` with
`mesh: false`: the management-plane namespace of the node collectors (release `otel-node`), which run
on the host network and never receive a sidecar. It gets the plane label, the default deny and the
baseline lanes like the control planes; a host-network pod is not subject to its pod policies, so the
node collectors' egress is fixed by their configuration, which names the demonstrator cluster's entry
as their only exporter ([ADR-0017](adr/0017-central-observability-backends.md)).

**Default deny at the network layer.** Every plane namespace gets a `default-deny` NetworkPolicy in
both directions. These openings follow, each declared in [Architecture §6](architecture.md), beside
the DNS bypass, and each rendered only when the zone enables it:

| Lane | Rendered as | Why it exists |
|---|---|---|
| workloads → DNS | `allow-dns-egress`, the resolver pods' port (`networkPolicy.dns.ports`: 53, 8053 on the Gardener clusters) to the cluster resolver only | the declared DNS bypass |
| pods within one plane namespace | `allow-intra-plane` | who may talk is decided on identity by the mesh layer, not on IP: the mesh-wide default deny of `zone-policy` and the pairs of `intraPlanePairs` |
| management → Kubernetes API (`kubeApi`) | `allow-kube-api-egress`: with Cilium a `CiliumNetworkPolicy` to the `kube-apiserver` entity on the `kubernetes` Service port 443 and on the zone's API port; without Cilium an `ipBlock` egress to the zone's endpoint | the SPIRE server, its controller-manager and istiod call the API; required wherever the mesh runs |
| meshed plane namespaces → istiod (`meshControlPlane`) | `allow-mesh-control-plane-egress` in each namespace with the mesh label, `allow-mesh-control-plane-ingress` in `istio-system`, port 15012 | the sidecars fetch their configuration over xDS |
| API server → webhooks (`controlPlaneWebhooks`) | `allow-control-plane-openings` in `istio-system` (istiod, 15017) and `spire-system` (controller-manager, 9443), a `CiliumNetworkPolicy` from the `kube-apiserver`, `host` and `remote-node` entities | injection and the admission of `PeerAuthentication` and `ClusterSPIFFEID` |
| SPIRE agents → SPIRE server (`identityServer`) | in the same `allow-control-plane-openings` of `spire-system`, from the `host` and `remote-node` entities, port 8081 | the agents run on the host network and attest to the server |
| zone gateway → SPIRE metrics (`observabilityScrape`) | `allow-observability-scrape-egress` in the management namespace (the gateway's pods, by `telemetryExport.gateway.podSelector`), `allow-observability-scrape-ingress` in `spire-system` (the server pod), ports 9988 and 8082 only; and the ClusterIP Service `spire-server-metrics` on those two ports | the zone gateway scrapes the SPIRE server and the controller-manager; a stopped server shows as a failed scrape (`up == 0`), not as a vanished target. A management-plane path, outside the allow matrix |
| zone gateway → the demonstrator cluster's entry (`telemetryExport.entry`) | `allow-telemetry-export-egress` in the management namespace: the gateway's pods to the entry's address (`address`, a /32) on this zone's port, and no other external destination; on kind, where the entry is a pod of the same cluster, to its namespace and labels (`inCluster`) | the declared ZT-26 bypass of the observability export; rendered once the zone file names the entry. The address is the transport switch: the public entry during the contingency period, the CUG address after the move |

The openings whose source is not a pod (the API server, the host-networked agents) are Cilium
policies by entity, because a Kubernetes NetworkPolicy cannot name those sources; with a mesh and
without Cilium the chart refuses to render and names the derogation another CNI needs. Each Cilium
rule adds its lane and leaves the deny to `default-deny` (`enableDefaultDeny` false). The reasoning
and the proof are in [Workload identity](workload-identity.md#openings-under-the-default-deny).

**The API lane under Cilium.** Cilium does not select an API server that runs on a cluster node by its
address: it treats it as the `kube-apiserver` entity, and a NetworkPolicy `ipBlock` never matches it,
so an address lane would stay shut. With `cni.cilium.enabled` the lane is therefore the entity policy,
and the zone file's `cidrs` are recorded, not rendered. It opens the `kubernetes` Service port, 443,
and the zone's endpoint port (`ports`): with kube-proxy, Cilium sees the Service port before
kube-proxy translates it, without kube-proxy the endpoint port. Opening every port instead would open
the whole node the API server runs on, the kubelet included. The evidence (section 7) shows the lane
open from the management plane only, on a kind cluster with Cilium chained as the zones run it.

**The allow matrix, as data.** The lanes of the ZT-55 matrix are entries in `allowMatrix`, each
with a source and a destination selector and the source's service account
(`from.serviceAccount`, required when the source names a workload, refused for a whole-plane
source); the chart renders an egress rule in the source namespace and an ingress rule in the
destination namespace for every lane. The selectors and accounts are the label and identity
contract with the component charts:

| Lane | From (data plane) | Caller's service account | To (management plane) |
|---|---|---|---|
| `pdp-adapter-to-tsa` | `app.kubernetes.io/name=ztd-policy-evaluator` (the guard chart's PDP adapter) | `ztd-policy-evaluator` | `tsa-policy-engine` |
| `atls-gateway-to-cmcd` | `atls-gateway` (reserved: no chart runs the gateway yet, IF-07 v0) | `atls-gateway` | `cmcd` |
| `atls-gateway-to-tcr` | `atls-gateway` (reserved, as above) | `atls-gateway` | `tcr` |
| `workloads-to-otel-collector` | every data-plane pod | none: the whole plane (the namespace) | `otel-collector`, ports 4317 and 4318 only |
| `token-store-to-verification-service` | `ztd-token-store` (`app.kubernetes.io/component=server`) | `ztd-token-store` | `verification-service`, port 8080 only |
| `connector-to-openbao` | `ztd-connector` | `ztd-connector` | `openbao` (`component=server`), port 8200 only |
| `token-store-to-openbao` | `ztd-token-store` (`app.kubernetes.io/component=server`) | `ztd-token-store` | `openbao` (`component=server`), port 8200 only |

`intraPlanePairs` takes entries of the same shape for a pair inside one plane namespace between
components of different releases. The chart renders nothing for them, as `allow-intra-plane` already
opens the namespace at L3/L4, and refuses one whose endpoints are not in one namespace. The list is
empty; the component task that brings a same-plane caller adds its pair there.

The identity provider's token endpoint is not a lane. No data-plane workload calls it: the
participant backend obtains its authorization from the connector, and Keycloak serves the viewer's
login and the pipeline ([Keycloak integration](keycloak.md#connector-boundary)). A permitted lane
without a caller would only widen what the matrix exists to limit.

Every row records its single L7 enforcement owner in `l7Owner`, `sidecar` (the destination's Envoy
sidecar) or `none`, required by the schema; the five shipped rows are `sidecar`. `cilium` is not a
value: under the mesh-wide STRICT mTLS Cilium sees only ciphertext on these paths, and the
`zone-policy` release refuses, in plane namespaces, Cilium policies that send traffic to Cilium's L7 proxy and Cilium Envoy configurations (`l7-owner-is-the-mesh`). Both
NetworkPolicies of a row and its mesh rule `allow-<name>` carry the owner as the annotation
`ztd.facis.io/l7-owner`, written `none` when `mesh.mode` is `none` or the parked `ambient`, which has
no per-pod proxy and deploys no waypoint ([Architecture](architecture.md#allow-matrix-data-plane-management-plane)).

Every row is enforced at both layers (`enforcedBy` documents the layer the architecture holds
responsible, not a choice between them). The network layer opens the L3/L4 lane here. The mesh
layer is rendered by the `zone-policy` release, which installs after Istio's CRDs: a mesh-wide
default deny and, for every `allowMatrix` row and `intraPlanePairs` entry, an `AuthorizationPolicy`
`allow-<name>` in the destination namespace that admits the caller by its SPIFFE identity
(`<trust domain>/ns/<namespace>/sa/<serviceAccount>`), or the source namespace for a whole-plane
source. `scripts/install-zone/install.sh` copies the rows from the zone values to `zone-policy` and
refuses a zone whose mesh rules are not exactly one per row ([Workload
identity](workload-identity.md#mesh-authorization)). Anything else from the data plane into the
management plane is denied by both layers, which is the negative case the evidence script proves.

**The demonstrator role.** With `zone.role: demonstrator` (the IONOS cluster,
`deployment/helm/ztd/zones/ionos.yaml`; on kind `ci/demonstrator-values.yaml`) the chart renders no
plane namespace, no allow matrix and no control-plane opening: the demonstrator cluster sits outside
both trust domains. It renders the backends' namespace (`observabilityBackends.namespace`,
`ztd-observability`), labelled `ztd.facis.io/role: observability-backends` and without plane or mesh
label, with `default-deny`, `allow-dns-egress`, `allow-between-backends` (the entry to Prometheus and
Jaeger, inside the namespace), and `allow-telemetry-entry-ingress`: the
entry's pods, on the per-zone listener ports only, from the zones' egress addresses
(`observabilityBackends.entry.sourceRanges`; on kind from the in-cluster sources). Prometheus
and Jaeger get no opening from outside. The schema refuses a demonstrator with a mesh,
and one without a zone listener; the installer refuses one with a LoadBalancer and no source ranges.
The verification job checks the backends' namespace, its role label, no plane or mesh label, and its
default deny. The release is named `ztd-demonstrator`, so on kind both roles share the cluster.

## The mesh mode is one label

[ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md) baselines Istio sidecar mode
with Cilium as the CNI, superseding the ambient baseline of ADR-0001 through the fallback clause
that record foresaw: the mesh cannot take SPIRE-issued identities under ambient with community
Istio. Ambient is parked, not abandoned. Between the two modes the layout differs in one namespace
label — `istio-injection=enabled` or `istio.io/dataplane-mode=ambient`, never both on the same
namespace — so `mesh.mode` in the zone file is the only thing that changes, and the chart is the
same either way: the default is `sidecar`, the value `ambient` stays accepted, and the evidence
script switches a live install from the sidecar baseline to ambient and back. Istio itself is
installed by the mesh step after the umbrella; until then the label is inert.

One piece is mode-specific, and it belongs to the parked mode. Under Istio ambient with Cilium as
the CNI, the kubelet's health probes reach ambient pods SNAT-ed to `169.254.7.127`, an address Cilium
does not exempt from policy, so a default-deny NetworkPolicy would fail every probe. Istio's platform
prerequisites prescribe a cluster-wide Cilium policy admitting that address, and the chart renders it
only when the mode is ambient and Cilium is enabled; in the sidecar baseline of ADR-0009 nothing of
the kind is rendered, and the template stays so that returning to ambient costs a zone value, not a
chart change.

## Admission in the data plane is an opt-in label

The Gatekeeper image policy ([deployment/admission](../deployment/admission)) applies only to
namespaces labelled `facis.ztd/admission-proof=true`. The umbrella sets that label on one namespace,
the data-plane namespace (`planes.data.namespace`), and only when the zone sets
`admission.enforceDataPlane: true`; the default is off. The management plane, any `planes.extra`
namespace (a second data-plane namespace included) and the control-plane namespaces
(`gatekeeper-system`, `istio-system`, `spire-system`, `kube-system`) never get it, and
`planes.namespaceLabels`, which applies to every namespace the umbrella creates, may not set it. The
CI chart job renders both settings and checks exactly that.

Turning it on puts every workload of the data plane under the image policy, the injected Istio
proxy and `istio-validation` init container included. They run Istio's own `proxyv2` image, which the
project does not sign; [istiod.yaml](../deployment/helm/values/istiod.yaml) references it by digest
only, and that exact reference must be on the admission digest allow-list
(`admissionProvider.trust.allowedDigests` in the zone file for the admission release below, or
`ALLOWED_DIGESTS` of `scripts/admission/install.sh`). Where Helm owns the policy (standalone, or
`admission.policy.managedBy: helm`), that one list reaches both the provider's `trust.allowedDigests`
and the `ztd-allowed-repositories` constraint. Where Argo CD keeps the policy (zone A and zone B,
`managedBy: argocd`) the zone file reaches the provider only: the same digests must be added to the
`allowedDigests` of the constraint in Argo CD's policy source and synced, and
`scripts/admission/preflight-data-plane.sh <namespace>` must pass - it checks the namespace's images
against both the provider's policy and the live constraint - before the data plane is enforced. The
zone installer refuses `enforceDataPlane` with `managedBy: argocd` while the live constraint lacks a
digest of the zone's `admissionProvider.trust.allowedDigests`. Before turning it on, run
`scripts/admission/preflight-data-plane.sh <namespace>` (read-only), which names every image there
that would be denied. With the label on, a Gatekeeper or provider outage denies admission in the data
plane (fail closed), and `scripts/admission/fault-injection.sh` expects it to.

## Admission in the umbrella

The admission stack - Gatekeeper, the image-verification provider
([deployment/helm/admission](../deployment/helm/admission)), the admission policy (constraint
templates, exemptions and constraints of [deployment/admission](../deployment/admission)) and the
admission pool ([deployment/helm/admission-pool](../deployment/helm/admission-pool)) - is part of this
chart: the pinned Gatekeeper chart and the two local charts are dependencies (`gatekeeper`,
`admissionProvider`, `admissionPool`, locked in `Chart.lock`), and `templates/admission-policy.yaml`
renders the policy from `files/admission`, links to `deployment/admission`, so the policy keeps one
copy. A zone file opts in with `admission.install: true` and carries the settings
(`gatekeeper.replicas`, `admissionProvider.*`, `admissionPool.*`); the default is off, so an upgrade
of the chart changes nothing on a zone that has not opted in.

**Namespace model: a second release of this chart.** The stack is not part of release `ztd`. The zone
installer installs this chart a second time, as release `gatekeeper` in `gatekeeper-system` - the
*admission release* - and only there are the admission parts switched on (`gatekeeper.enabled` and
the stage switches, which the installer sets and a zone file may not). With `gatekeeper.enabled` the
chart renders the admission stack and nothing of release `ztd`; without it, any admission part is
refused. The reasons are in the Gatekeeper chart itself: it puts every object in
`.Release.Namespace` (26 places, including the webhook's exempt namespace and the Service URL) and
its Deployment selectors carry `release: <release name>`, which is immutable. Inside release `ztd`
Gatekeeper would land in `ztd-system`; under any release name but `gatekeeper` its Deployments
would have to be deleted and recreated - a webhook outage, and with `failurePolicy: Fail` a denial
of every admission in the labelled namespaces. As release `gatekeeper` in `gatekeeper-system`,
Gatekeeper and the provider stay co-located, the provider's Provider URL and server certificate
names (`.Release.Namespace`) are unchanged, and its TLS Secret is looked up where it already is, so
the provider CA survives the migration. The provider chart's Deployment selector no longer follows
the release name: it is fixed to `app.kubernetes.io/instance: admission`, the name it was first
installed under, so the same Deployment is adopted in place.

**Install order: four stages of one release.** A Helm dependency cannot make a constraint wait for
the CRD Gatekeeper generates from its template, so on a first install the installer deploys the
admission release four times, each through `scripts/lifecycle.sh` (server-side dry run, then
`helm upgrade --install --wait`), each waiting for what the next needs:

| Stage | Adds | The next stage waits for |
|---|---|---|
| 1 | Gatekeeper | its CRDs (`providers`, `constrainttemplates`, `configs`) Established |
| 2 | the provider, the constraint templates, the exemptions | the four constraint CRDs Established |
| 3 | the four constraints | every constraint enforced by every Ready webhook replica (`scripts/admission/enforced.sh`) |
| 4 | the admission pool (the labelled `ztd-adm-*` namespaces and the tester identity) | - |

No deploy renders less than the release already holds (its deployed switches): on an upgrade the
stages below it are not deployed again, whatever a readiness check says at that moment, so a
readiness blip can never make Helm delete an installed component; a stage above it is skipped only
when its successor's condition already holds (the migration, where everything is in place). Stage 4
goes out in two steps: first with the pool namespaces that already exist, so a changed policy is
applied without touching the pool; then, once every constraint's current generation is enforced by
every Ready webhook replica, with any new pool namespace. Enforcement therefore exists before any
labelled namespace does, on a first install and on an upgrade. After the last stage the installer runs the checks of
`scripts/admission/install.sh`: both webhooks scoped to `facis.ztd/admission-proof=true`, the
response cache off, every constraint enforced. Every render, dry run and deploy of the admission
release goes through the `ztd-webhook-scope` post-renderer, and only of that release: release `ztd`
has no webhook, and the post-renderer fails unless it scopes exactly two.

**Who owns the policy: `admission.policy.managedBy`.** The policy objects (constraint templates,
constraints, exemptions) have one owner per cluster. `helm` (the default; kind and IONOS): the
admission release renders them, as above. `argocd` (zone A and zone B): the Argo CD on the cluster
keeps them from Git - Applications `admission-templates`, `admission-constraints` and
`admission-exemptions`, created by the app-of-apps Application `ztd-admission`, which itself manages
only those three Applications and their AppProject, nothing of Gatekeeper or the provider. The
admission release then installs Gatekeeper, the provider and the pool only, renders no policy object
(the chart refuses one), and so never takes ownership of one, in an install or an adoption. Stage 3
deploys nothing: after stage 2 the installer waits for the constraint CRDs that Gatekeeper generates
from Argo CD's templates, then for Argo CD's constraints to be enforced by every Ready webhook
replica, and only then deploys stage 4 (the pool). If Argo CD has not provided them within
`ADMISSION_POLICY_TIMEOUT` seconds (default 300) per wait, the installer stops and names the
Applications to check.

**Handing the policy from Helm to Argo CD.** Switching a cluster whose release renders the policy
from `helm` to `argocd` would make Helm delete the policy objects it holds, so the installer refuses
that switch, before any deploy, while the release holds a policy object without
`helm.sh/resource-policy: keep`. The handoff: (1) set `admission.policy.keep: true` (managedBy still
`helm`) and run `install gatekeeper`, which marks every policy object keep; (2) point Argo CD's
Applications at the same objects; (3) set `managedBy: argocd` and run `install gatekeeper` again:
the release stops rendering the policy and Helm leaves every object in place (proven by kind-e2e,
umbrella layout, POLICY=helm).

**Standalone path.** `scripts/admission/install.sh` stays supported and unchanged for a zone that has
not opted in; it refuses a zone in the umbrella layout except as the rollback below. The fault,
evidence and end-to-end scripts detect the layout (`admission_layout` in
`scripts/admission/checks.sh`) and change the provider through whichever release owns it, with
`--reuse-values` and the recorded replica counts, never resetting other values.

### Migration runbook (live zone, standalone to umbrella)

Not run on a live cluster yet. Proven on kind: `LAYOUT=migrate` and `LAYOUT=rollback` of
`scripts/admission/kind-e2e.sh`, and `POLICY=argocd` for the Argo CD split (a stand-in applies
the policy from outside the release; the run checks no policy object gets a Helm owner).

1. **Preflight.** On zone A and zone B the policy stays with Argo CD: the zone files set
   `admission.policy.managedBy: argocd`, and its Applications must be Synced and Healthy
   (`kubectl -n argocd get applications`); nothing of them changes. On IONOS (`helm`) the release
   adopts the policy objects that `install.sh` applied. Then: `helm list -n gatekeeper-system` shows `gatekeeper` (chart `gatekeeper-3.23.1`),
   `admission` and `admission-pool`. Compare the zone file's admission settings with the live ones:
   `helm get values admission -n gatekeeper-system` against `admissionProvider` (image digest,
   repositories, key, allowed digests, replicas) and `helm get values gatekeeper` replicas against
   `gatekeeper.replicas`. If the zone enforces its data plane (`admission.enforceDataPlane`), run
   `scripts/admission/preflight-data-plane.sh <data-plane namespace>`; it must exit 0.
2. **Build and render.** `helm dependency build deployment/helm/ztd`; set `admission.install: true`
   in the zone file; `ZONE_VALUES=<zone file> RENDER_DIR=<dir> scripts/install-zone/install.sh render gatekeeper`
   writes the manifest and the values it was rendered with.
3. **Dry run against the cluster** (read-only), with the rendered values of stage 4:
   `helm upgrade gatekeeper deployment/helm/ztd -n gatekeeper-system -f <RENDER_DIR>/gatekeeper.values.yaml
   --post-renderer ztd-webhook-scope --take-ownership --dry-run=server`, then
   `kubectl diff --server-side --force-conflicts -f <the MANIFEST part of that output>`. Expected:
   Gatekeeper and the provider (its TLS Secret is looked up, not regenerated) unchanged;
   `app.kubernetes.io/instance` of the seven pool objects `admission-pool` → `gatekeeper`; Helm's
   ownership annotations on the adopted objects. On zone A and zone B the manifest holds no policy
   object, so Argo CD's are untouched. The 2026-11-21 dry runs showed exactly that on zone A and
   zone B; on IONOS also the policy objects adopted unchanged except the constraint template
   `k8sztdallowedrepositories` gaining `allowedDigests` - the digest allow-list, which IONOS does
   not run yet. Any other change is a difference between the zone file and the live values, to
   settle first. A dry run persists nothing (the release revision stays).
4. **Adopt.** `ZONE_VALUES=<zone file> KUBE_CONTEXT=<context> ADMISSION_ADOPT=1
   scripts/install-zone/install.sh install gatekeeper` (or `install` for the whole zone). Release
   `gatekeeper` is upgraded to this chart with `--take-ownership` and without rollback on failure
   (rolling an adoption back would delete the adopted objects); on success the records of releases
   `admission` and `admission-pool` are dropped (their Helm Secrets), their objects kept. A failed
   adoption is re-run, not rolled back.
5. **Verify.** `helm list -n gatekeeper-system` shows only `gatekeeper` with chart `ztd-<version>`;
   the Deployments `gatekeeper-controller-manager`, `gatekeeper-audit` and `ztd-admission-provider`
   keep their UIDs and the Secret `ztd-admission-provider-tls` its CA; then the evidence pack
   (`scripts/admission/evidence-pack.sh <zone>`, no provider inputs needed in this layout).
6. **Rollback** to the standalone layout, if needed: `FROM_UMBRELLA=1 scripts/admission/install.sh`
   with the usual inputs. It checks them, drops release `gatekeeper`'s records while that release is
   still the umbrella's - every object stays and keeps serving - and installs `gatekeeper`,
   `admission` and `admission-pool` again with `--take-ownership`. It is resumable: an interrupted
   rollback is re-run with the same command; then set `admission.install: false` in the zone file again. `install.sh`
   applies the policy with kubectl, as it always has; on zone A and zone B Argo CD keeps owning it.

## The hook-weight scheme

Helm orders two things. Regular resources — of the chart and of every subchart together — are
created in Helm's fixed order of kinds, with no waiting between them. Hooks are ordered by
`helm.sh/hook-weight` within their phase, and Helm waits for each hook Job to finish before the next.
Nothing else is ordered, so the scheme is about hooks, and hooks are for Jobs: waits and checks.

Two rules follow from how Helm runs hooks:

- **A long-lived component is never a hook.** Hook resources are not tracked as part of the
  release and would survive `helm uninstall`.
- **Nothing a regular resource needs in order to become ready is a post-install hook.** With
  `--wait`, Helm runs the post-install hooks only after every regular resource is ready
  ([Helm, chart hooks](https://helm.sh/docs/topics/charts_hooks/)). A resource that waits for
  something a post-install hook creates therefore waits for a hook that waits for the resource,
  and the install times out.

Six bands of twenty weights, addressed by name so that the order between the jobs of different
components is a lookup and not a convention remembered by hand:

| Band | Weights | Jobs it holds |
|---|---|---|
| `preflight` | 0–19 | checks that must hold before anything is installed |
| `identity` | 20–39 | SPIRE: checks on the server, the trust bundle and the registration entries |
| `platform` | 40–59 | jobs of OpenBao (the `ztd-openbao` chart's verification hook, offset 10), Harbor, TSPA, estserver, observability and admission |
| `policy` | 60–79 | jobs of the mesh and admission policy that depends on identity and platform |
| `workloads` | 80–99 | jobs of the demonstrator workloads |
| `verification` | 100–119 | read-back checks that fail the release when the layout is wrong |

Helm runs the hooks of a phase from the lowest weight and stops at the first one that fails, so a
failed install names the earliest band that is wrong.

A component names its band and an offset inside it:

```yaml
metadata:
  annotations:
    {{ include "ztd.hook.annotations" (dict "phase" "post-install,post-upgrade" "band" "identity" "offset" 5) | nindent 4 }}
```

The helper refuses an unknown band or an offset outside the band at render time. The chart's own
post-install verification job is the first use of the scheme, in the `verification` band: it reads
the layout back through the API and fails the release if a plane namespace, its plane label, its
mesh label or its `default-deny` policy is missing, or if a control-plane namespace carries an
injection label. The `zone-policy` chart uses the `identity` band (20–39) through a copy of the
helper, so the scheme reads the same across the charts: `server-healthy` (20),
`trust-bundle-published` (25), `registrations-reconciled` (30). The `ztd-openbao` chart uses the
`platform` band through another copy: `ztd-verify-openbao` (50), whose ServiceAccount is a hook
of weight 49 so that Helm creates it just before the Job.

**The bands order jobs within a release; the installer orders the releases.** A zone is eight
releases (the umbrella, the SPIRE and Istio upstream charts, `zone-policy`, `ztd-openbao`), installed
in a fixed order by `scripts/install-zone/install.sh`, each waiting on the previous. A component
whose pods must hold a mesh identity from their first start is installed after `zone-policy`, as
OpenBao is: whatever the umbrella creates exists before istiod and the registration rule, so it
could never get a sidecar or an SVID at creation. Helm's hook weights only
order the hooks of one release, so the bands say where a job sits inside its own chart and what it
checks; which release's jobs run first is the installer's order. The installer is the unit that
reaches all-Ready from an empty cluster and repeats idempotently
([Deployment](deployment.md#installing-a-zone)).

**Identity before workloads.** The guarantee that a workload cannot become READY before its identity
exists does not come from a weight. It comes from two facts of the identity path. The SPIFFE CSI
volume is an ephemeral inline mount: the kubelet does not start the container until the driver,
which ships in the agent's DaemonSet, has bind-mounted the socket directory, so a workload cannot
even start on a node without the identity infrastructure. And the socket only answers once the
agent is up and a registration entry matches the workload, so a workload whose readiness depends on
holding its SVID is not READY until then. A registration is therefore a regular resource, which
the SPIRE controller-manager reconciles into an entry on the server, and never a post-install hook:
by the second rule above, a workload waiting for an entry that a hook creates would make
`helm install --wait` time out. The bands order the jobs around that path, the checks on identity
ahead of the checks on the workloads; the identity path is what makes the order a fact rather than
a hope.

## Zone values without defaults

`zone.kubernetesVersion`, `zone.storageClass` and `zone.loadBalancer.type` are facts about a cluster
that the cluster baseline records. The chart has no defaults for them and refuses to render until
the zone file states them, so a zone is never installed on assumed values. Where the mesh runs the
zone file also states `zone.trustDomain`, the zone's SPIFFE trust domain (the DNS zone delegated to
the trust zone; [Workload identity](workload-identity.md#the-trust-domain)), and enables the API
lane; the schema refuses a meshed zone without either. In sidecar mode the chart also refuses a
`zone.kubernetesVersion` below 1.33, because native sidecar containers need it. A zone that enables
Cilium also states `cni.cilium.version`, the Cilium version it is verified against (the tag of the
`cilium` DaemonSet's image without the leading `v`, bare `major.minor.patch`); the schema refuses a
zone with Cilium and without it, or with another form such as `v1.19.6`. The mesh identity proof
compares it with the running Cilium and fails on a difference, naming both, so that an upgrade of
Cilium by the provider is detected at the proof's next run. The zone files live in
`deployment/helm/ztd/zones/`; the CI chart job and the local kind cluster use
`deployment/helm/ztd/ci/values.yaml`, filled the same way with what that cluster is.

`zone.role` is `participant` (the default) or `demonstrator`; the schema refuses any other value, and
`scripts/ci/check-charts.sh` renders each case under `deployment/helm/ztd/ci/refused/` and expects the
refusal to name the value. A participant zone that installs the telemetry releases also states
`telemetryExport.entry` (the entry's address and this zone's port) and
`telemetryExport.revocationStatusListUrl`; the installer refuses those releases without them.

## Release namespace and teardown

Helm cannot own or label the namespace it installs into, so the release lives in `ztd-system`, a
namespace with no plane semantics that holds the release record and the hook jobs. The plane
namespaces belong to the release and go with `helm uninstall ztd -n ztd-system`; components
uninstall before the layout, in the reverse order of their installation.

The chart is cluster-scoped by nature. It creates the plane namespaces, the cluster role and binding
of its verification job, and, only in the parked ambient mode with Cilium (not in the sidecar
baseline of [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md)), one cluster-wide
Cilium policy; it ships no CRD (its Cilium policies are instances of Cilium's own CRDs and are
rendered only where Cilium is enabled). An identity confined to one namespace cannot install it.
That is the design point to settle before the umbrella replaces the fixture chart as the release
under test of the deployment-lifecycle scenarios (TDR-BDD-01 to TDR-BDD-04), whose deployer works
inside its pool namespaces and never creates one.

The CRDs of the identity path and of the mesh are not the umbrella's: each upstream chart is its own
release and installs, upgrades and removes the CRDs it ships in its templates (`spire-crds`, Istio's
`base`). A wrapper chart could not render a custom resource next to its CRD in one release, and
copying the CRDs into a wrapper's `crds/` folder would leave them never upgraded and never removed.
The installer's uninstall removes the CRDs Istio's `base` chart marks to be kept by Helm, so that
every CRD leaves with the release that brought it.

## Verifying it

Locally, `scripts/dev/kind-cilium-up.sh` gives a kind cluster with Cilium chained the way
the zones run it, and `scripts/verify-umbrella/verify.sh` produces the evidence: install from an
empty cluster in sidecar mode, the baseline, and assert the sidecar label with no ambient label and
no host-probe policy; install again to show nothing changes; read the layout back; prove with
stand-in pods that a data-plane workload reaches nothing in the management plane except through a
matrix lane; switch the live release to the parked ambient mode with the script's excursion fixture
(`ambient-values.yaml`) and assert the ambient label and the host-probe policy while the denial and
the lane still hold; return to sidecar and assert the baseline layout again; and tear down without
leaving a namespace behind. The last run's `evidence.md` sits next to the script.

The evidence also carries the negative proof of the CI chart gate. Section 8 shows the chart refused
without a zone file and with an unknown mesh mode by `helm lint` and by `helm template` alike, because
both validate the values against `values.schema.json`; and refused with the API lane enabled but no
CIDRs on a zone without Cilium (where the lane is an `ipBlock`) by `helm template` alone, because
that guard is a `fail` call in a template, and Helm's lint
mode renders `fail` as a no-op by design (Helm v4.3.0 logs the message at INFO and reports the chart
as passing). The "Chart lint and render" job runs lint and then template with `ci/values.yaml`, so
each of those cases is a red job: the schema cases at the lint step, the CIDR case at the render
step. The chart is verified with Helm v4.3.0, the version the pipeline pins. The release workflow's
chart gate (TDR-BDD-11) adds a server-side dry-run against a disposable cluster that serves the
Cilium and Gatekeeper CRDs, and no candidate is built unless it passes; a later chart publishing or
promotion job must need the same gate. The chart installs no OpenBao: the secret store is the
release `ztd-openbao`, the last of a zone, from `deployment/helm/ztd-openbao`
([Secrets](secrets.md)), and the schema refuses the values this chart once took for it.

The umbrella's evidence covers the layout alone; the identity path and the mesh installed into it,
with the eight releases, are proven by `scripts/verify-mesh-identity/verify.sh`
(what a run shows: `scripts/verify-mesh-identity/README.md`).

What waits for the client clusters is the first acceptance criterion — the layout on all three
clusters — and the per-zone values the baseline records, including the API endpoint for the
management-plane lane. The two OSC clusters are provided, and the mesh-identity proof has run on
zone A and zone B ([Open Sovereign Cloud — what has been run](environments/osc.md#what-has-been-run)).
The IONOS cluster is provided too, and `zones/ionos.yaml` is recorded from it, but the chart is not
installed there: that cluster holds no demonstration workload, its CNI is the provider-managed Calico
rather than the Cilium of [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md), and
SPIRE and the mesh there are in progress, with the Istio CNI plugin chained behind Calico ([the mesh
and SPIRE on each cluster](specifications.md#the-mesh-and-spire-on-each-cluster)). Until that work
installs them the IONOS zone file is validated against that cluster's API with a server-side dry
run, which persists nothing.
