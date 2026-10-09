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

**Default deny at the network layer.** Every plane namespace gets a `default-deny` NetworkPolicy in
both directions. These openings follow, each declared in [Architecture §6](architecture.md), beside
the DNS bypass, and each rendered only when the zone enables it:

| Lane | Rendered as | Why it exists |
|---|---|---|
| workloads → DNS | `allow-dns-egress`, port 53 to the cluster resolver only | the declared DNS bypass |
| pods within one plane namespace | `allow-intra-plane` | who may talk is decided on identity by the mesh layer, not on IP |
| management → Kubernetes API (`kubeApi`) | `allow-kube-api-egress`: with Cilium a `CiliumNetworkPolicy` to the `kube-apiserver` entity on the API port; without Cilium an `ipBlock` egress to the zone's endpoint | the SPIRE server, its controller-manager and istiod call the API; required wherever the mesh runs |
| meshed plane namespaces → istiod (`meshControlPlane`) | `allow-mesh-control-plane-egress` in each namespace with the mesh label, `allow-mesh-control-plane-ingress` in `istio-system`, port 15012 | the sidecars fetch their configuration over xDS |
| API server → webhooks (`controlPlaneWebhooks`) | `allow-control-plane-openings` in `istio-system` (istiod, 15017) and `spire-system` (controller-manager, 9443), a `CiliumNetworkPolicy` from the `kube-apiserver`, `host` and `remote-node` entities | injection and the admission of `PeerAuthentication` and `ClusterSPIFFEID` |
| SPIRE agents → SPIRE server (`identityServer`) | in the same `allow-control-plane-openings` of `spire-system`, from the `host` and `remote-node` entities, port 8081 | the agents run on the host network and attest to the server |

The openings whose source is not a pod (the API server, the host-networked agents) are Cilium
policies by entity, because a Kubernetes NetworkPolicy cannot name those sources; with a mesh and
without Cilium the chart refuses to render and names the derogation another CNI needs. Each Cilium
rule adds its lane and leaves the deny to `default-deny` (`enableDefaultDeny` false). The reasoning
and the proof are in [Workload identity](workload-identity.md#openings-under-the-default-deny).

**The allow matrix, as data.** The lanes of the ZT-55 matrix are entries in `allowMatrix`, each
with a source and a destination selector; the chart renders an egress rule in the source namespace
and an ingress rule in the destination namespace for every lane. The selectors are the label
contract with the component charts:

| Lane | From (data plane) | To (management plane) |
|---|---|---|
| `pdp-adapter-to-tsa` | `app.kubernetes.io/name=pdp-adapter` | `tsa-policy-engine` |
| `atls-gateway-to-cmcd` | `atls-gateway` | `cmcd` |
| `atls-gateway-to-tcr` | `atls-gateway` | `tcr` |
| `workloads-to-otel-collector` | every data-plane pod | `otel-collector`, ports 4317 and 4318 only |
| `backend-to-verification-service` | `backend` | `verification-service` |

The identity provider's token endpoint is not a lane. No data-plane workload calls it: the
participant backend obtains its authorization from the connector, and Keycloak serves the viewer's
login and the pipeline ([Keycloak integration](keycloak.md#connector-boundary)). A permitted lane
without a caller would only widen what the matrix exists to limit.

The architecture names the mesh as the enforcing layer for these pairs. The network layer opens the
L3/L4 lane; the mesh layer, installed later, decides on identity on top. Anything else from the data
plane into the management plane is denied by both layers, which is the negative case the evidence
script proves.

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
| `platform` | 40–59 | jobs of OpenBao, Harbor, TSPA, estserver, observability and admission |
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
`trust-bundle-published` (25), `registrations-reconciled` (30).

**The bands order jobs within a release; the installer orders the releases.** A zone is seven
releases (the umbrella, the SPIRE and Istio upstream charts, `zone-policy`), installed in a fixed
order by `scripts/install-zone/install.sh`, each waiting on the previous. Helm's hook weights only
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
`zone.kubernetesVersion` below 1.33, because native sidecar containers need it. The zone files live in
`deployment/helm/ztd/zones/`; the CI chart job and the local kind cluster use
`deployment/helm/ztd/ci/values.yaml`, filled the same way with what that cluster is.

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

The evidence also carries the negative proof of the CI chart gate. Section 7 shows the chart refused
without a zone file and with an unknown mesh mode by `helm lint` and by `helm template` alike, because
both validate the values against `values.schema.json`; and refused with the API lane enabled but no
CIDRs on a zone without Cilium (where the lane is an `ipBlock`) by `helm template` alone, because
that guard is a `fail` call in a template, and Helm's lint
mode renders `fail` as a no-op by design (Helm v4.3.0 logs the message at INFO and reports the chart
as passing). The "Chart lint and render" job runs lint and then template with `ci/values.yaml`, so
each of those cases is a red job: the schema cases at the lint step, the CIDR case at the render
step. The chart is verified with Helm v4.3.0, the version the pipeline pins. The pipeline's criterion
that a chart failing lint or dry-run cannot be released rests on this proof until the packaging and
release work adds a chart publishing job, which is where that criterion closes.

The umbrella's evidence covers the layout alone; the identity path and the mesh installed into it,
with the seven releases, are proven by `scripts/verify-mesh-identity/verify.sh`
([the mesh identity evidence](evidences/mesh-identity/README.md)).

What waits for the client clusters is the first acceptance criterion — the layout on all three
clusters — and the per-zone values the baseline records, including the API endpoint for the
management-plane lane. The two OSC clusters are not yet provided. The IONOS cluster is, and
`zones/ionos.yaml` is recorded from it, but the chart is not installed there: that cluster holds no
demonstration workload and runs no mesh, its CNI is the provider-managed Calico rather than the
Cilium of [ADR-0009](adr/0009-service-mesh-mode-istio-sidecar-with-cilium.md), and whether it needs
Cilium and the mesh at all is a decision for its visualization stage. Until then the IONOS zone file
is validated against that cluster's API with a server-side dry run, which persists nothing.
