# ztd — umbrella chart for one zone

Lays a zone down before any component is installed: the plane namespaces, the network-layer
baseline, the allow-matrix lanes and the hook-weight bands that order the jobs of everything
installed after it. The design is described in
[docs/umbrella-chart.md](../../../docs/umbrella-chart.md); this file documents the chart itself.

The chart is the first of the seven releases of a zone, installed with the others by
`scripts/install-zone/install.sh` (umbrella, `spire-crds`, `spire`, `istio-base`, `istiod`,
`istio-cni`, `zone-policy`). Alone, as the evidence script does:

```bash
helm upgrade --install ztd deployment/helm/ztd -n ztd-system --create-namespace \
  -f deployment/helm/ztd/zones/<zone>.yaml --wait
```

## Release namespace

Helm cannot own or label the namespace it installs into, so the release lives in a namespace of
its own (`ztd-system` above) that carries no plane semantics: it holds the release record and the
hook jobs, nothing else. The plane namespaces are created and labelled by the chart, and removed
by `helm uninstall`.

## Cluster-scoped footprint

Installing the chart needs rights beyond one namespace: it creates the plane namespaces, a
ClusterRole and ClusterRoleBinding for the verification job (read-only on namespaces and network
policies, removed with the job by its hook policy) and, only in the parked ambient mode
(`mesh.mode=ambient` with `cni.cilium.enabled=true`), one CiliumClusterwideNetworkPolicy. It ships
no CRD; its Cilium policies are instances of Cilium's own CRDs and are rendered only where Cilium is
enabled. In the sidecar baseline nothing cluster-wide beyond the namespaces and the verification
job's role is created. Everything else is namespaced and lives in the plane namespaces, the
control-plane namespaces included.

## Cilium requirement

With a mesh (`mesh.mode` other than `none`) the chart needs Cilium (`cni.cilium.enabled: true`) and
fails rendering otherwise: the openings of the control planes whose source is not a pod (the API
server, the host-networked SPIRE agents) and the API lane are `CiliumNetworkPolicy` objects by
entity, because a Kubernetes NetworkPolicy cannot name those sources. A zone on another CNI needs a
declared derogation of the preferred stack first (`docs/workload-identity.md`).

## Values

| Key | Default | Meaning |
|---|---|---|
| `zone.name` | none, required | Zone identifier (`zone-a`, `zone-b`, `ionos`, `kind`) |
| `zone.kubernetesVersion` | none, required | Server version recorded at stand-up; `scripts/verify-umbrella` asserts it |
| `zone.storageClass` | none, required | Storage class the zone provides to persistent components |
| `zone.loadBalancer.type` | none, required | `cloud`, `metallb` or `none` |
| `zone.trustDomain` | none; required where `mesh.mode` is not `none` | The zone's SPIFFE trust domain: the DNS zone delegated to the trust zone (`kind.facis-ztd.local` on kind). Read by the installer for SPIRE and the mesh; fixed at the first SPIRE install |
| `planes.management.namespace` | `ztd-mgmt` | Management-plane namespace |
| `planes.data.namespace` | `ztd-data` | Data-plane namespace |
| `planes.extra` | `[]` | Further `{name, plane, mesh}` namespaces: the control planes `spire-system` and `istio-system` (management, `mesh: false`) and any a component task adds. `mesh: false` leaves out the mesh label |
| `mesh.mode` | `sidecar` | `sidecar` (the ADR-0009 baseline), `ambient` (parked) or `none`; sets the namespace label. Sidecar mode refuses a `zone.kubernetesVersion` below 1.33 (native sidecars) |
| `mesh.revision` | `""` | Sidecar mode: pin an Istio revision (`istio.io/rev`) instead of the default injector |
| `cni.cilium.enabled` | `true` | Render the Cilium-specific pieces: the entity openings and the API lane, and the host-probe exception of the parked ambient mode. Required with a mesh |
| `networkPolicy.defaultDeny` | `true` | Default deny, ingress and egress, in every plane namespace |
| `networkPolicy.dns.*` | kube-dns in `kube-system` | The declared DNS bypass, port 53 only |
| `networkPolicy.intraPlane` | `true` | Pods within one plane namespace may reach each other at L3/L4 |
| `networkPolicy.kubeApi.*` | off | Management-plane egress to the API server on `ports`; required where `mesh.mode` is not `none`. With Cilium a policy to the `kube-apiserver` entity; without, an `ipBlock` to `cidrs`, a per-zone fact |
| `networkPolicy.meshControlPlane.*` | off; istiod (`app: istiod`) in `istio-system`, 15012 | Declared opening: every meshed plane namespace → istiod's xDS port (egress there, ingress in `istio-system`) |
| `networkPolicy.controlPlaneWebhooks.*` | off; entities `kube-apiserver`, `host`, `remote-node`; istiod 15017, controller-manager 9443 | Declared opening: the API server → the admission webhooks of both control planes (Cilium, by entity) |
| `networkPolicy.identityServer.*` | off; SPIRE server (`app.kubernetes.io/name: server`) in `spire-system`, 8081, entities `host`, `remote-node` | Declared opening: the host-networked SPIRE agents → the SPIRE server (Cilium, by entity) |
| `allowMatrix` | the lanes of architecture §6 | Data-plane → management-plane lanes, as data (see below) |
| `verification.enabled` | `true` | Post-install job that reads the layout back and fails the release if it is wrong |
| `verification.image` | `curlimages/curl` by digest | Image of the verification job |

The zone record has no defaults on purpose and `values.schema.json` enforces it: the chart does
not render until a zone file states what the cluster is. `zones/` holds the zone files;
`ci/values.yaml` is the file the CI chart job and the local kind cluster render with; it enables the
control-plane namespaces and every opening.

## Declared openings

Beside the DNS bypass, a meshed zone enables four openings for the control planes, each rendered
only when enabled and each documented in `docs/architecture.md` (section 6) and
`docs/workload-identity.md`:

| Opening | Rendered as |
|---|---|
| `meshControlPlane` | `allow-mesh-control-plane-egress` (NetworkPolicy) in each meshed plane namespace; `allow-mesh-control-plane-ingress` in `istio-system` |
| `controlPlaneWebhooks`, `identityServer` | `allow-control-plane-openings` (CiliumNetworkPolicy) in `istio-system` and `spire-system`, one per pod selector |
| `kubeApi` | `allow-kube-api-egress` in each management-plane namespace: a CiliumNetworkPolicy with Cilium, a NetworkPolicy without |

The Cilium rules set `enableDefaultDeny` false: they add their lane and leave the deny to
`default-deny`. Nothing else opens toward the control planes.

## Allow matrix as data

Each `allowMatrix` entry names a source (`from`) and a destination (`to`), each a plane (or an
explicit namespace) with a pod selector and optional ports, and renders two NetworkPolicies: an
egress rule in the source namespace and an ingress rule in the destination namespace. The
selectors are the label contract with the component charts (`app.kubernetes.io/name`), so a
component that lands under another name changes the matrix, not the templates. `enforcedBy`
records which layer the architecture holds responsible; the network lane is opened either way and
the mesh layer decides on identity on top.

## Hook-weight scheme

Six bands of twenty weights, addressed by name through the `ztd.hook.annotations` helper:

```yaml
metadata:
  annotations:
    {{ include "ztd.hook.annotations" (dict "phase" "post-install,post-upgrade" "band" "identity" "offset" 5) | nindent 4 }}
```

Hooks are for Jobs — waits and checks — never for long-lived components, which Helm would not
track as part of the release, and never for something a regular resource needs in order to become
ready, such as a registration: with `--wait`, Helm runs the post-install hooks only after every
regular resource is ready. The chart's own post-install verification job is the example, in the
`verification` band; it also fails the release if a control-plane namespace carries an injection
label. The `zone-policy` chart uses the `identity` band through a copy of the helper. The bands
order the jobs within a release; the installer orders the releases. Bands and rules are in the
design page.

## Verify locally

```bash
scripts/dev/kind-cilium-up.sh               # kind with Cilium chained, cni.exclusive=false
scripts/verify-umbrella/verify.sh           # installs, re-installs, probes the policies, tears down
scripts/verify-mesh-identity/verify.sh      # the zone with SPIRE and Istio: the seven releases
```

In CI, `helm lint` and `helm template` run with `ci/values.yaml` (sidecar, the ADR-0009 baseline);
the chart is verified with Helm v4.3.0, the version the pipeline pins. The evidence script installs
in sidecar mode and proves the parked ambient mode live, as an excursion and back.
