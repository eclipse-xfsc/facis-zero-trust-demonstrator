# ztd — umbrella chart for one zone

Lays a zone down before any component is installed: the plane namespaces, the network-layer
baseline, the allow-matrix lanes and the hook-weight bands that order the jobs of everything
installed after it. The design is described in
[docs/umbrella-chart.md](../../../docs/umbrella-chart.md); this file documents the chart itself.

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
policies, removed with the job by its hook policy) and, with `mesh.mode=ambient` and
`cni.cilium.enabled=true`, one CiliumClusterwideNetworkPolicy. It ships no CRD; the Cilium policies
are instances of Cilium's own CRDs and are rendered only where Cilium is enabled. Everything else is
namespaced and lives in the plane namespaces, including, with OpenBao on, the bootstrap Job's Role
(it may create Secrets in the management namespace and read and patch only its own) and, under
Cilium, its CiliumNetworkPolicy to the API server.

## Values

| Key | Default | Meaning |
|---|---|---|
| `zone.name` | none, required | Zone identifier (`zone-a`, `zone-b`, `ionos`, `kind`) |
| `zone.kubernetesVersion` | none, required | Server version recorded at stand-up; `scripts/verify-umbrella` asserts it |
| `zone.storageClass` | none, required | Storage class the zone provides to persistent components |
| `zone.loadBalancer.type` | none, required | `cloud`, `metallb` or `none` |
| `planes.management.namespace` | `ztd-mgmt` | Management-plane namespace |
| `planes.data.namespace` | `ztd-data` | Data-plane namespace |
| `planes.extra` | `[]` | Further `{name, plane}` namespaces that component tasks add |
| `mesh.mode` | `ambient` | `ambient`, `sidecar` or `none`; sets the namespace label only |
| `mesh.revision` | `""` | Sidecar mode: pin an Istio revision (`istio.io/rev`) instead of the default injector |
| `cni.cilium.enabled` | `true` | Render the Cilium-specific pieces (ambient host-probe exception) |
| `networkPolicy.defaultDeny` | `true` | Default deny, ingress and egress, in every plane namespace |
| `networkPolicy.dns.*` | kube-dns in `kube-system` | The declared DNS bypass, port 53 only |
| `networkPolicy.intraPlane` | `true` | Pods within one plane namespace may reach each other at L3/L4 |
| `networkPolicy.kubeApi.*` | off | Management-plane egress to the API server on `ports`: with Cilium a CiliumNetworkPolicy to the `kube-apiserver` entity on `ports` and 443 (`cidrs` optional), otherwise a NetworkPolicy to `cidrs` (required) |
| `allowMatrix` | the lanes of architecture §6 | Data-plane → management-plane lanes, as data (see below) |
| `verification.enabled` | `true` | Post-install job that reads the layout back and fails the release if it is wrong |
| `verification.image` | `curlimages/curl` by digest | Image of the verification job |
| `openbao.enabled` | `false` | Install OpenBao (chart 0.28.3, server v2.5.4) in the management plane; on in `ci/values.yaml` |
| `openbao.global.namespace` | `ztd-mgmt` | Must equal `planes.management.namespace`; the chart refuses to render otherwise |
| `openbao.server.dataStorage.storageClass` | `null` | Must equal `zone.storageClass` when OpenBao is on |
| `openbao.*` | see `values.yaml` | Passed to the upstream chart: standalone, file storage, no injector, no auth-delegator |
| `openbaoBootstrap.image` | `curlimages/curl` by digest | Image of the bootstrap Job and the OpenBao verification hook |
| `openbaoExternal.address` | `""` | An OpenBao the umbrella does not own; exclusive with `openbao.enabled` |
| `openbaoExternal.verifyTokenSecret` | `""` | Secret in the management namespace with its `verify-token` |

OpenBao, its bootstrap, the manual unseal after a restart and the secrets baseline are described in
[docs/secrets.md](../../../docs/secrets.md). Install with `--wait --wait-for-jobs`: the bootstrap is a
regular Job, and the OpenBao verification hook needs its result.

The zone record has no defaults on purpose and `values.schema.json` enforces it: the chart does
not render until a zone file states what the cluster is. `zones/` holds the zone files;
`ci/values.yaml` is the file the CI chart job and the local kind cluster render with.

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
`verification` band. Bands and rules are in the design page.

## Verify locally

```bash
scripts/dev/kind-cilium-up.sh               # kind with Cilium chained, cni.exclusive=false
scripts/verify-umbrella/verify.sh           # installs, re-installs, probes the policies, tears down
```

In CI, `helm lint` and `helm template` run with `ci/values.yaml`; the chart is verified with Helm
v4.3.0, the version the pipeline pins, and the sidecar mode is proven live by the evidence script.
