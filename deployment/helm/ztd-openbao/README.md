# ztd-openbao — the secret store of one zone

OpenBao (ZT-11, [ADR-0004](../../../docs/adr/0004-openbao-as-x509-key-value-store.md)) as a release
of its own: `ztd-openbao`, the eighth and last release of a zone (`scripts/install-zone/install.sh`),
installed into the management-plane namespace after `zone-policy`. Being last is the point: the
injector, the registration rule and SPIRE exist when its pods are created, so the server, the
bootstrap Job and the verification hook each start with a sidecar, a SPIRE entry and an SVID, and
the server's traffic inside the management plane is mesh mTLS. The design is in
[docs/secrets.md](../../../docs/secrets.md).

The chart wraps the upstream `openbao` chart 0.28.3 (OpenBao v2.5.4), a dependency locked in
`Chart.lock`, its archive pinned by the sha256 in `dependencies.sha256`
(`scripts/ci/verify-chart-dependencies.sh` checks it after every `helm dependency build`), and adds:

- **the bootstrap Job** `ztd-openbao-bootstrap-<hash>`, a regular Job (not a hook: a sealed server is
  not ready, and with `--wait` Helm runs post-install hooks only once every regular resource is
  ready), with its ServiceAccount, Role and RoleBinding, and under Cilium a `CiliumNetworkPolicy` to
  the `kube-apiserver` entity for its pods. It initialises the server once, keeps the unseal key in
  the Secret `ztd-openbao-bootstrap`, unseals, enables KV version 2 at `secret/` and transit at
  `transit/`, issues a narrow periodic verification token and revokes the root token. It first
  waits until the server pod runs the StatefulSet's update revision, read once the StatefulSet's
  controller has seen the current spec (its Role reads that one StatefulSet and that one pod), so
  on an upgrade it unseals the new pod, not the one being replaced; a sealed pod of the previous
  revision, which the StatefulSet would not replace, it unseals first. Its name
  hashes the script and the whole of the values: an upgrade that changes a value (and so may
  restart the server sealed) runs it again and unseals the server; an unchanged upgrade renders the
  same name;
- **the verification hook** `ztd-verify-openbao`, with a ServiceAccount of its own of the same name
  (no role, no API token; a hook too, weight 49, so it is created just before the Job and even an
  external-mode release holds hooks only), post-install and post-upgrade, `platform` band
  offset 10 (weight 50; `templates/_hooks.tpl` is a copy of the umbrella's helper), which fails the
  release unless the server is initialised and unsealed with both engines, and with the bundled
  server reads the fixture value (a hash, never the value) and round-trips the fixture transit key;
- **the identity label** `spiffe.io/spire-managed-identity: "true"` on the server pods
  (`openbao.server.extraLabels`) and on both jobs' pods;
- **the node pin**, off by default (below).

Install it with `--wait --wait-for-jobs` into the management namespace the umbrella created. The
installer does, and fills the zone facts:

```bash
scripts/install-zone/install.sh render ztd-openbao      # with the zone file's facts, no cluster
```

By hand, as the secrets baseline does on a cluster without a mesh:

```bash
helm dependency build deployment/helm/ztd-openbao
scripts/ci/verify-chart-dependencies.sh deployment/helm/ztd-openbao
helm upgrade --install ztd-openbao deployment/helm/ztd-openbao -n ztd-mgmt \
  -f deployment/helm/ztd-openbao/ci/values.yaml --set cilium.enabled=false --wait --wait-for-jobs
```

## Values

| Value | Default | Meaning |
|---|---|---|
| `managementNamespace` | `ztd-mgmt` | The management-plane namespace (zone fact `planes.management.namespace`); the bootstrap and the hook go there |
| `global.pin.node` | `""` | The node the server and both jobs must run on (required node affinity on `kubernetes.io/hostname`); empty: no pin. Temporary, participant zones only (below) |
| `cilium.enabled` | `true` | Open the bootstrap Job's API lane with a `CiliumNetworkPolicy` (zone fact `cni.cilium.enabled`); without Cilium the umbrella's `networkPolicy.kubeApi` lane must be open |
| `openbao.global.enabled` | `false` | Every upstream piece off unless turned on by name, so external mode renders nothing upstream |
| `openbao.global.namespace` | `ztd-mgmt` | Zone fact `planes.management.namespace`; must equal `managementNamespace`, the chart refuses to render otherwise |
| `openbao.server.enabled` | `true` | The bundled server; `false` to verify an external OpenBao. Exclusive with `external.address` |
| `openbao.server.dataStorage.storageClass` | `null` | Zone fact `zone.storageClass`; required with the bundled server |
| `openbao.server.extraLabels` | the identity label | Labels of the server pods; the identity label makes them declared workloads under `zone-policy` |
| `openbao.server.affinity` | node pin or the upstream anti-affinity | A template evaluated by the upstream chart: the node affinity of `global.pin.node` when set |
| `openbao.server.updateStrategyType` | `RollingUpdate` | Not the upstream `OnDelete`: an upgrade that changes the pod template restarts the server, and the rerun bootstrap unseals it |
| `openbao.*` | see `values.yaml` | Passed to the upstream chart: standalone, file storage, one replica, image pinned by digest, no injector, no auth-delegator |
| `bootstrap.image` | `curlimages/curl` by digest | Image of the bootstrap Job and the verification hook |
| `external.address` | `""` | An OpenBao the zone does not own, `https://` only (the hook sends its token there); exclusive with `openbao.server.enabled` |
| `external.verifyTokenSecret` | `""` | Secret in the management namespace with its `verify-token`; required with `external.address` |

`values.schema.json` refuses unknown top-level keys and both modes at once: rendering with the
bundled server and `external.address` fails naming `openbao.server.enabled and external.address are
exclusive`.

## The two modes

- **Bundled** (the default): the upstream server, the bootstrap Job and the verification hook.
- **External**: `openbao.server.enabled: false`, `external.address` and
  `external.verifyTokenSecret` set. Nothing is installed or initialised; only the verification hook
  runs against that address (health, unseal state, the two engines).

## The node pin

On the participant clusters of zone A and zone B the provider's pod network masquerades pod traffic
between nodes, so a meshed pod on another node than istiod never passes its proxy's readiness. Their
zone files set `openbao.pinToMeshNode: true`; the installer then reads istiod's node after the istiod
release and sets `global.pin.node` to it (`istiod-node-not-found`, which matches no node, when istiod
has none; `render` uses that placeholder). The value sits under `global` because Helm passes a
parent's values to a subchart only there, so one value pins the server and both jobs. The pin is
temporary: it falls when the provider's network is fixed (`docs/environments/osc.md`). The kind zone
is not pinned.

## The manual unseal

OpenBao seals itself on every restart. The bootstrap unseals it on install and on an upgrade that
changes a value; after a restart the lifecycle did not cause (an eviction, a node reboot), the server
stays sealed and not ready until `scripts/secrets/unseal.sh` is run. This is declared in
`docs/specifications.md` as a reading of the TDR's "zero manual intervention" rule.

Uninstalling the zone removes this release first; the umbrella's uninstall then deletes the
management namespace with the volume and the bootstrap Secret, a destructive reset of the store.
