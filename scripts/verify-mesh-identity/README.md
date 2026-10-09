# verify-mesh-identity

Evidence that the mesh identities of a zone are SPIRE's, on the local kind cluster from
`scripts/dev/kind-cilium-up.sh` (Kubernetes v1.35.5, Cilium 1.20.2 with `cni.exclusive=false`).
`verify.sh` installs the zone from an empty cluster with `scripts/install-zone/install.sh`, twice,
runs the stand-in pods of `fixtures/stand-ins.yaml`, proves each check below, and tears the zone
down again. It writes `docs/evidences/mesh-identity/evidence.md` and `environment.json`; the files
in the repository are the output of the last run, on the commit and host `environment.json` names.

```bash
sudo sysctl -w fs.inotify.max_user_instances=512   # kind hosts: the Istio CNI agent needs it
scripts/dev/kind-cilium-up.sh
scripts/verify-mesh-identity/verify.sh             # destructive: uninstalls the zone first
scripts/verify-mesh-identity/verify.sh --help      # usage; touches nothing
```

The run uninstalls and reinstalls the zone, so it refuses any context that is not a kind cluster
(the context must be named `kind-<name>` and every node's provider ID must start with `kind://`).
It takes no arguments: `--help` or `-h` prints the usage, any other argument prints it and exits 2,
in both cases before the cluster is touched.

| Check | What it proves |
|---|---|
| `install-order-idempotent` | the seven releases install from an empty cluster with no manual step, every pod is Ready, every SPIRE and Istio image is pinned by digest, and a second run leaves every release's manifest identical |
| `svid-over-csi-socket` | a labelled pod mounts `csi.spiffe.io` and gets over that socket the SVID of its service account in the zone's trust domain, chained to the SPIRE CA; an unlabelled pod gets no entry and no SVID |
| `native-sidecar-version` | the server is 1.33 or later; the proxy is an init container with `restartPolicy: Always` |
| `mesh-identity-issued-by-spire` | read with `istioctl proxy-config secret`: the proxy's certificate has `O = SPIRE`, the SPIRE CA as issuer, the SVID's URI SAN; its `ROOTCA` bundle is the SPIRE CA, and istiod's CA did not issue it; a pod that chooses its injection templates, brings its own proxy without the SPIRE socket, or runs Istio's agent under another container name is refused at admission; so is, under the capture rule (`capture-at-injector-defaults`), a pod that excludes an application port from the capture, switches the capture off (`NONE`), moves the status port, overrides its proxy's configuration, opts out of injection, swaps its proxy's image or brings its own `istio-proxy` container, and, under the proxy rule, an `istio-proxy` of another image on the SPIRE socket, a second proxy under another name, and an `istio-proxy` of the injector's image with its own `postStart` hook or `NET_ADMIN` (next to the same pre-set status with nothing added, admitted), and, under the socket rule, an `istio-proxy` that mounts the SPIRE socket volume with a `subPath`, while a pod annotated `prometheus.io/scrape` and `prometheus.io/port` is admitted with the injector's `ISTIO_PROMETHEUS_ANNOTATIONS`, while an ordinary pod is admitted carrying the injector's status-port exclusion and `REDIRECT`, and the istiod and `istio-cni` pods, which opt out of injection, are admitted in `istio-system` (no injection label) and refused in the data plane; a label added to a running pod is admitted (an update is checked for what it changes), an added excluded port refused, the same through the `pods/status` subresource refused, a status update that changes no annotation admitted, and the removal of `sidecar.istio.io/status` from a running injected pod refused; outside the plane namespaces istiod's 15012 is not reachable; a certificate signed with istiod's CA key for the caller's SPIFFE ID is refused by the meshed peer, the caller's SPIRE SVID accepted |
| `unregistered-workload-cut-off` | an unlabelled pod's proxy has no certificate, its application never starts, and the peer refuses a call from its network namespace under STRICT; the labelled pod's call succeeds |
| `traffic-through-the-proxies` | the peer sees the caller's SPIFFE ID in `X-Forwarded-Client-Cert`; both proxies count the request, as mTLS |
| `default-deny-with-chained-cni` | the Istio plugin is chained after Cilium on the node, `cni-exclusive=false`, and the umbrella's cross-plane denial and matrix lane hold with the proxies in place |
| `control-planes-under-default-deny` | `spire-system` and `istio-system` hold only the declared openings; no SPIRE pod has a sidecar; every agent is attested; the proxies are SYNCED; a stand-in pod's TCP probes to the SPIRE server and istiod on every port but istiod's xDS port are denied; the agents' metrics port listens on each node's loopback only |

It also shows the identity-band checks of `zone-policy` passing on the install and failing the
release when a declared registration has no entry, the render guards (no trust domain, Kubernetes
below 1.33, no Cilium), and a teardown in reverse order that leaves no plane or control-plane
namespace, no SPIRE or Istio CRD and no admission webhook behind.

Needs `kind`, `kubectl`, `helm` (v4.3.0), the `cilium` CLI, `istioctl` 1.31.1, `jq`, `openssl`,
`python3` with PyYAML and `git`; the versions are recorded in `environment.json`. Run it on a clean
tree after the commit it should cite, and commit the two files it rewrites. It refuses to run under
CI (`CI` set): the evidence is the record of a run on a cluster, never written by a pipeline. The
exit status is non-zero when a check failed.

The stand-in pods run the images the umbrella's own verification uses (agnhost, curl) and SPIRE's
agent image as the Workload API client; nothing about them is consumed by a zone.

Three stand-ins have no proxy (`unregistered-svid` and the two `probe` pods): they opt out of
injection, which the capture rule refuses in a plane namespace. The proof shows them refused as
written, creates them with only the capture validation lifted from `proxy-takes-spire-socket`, puts
the validation back unchanged and shows them refused again, all in section 5 of the evidence. The
refusals are asked with a server-side dry-run create of a renamed copy of the three, so each is a
real admission request even once the stand-ins exist. If the run exits while the validation is
lifted (an interrupt included), its exit trap puts the validation back. The status port the
admitted-pod check expects is read from the installed `zone-policy` release
(`helm get values --all`), not from the chart's defaults.
