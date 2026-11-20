# verify-umbrella

Evidence for the umbrella chart (`deployment/helm/ztd`) on the local kind cluster from
`scripts/dev/kind-cilium-up.sh`. `verify.sh` installs the chart from an empty cluster, installs it again to
show nothing changes, reads the layout back, proves with stand-in pods that a data-plane workload
reaches nothing in the management plane except through an allow-matrix lane, switches the mesh
mode from the sidecar baseline to the parked ambient mode and back, probes the management plane's
API lane under Cilium (open from the management plane, shut from the data plane), checks the lint
and render guards of the CI chart gate, and tears down without leaving a plane namespace behind. It writes `evidence.md` next to itself; `evidence.md` in the repository is the
output of the last run.

```bash
scripts/dev/kind-cilium-up.sh
scripts/verify-umbrella/verify.sh
```

The chart installs in sidecar mode, the baseline of ADR-0009, from `deployment/helm/ztd/ci/values.yaml`,
the file the chart's own CI render uses: the baseline checks assert `istio-injection=enabled` on
every plane namespace, no ambient label and no cluster-wide Cilium host-probe policy.
`ambient-values.yaml` is the kind zone in ambient mode, the excursion fixture of this script only:
the mode leg switches the live release to it, asserts the ambient label and the host-probe policy
while the cross-plane denial and the matrix lane still hold, returns to sidecar and asserts the
baseline layout again. Ambient with Cilium is parked, not abandoned, and this is where the
repository proves that the parked path still works.

Section 8b renders, without installing, the demonstrator cluster's zone file
(`deployment/helm/ztd/zones/ionos.yaml`, ambient on the provider's Calico without SPIRE under the
declared derogation `cni.derogation: calico-ambient`, ADR-0018) with the documentation-range
overlay `deployment/helm/ztd/ci/ionos.overlay.yaml`: no Cilium object, exactly the declared openings
(istiod 15017 from the webhook source pods, istiod 15012 from ztunnel, the probe lane from
169.254.7.127 in each meshed plane namespace, the API lane in each management-plane namespace), no
other ingress to `istio-system`, the HBONE port 15008 on an allow-matrix lane with ports, and the
refusals: ambient without Cilium and without the derogation, the derogation without the API
addresses or the webhook source, and a sidecar zone with the derogation. That cluster's mesh is
proven on the cluster by `scripts/verify-ambient-mesh/verify.sh`. The `evidence.md` in the
repository predates these cases; the next run on kind records them.

The kind zone file also lists the two control-plane namespaces, `spire-system` and `istio-system`,
as management-plane namespaces without the mesh label, with the openings of the control planes;
the script asserts their layout and that they go with the release. The umbrella alone installs no
SPIRE, no Istio and no OpenBao: the whole zone, the eight releases of
`scripts/install-zone/install.sh`, is proven by `scripts/verify-mesh-identity/verify.sh`. The
stand-in `openbao-standin` carries only the allow-matrix label of the store; the store itself is the
release `ztd-openbao`.

The stand-in pods carry only the labels of the allow matrix; nothing else about them is real, and
none of their images is consumed by a zone.
