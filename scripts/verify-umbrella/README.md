# verify-umbrella

Evidence for the umbrella chart (`deployment/helm/ztd`) on the local kind cluster from
`scripts/dev/kind-cilium-up.sh`. `verify.sh` installs the chart from an empty cluster, installs it again to
show nothing changes, reads the layout back, proves with stand-in pods that a data-plane workload
reaches nothing in the management plane except through an allow-matrix lane, switches the mesh
mode from the sidecar baseline to the parked ambient mode and back, checks the lint and render
guards of the CI chart gate, and tears down without leaving a plane namespace behind. It writes `evidence.md` next to itself; `evidence.md` in the repository is the
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
baseline layout again. Ambient is parked, not abandoned, and this is where the repository proves
that the parked path still works.

The kind zone file also lists the two control-plane namespaces, `spire-system` and `istio-system`,
as management-plane namespaces without the mesh label, with the openings of the control planes;
the script asserts their layout and that they go with the release. The umbrella alone installs no
SPIRE and no Istio: the whole zone, the seven releases of `scripts/install-zone/install.sh`, is
proven by `scripts/verify-mesh-identity/verify.sh`.

The stand-in pods carry only the labels of the allow matrix; nothing else about them is real, and
none of their images is consumed by a zone.
