# TRAIN DNS zone manager: image and chart cases

Two scripts prove the zone manager's image and its chart, each case with its positive and its
negative half. Their PASS/FAIL lines are read by the `@image` and `@chart` regression features in
`features/go/`, and CI runs them in the "TRAIN zone manager image" and "TRAIN zone manager chart
(kind)" jobs.

| Script | What it proves | Where it runs |
|---|---|---|
| `image_test.sh` | The image in `deployment/docker/train-zone-manager`: built from the pinned upstream commit with its patches, starts and serves its zone over UDP and TCP, serves it again after a restart with the same keys, renews its signatures on command, refuses to be built unpatched (upstream issues #39, #40, #41) | Docker, no cluster |
| `chart_test.sh` | The chart in `deployment/helm/train-zone-manager`: installs into a zone laid out by the umbrella and serves the zone from outside the cluster, fixes the zone's own records to the address its LoadBalancer Service was given and does not start without one, is pulled from the Service when NSD stops, keeps its keys across `helm uninstall` and reinstall, restores them from the keeper's backup onto a fresh volume, re-signs on command and on schedule, keeps the API inside the management plane, passes the chart gate | A throwaway kind cluster with Cilium (its LoadBalancer IPAM standing in for the cloud's load balancer), the umbrella and a local registry, created by the script |

```bash
scripts/train-zone-manager/image_test.sh                       # builds the image, runs the 16 image checks
scripts/train-zone-manager/chart_test.sh                       # builds the image, creates the cluster, runs the chart cases
IMAGE=ztd/train-zone-manager:dev EVIDENCE=out.md scripts/train-zone-manager/chart_test.sh
```

Both take `IMAGE=` for an image already built and `EVIDENCE=` for a file to write the lines to;
`KEEP=1` leaves the container (image cases) or the cluster and registry (chart cases) behind for
inspection. The image cases need docker and dig; the chart cases also kind, kubectl, helm and curl,
and pull the kind node image and Cilium's chart. `evidence-image-2026-10-16.md` and
`evidence-chart-2026-10-16.md` are the records of the first passing runs on a developer machine.
