# TRAIN DNS zone manager: image cases

`image_test.sh` exercises the image in `deployment/docker/train-zone-manager` in Docker, with no
cluster: five cases, each with its positive and its negative half, one per defect the upstream image
ships with (upstream issues #39, #40 and #41). The `@image` regression feature in
`features/go/train-zone-manager.feature` reads its PASS/FAIL lines; CI runs it in the
"TRAIN zone manager image" job.

```bash
scripts/train-zone-manager/image_test.sh                 # builds the image, runs every case
EVIDENCE=evidence.md scripts/train-zone-manager/image_test.sh
IMAGE=ztd/train-zone-manager:dev scripts/train-zone-manager/image_test.sh   # an image already built
```

Needs docker and dig; the queries use port 15353 on 127.0.0.1 (`PORT=` changes it). `KEEP=1` leaves
the container and its volume behind for inspection. `evidence-2026-10-15.md` is the record of the
first passing run on a developer machine.
