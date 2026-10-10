# verify-tspa-api

Reproducible check of the TSPA (TRAIN Trust Framework Manager) trust-list publish API. Documentation and
findings: [docs/tspa-publish-api.md](../../docs/tspa-publish-api.md).

- `kind-up.sh` / `kind-down.sh` — bring up and remove a local TSPA: kind cluster `ztd-tspa`, upstream's image
  built from its Dockerfile, upstream's Helm chart with `values-kind.yaml`, and Keycloak (`keycloak.yaml`)
  with upstream's test realm. Needs `TSPA_REPO` pointing at a clone of
  `eclipse-xfsc/train-trust-framework-manager` with `eclipse-xfsc/train-shared` cloned into its `shared/`.
- `roundtrip.sh` — writes, reads back, updates and deletes one entry against that TSPA; appends every
  request/response to `evidence.md`. Reads the test client's secret from the same `TSPA_REPO`.
- `payloads/` — framework, trust-list init and two entry versions (measurement `1111…` and `2222…`).
- `evidence.md` — output of the last run (2026-10-08, kind; every status and check identical to the
  2026-09-18 run).
- `tcr-findings/` — out-of-scope finding about the read side (TCR), with a candidate upstream patch.
