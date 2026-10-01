# verify-tspa-api

Reproducible check of the TSPA (TRAIN Trust Framework Manager) trust-list publish API. Documentation and
findings: [docs/tspa-publish-api.md](../../docs/tspa-publish-api.md).

- `roundtrip.sh` — writes, reads back, updates and deletes one entry against a local TSPA; appends every
  request/response to `evidence.md`. Needs `TSPA_REPO` pointing at a clone of
  `eclipse-xfsc/train-trust-framework-manager` (the bundled Keycloak realm is read from it).
- `payloads/` — framework, trust-list init and two entry versions (measurement `1111…` and `2222…`).
- `docker-compose.override.yml` — copy next to the TSPA `docker-compose.yml` before `docker compose up`.
- `evidence.md` — output of the last run (2026-09-18).
- `tcr-findings/` — out-of-scope finding about the read side (TCR), with a candidate upstream patch.
