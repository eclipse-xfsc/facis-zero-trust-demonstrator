# Scripts

Bash automation — environment bootstrap, evidence collection, reset hooks.

Bash is the language for scripts under `scripts/` per the Technical Development Requirements.

| Script | What |
|---|---|
| `lifecycle.sh` | deploy or uninstall one Helm release: server-side dry run, then upgrade with rollback; the ORCE lifecycle node runs it |
| `install-zone/install.sh` | install, upgrade, render or uninstall a cluster from its zone file, each release through `lifecycle.sh`: a participant zone (ten releases, the telemetry collectors last) or the demonstrator cluster (the observability backends); `telemetry-client-certs` copies each zone's client certificate |
| `dev/kind-cilium-up.sh` | the local kind cluster with Cilium chained (`cni.exclusive=false`) |
| `dev/kind-cert-manager-up.sh` | cert-manager on kind (pinned), for the demonstrator role that shares the cluster |
| `verify-umbrella/verify.sh` | evidence for the umbrella chart alone on kind |
| `verify-mesh-identity/verify.sh` | evidence that the mesh identities are SPIRE's, the whole zone on kind |
| `verify-observability/verify.sh` | evidence that the observability stack collects, carries, stores and alerts within 30 s; kind, or a zone with the demonstrator cluster |
| `verify-observability/test-alert-rules.sh`, `check-rendered-images.sh` | the alert rules and the detection budget; the observability images pinned and licensed (no cluster, CI) |
| `mesh-mode/check-upstream-state.sh` | the upstream-state record behind ADR-0009 and its reopen check |
