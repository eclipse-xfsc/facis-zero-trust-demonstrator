# Container builds

Build contexts and Dockerfiles for the services in `services/`.

Images are built in CI, signed by digest, and admitted only if that signature and the accompanying
attestations verify.

Runtime dependencies are packaged separately from application binaries. `envoy-runtime` retains
Envoy 1.36.10 and updates its pinned OpenSSL packages. `postgres-runtime` uses PostgreSQL 16.15 and
rebuilds the same upstream gosu source with the patched Go toolchain. `proxy-runtime` retains the
upstream Istio 1.31.3 image contents; selecting it for a workload does not update its control plane.

The proxy's `vex.json` attributes four historical alerts to their actual fixed release. It matches
only the exact upstream Go module pseudo-version for release 1.31.3, not all Istio versions or any
image directory. The source revision matches the upstream release tag and `pilot-agent version`.
Each statement links the upstream fixed-version advisory. CI displays suppressed findings; other
HIGH/CRITICAL findings still fail. These are packaging-project statements, not upstream signatures.
