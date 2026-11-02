# Container builds

Build contexts and Dockerfiles for the services in `services/`.

Images are built in CI, signed by digest, and admitted only if that signature and the accompanying
attestations verify.

`trace-echo/` builds the observability proof's instrumented echo (`tools/trace-echo`), which is never
part of a zone; it is built, scanned and signed with the others.
