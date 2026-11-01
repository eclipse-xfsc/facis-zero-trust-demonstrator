# Container builds

Build contexts and Dockerfiles for the services in `services/` and for the policy package puller
(`cmd/policypuller`, deployed by `deployment/helm/policy-puller`).

Images are built in CI, signed by digest, and admitted only if that signature and the accompanying
attestations verify.
