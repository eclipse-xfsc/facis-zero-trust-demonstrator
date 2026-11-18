# Container builds

Build contexts and Dockerfiles for the services in `services/`.

Images are built in CI, signed by digest, and admitted only if that signature and the accompanying
attestations verify.

`train-zone-manager/` is the one context that is not a service in `services/`: the upstream TRAIN DNS
zone manager, built from a pinned commit of `eclipse-xfsc/train-dns-trust-zone-manager` with the
patches in its `patches/` directory applied on top, because the image as shipped neither starts nor
serves its zone after a restart. Its cases, positive and negative, run in
`scripts/train-zone-manager/image_test.sh`.
