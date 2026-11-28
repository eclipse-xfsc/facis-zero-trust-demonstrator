# git daemon for the TSA policy service's start-up clone (deployment/helm/tsa-policy): the TSA's
# in-memory storage must clone a Git repository before it serves; the chart serves it an empty
# bootstrap repository on loopback, so no policy is active until a verified bundle is imported.
FROM docker.io/library/alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN apk add --no-cache git-daemon=2.49.1-r0
USER 65532:65532
ENTRYPOINT ["git"]
