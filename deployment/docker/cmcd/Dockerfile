# The zone's attester, CMC's cmcd (github.com/Fraunhofer-AISEC/cmc), at the version go.mod pins: a
# static Go binary on an empty base, running as a non-root user. Built with the repository root as
# the context:
#   docker build --platform linux/amd64 -f deployment/docker/cmcd/Dockerfile .
# The build reads the pinned version from go.mod and builds cmcd in a scratch module, because the
# repository module does not carry cmcd's own dependencies in its go.sum. CGO is off, so the build
# uses CMC's tags: nodefaults drops every TEE driver (one needs cgo), sw keeps the software driver
# that signs the zone's mock evidence (ADR-0011), grpc keeps the API the gateway speaks, and socket
# is required by cmcd's gRPC server at this version (its Sign helper lives behind that tag). The
# configuration selects the gRPC API; nothing listens on the socket API.
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN set -eu; v=$(go list -m -f '{{.Version}}' github.com/Fraunhofer-AISEC/cmc); \
    mkdir /build && cd /build && go mod init cmcd-build >/dev/null 2>&1 && \
    go get "github.com/Fraunhofer-AISEC/cmc/cmcd@$v" && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -tags nodefaults,grpc,socket,sw -ldflags='-s -w' -o /out/cmcd github.com/Fraunhofer-AISEC/cmc/cmcd
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/cmcd /cmcd
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/cmcd"]
