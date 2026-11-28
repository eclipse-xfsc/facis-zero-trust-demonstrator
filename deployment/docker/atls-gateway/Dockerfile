# The attested-channel gateway (cmd/connector-gateway): a static Go binary on an empty base,
# running as a non-root user. Built with the repository root as the context:
#   docker build --platform linux/amd64 -f deployment/docker/atls-gateway/Dockerfile .
# The image carries the gateway only; the zone's cmcd is a separate workload it reaches over gRPC.
# CGO is off, so CMC is built with its nodefaults,grpc tags: the gRPC attester stays, the
# in-process backend and the TEE drivers (one of them needs cgo) are left out
# (docs/attested-channel.md, "Attester selection and builds"). The binary is /atls-gateway, the
# path the zone's attestation configuration measures (deployment/attestation/<zone>.json).
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/connector-gateway/ cmd/connector-gateway/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -tags nodefaults,grpc -ldflags='-s -w' -o /out/atls-gateway ./cmd/connector-gateway
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/atls-gateway /atls-gateway
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/atls-gateway"]
