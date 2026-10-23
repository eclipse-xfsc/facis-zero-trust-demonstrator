FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOAMD64=v1 \
    GOTOOLCHAIN=local \
    GOWORK=off

COPY go.mod go.sum ./
COPY cmd/protected-resource/ ./cmd/protected-resource/
COPY services/protectedresource/ ./services/protectedresource/
# The token verifier and what it builds on (internal/tokenverify, dpopproof, replay, jose).
COPY internal/ ./internal/

RUN go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w" -o /out/protected-resource ./cmd/protected-resource

FROM scratch

COPY --from=build --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0555 /out/protected-resource /app/protected-resource

WORKDIR /app
ENV PROTECTED_RESOURCE_ADDRESS=:8086 \
    PROTECTED_RESOURCE_MODE=sample \
    PROTECTED_RESOURCE_ADAPTER_MODE=sample \
    PROTECTED_RESOURCE_REQUEST_TIMEOUT=5s \
    PROTECTED_RESOURCE_SLOW_DELAY=2s \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Orchestrator/CI health probe: HTTP GET /health on port 8086.
USER 65532:65532
EXPOSE 8086/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/protected-resource"]
