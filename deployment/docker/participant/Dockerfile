FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOAMD64=v1 \
    GOTOOLCHAIN=local \
    GOWORK=off

COPY go.mod go.sum ./
COPY cmd/participant/ ./cmd/participant/
COPY services/participant/ ./services/participant/

RUN go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w" -o /out/participant ./cmd/participant

FROM scratch

COPY --from=build --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0555 /out/participant /app/participant

WORKDIR /app
ENV PARTICIPANT_ADDRESS=:8085 \
    PARTICIPANT_ADAPTER_MODE=http-sample \
    PARTICIPANT_REQUEST_TIMEOUT=5s \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Required at runtime: PARTICIPANT_RESOURCE_URL=<actual Resource base URL>.
# Orchestrator/CI health probe: HTTP GET /health on port 8085.
USER 65532:65532
EXPOSE 8085/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/participant"]
