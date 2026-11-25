FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/feed-bridge/ cmd/feed-bridge/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags='-s -w' -o /out/feed-bridge ./cmd/feed-bridge
FROM scratch
COPY --from=build /out/feed-bridge /feed-bridge
# The event schemas it validates every line against.
COPY docs/contracts/if01-event.v1.schema.json docs/contracts/if01-event.v2.schema.json /contracts/
USER 65532:65532
ENTRYPOINT ["/feed-bridge", "--contracts=/contracts", "--listen=:8090"]
