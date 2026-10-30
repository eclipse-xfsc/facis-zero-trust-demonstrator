# The connector (services/connector): a static Go binary on an empty base, running as a
# non-root user. Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/connector/Dockerfile .
#
# The build stage runs on the build host's platform and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY services/connector/ services/connector/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags='-s -w' -o /out/connector ./services/connector

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/connector /connector
USER 65532:65532
ENTRYPOINT ["/connector"]
