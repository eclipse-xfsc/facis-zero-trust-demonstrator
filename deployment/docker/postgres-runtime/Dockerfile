# Rebuild gosu v1.19 with the patched Go toolchain; retain upstream privilege dropping.
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS gosu
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go install github.com/tianon/gosu@6456aaa0f3c854d199d0f037f068eb97515b7513 \
 && mkdir /out \
 && if [ -f /go/bin/gosu ]; then cp /go/bin/gosu /out/gosu; else cp /go/bin/${TARGETOS:-linux}_${TARGETARCH:-amd64}/gosu /out/gosu; fi

# PostgreSQL 16.15 on Alpine, independent of the local test fixture image.
FROM docker.io/library/postgres@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab
COPY --from=gosu /out/gosu /usr/local/bin/gosu
