# The proof-only echo service of the observability proof (tools/trace-echo): a static Go binary on an
# empty base, running as a non-root user. Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/trace-echo/Dockerfile .
FROM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY tools/trace-echo/ tools/trace-echo/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/trace-echo ./tools/trace-echo

FROM scratch
COPY --from=build /out/trace-echo /trace-echo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/trace-echo"]
