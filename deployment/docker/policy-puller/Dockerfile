# The policy package puller (cmd/policypuller): a static Go binary on an empty base, running as a
# non-root user. Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/policy-puller/Dockerfile .
FROM golang:1.27@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/policypuller/ cmd/policypuller/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/policypuller ./cmd/policypuller

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/policypuller /policypuller
USER 65532:65532
ENTRYPOINT ["/policypuller"]
