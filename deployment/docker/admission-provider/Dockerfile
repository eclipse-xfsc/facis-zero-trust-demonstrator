# The Gatekeeper external-data provider (services/admission-provider): a static Go binary on an
# empty base, running as a non-root user. Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/admission-provider/Dockerfile .
FROM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY services/admission-provider/ services/admission-provider/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/admission-provider ./services/admission-provider

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/admission-provider /admission-provider
USER 65532:65532
EXPOSE 8443 9090
ENTRYPOINT ["/admission-provider"]
