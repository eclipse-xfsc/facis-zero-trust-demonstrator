# Preserve Envoy v1.36.10 and apply the distribution's OpenSSL security update.
FROM docker.io/envoyproxy/envoy@sha256:3a76238cdf52c7a3e33951f44c02d694108e6481feffe6663bf9319f55ec1394
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3=3.0.2-0ubuntu1.30 openssl=3.0.2-0ubuntu1.30 \
 && rm -rf /var/lib/apt/lists/*
