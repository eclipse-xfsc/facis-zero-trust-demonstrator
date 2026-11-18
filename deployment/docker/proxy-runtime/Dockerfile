# Istio 1.31.4: upstream security-patched sidecar and validation binaries, plus the distribution's APT security update.
# Use only with a compatible control plane; this does not upgrade a mesh installation.
FROM docker.io/istio/proxyv2@sha256:04f0f4a8d494f17ae6c67ee400194f646f90460a220811acaaedafb0c332dd1d
RUN apt-get update \
 && apt-get install -y --no-install-recommends apt=2.8.4ubuntu0.1 libapt-pkg6.0t64=2.8.4ubuntu0.1 \
 && rm -rf /var/lib/apt/lists/*
