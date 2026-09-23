# First-party ORCE image for the FACIS ZTD deployment workflow: upstream ORCE plus the pinned
# Helm and kubectl the lifecycle Builder Node needs, the node itself, its flow, the lifecycle
# script and the lifecycle fixture chart. Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/orce/Dockerfile .
#
# Unlike the upstream image it does not run as root, removes the unauthenticated file browser
# rather than starting it, takes the Alpine security updates, and has no built-in credentials
# (see settings.js).
FROM ecofacis/xfsc-orce:2.0.13@sha256:52e4f98ff21a45225525057612f065ee8b32234f1f444d61cc83efded2949b80 AS orce

ARG HELM_VERSION=v4.3.0
ARG HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
ARG KUBECTL_VERSION=v1.35.8
ARG KUBECTL_SHA256=874d5e72dbb819f43cff16bcd1e4f8bac5b7f2361fe1e55049b0a6c676fb0cbf

USER root
RUN set -eux; \
    cd /tmp; \
    curl -fsSLo helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz"; \
    echo "${HELM_SHA256}  helm.tgz" | sha256sum -c -; \
    tar -xzf helm.tgz linux-amd64/helm; \
    install -m 0755 linux-amd64/helm /usr/local/bin/helm; \
    curl -fsSLo kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"; \
    echo "${KUBECTL_SHA256}  kubectl" | sha256sum -c -; \
    install -m 0755 kubectl /usr/local/bin/kubectl; \
    rm -rf /tmp/helm.tgz /tmp/linux-amd64 /tmp/kubectl; \
    apk upgrade --no-cache; \
    rm -f /usr/local/bin/filebrowser; \
    # The upstream demo flows carry a live cloud API token; this image loads its own flow file.
    rm -f /data/flows.json /data/.flows.json.backup /data/flows_cred.json; \
    mv /data/settings.js /data/settings.upstream.js

COPY deployment/docker/orce/settings.js /data/settings.js
COPY flows/lifecycle.json /data/lifecycle.json
COPY ui/nodes/ztd-lifecycle/ /data/nodes/ztd-lifecycle/
COPY scripts/lifecycle.sh /opt/ztd/scripts/lifecycle.sh
COPY features/fixtures/charts/lifecycle-fixture/ /opt/ztd/charts/lifecycle-fixture/

RUN chown -R node-red:node-red /data && chmod 0755 /opt/ztd/scripts/lifecycle.sh

# Flatten: deleting files in a layer leaves them readable in the layers below, and the upstream
# layers carry the demo flows' live credential. Only the cleaned filesystem is shipped.
FROM scratch
COPY --from=orce / /
ENV PATH=/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NODE_PATH=/usr/src/node-red/node_modules:/data/node_modules \
    HOME=/data
WORKDIR /data
USER node-red
EXPOSE 1880
ENTRYPOINT ["node", "/opt/maestro/MBE/packages/node_modules/node-red/red.js", "--userDir", "/data/", "--settings", "/data/settings.js"]
CMD []
