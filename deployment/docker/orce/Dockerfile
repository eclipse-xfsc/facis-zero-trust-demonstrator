# First-party ORCE image for the FACIS ZTD deployment workflow: upstream ORCE plus the pinned
# Helm (built from source) and kubectl the lifecycle Builder Node needs, the node itself, its
# flow, the lifecycle script and the lifecycle fixture chart. Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/orce/Dockerfile .
#
# Unlike the upstream image it does not run as root, removes the unauthenticated file browser
# rather than starting it, takes the Alpine security updates, and has no built-in credentials
# (see settings.js).

# Helm is built from its tagged source on the same pinned Go toolchain as the first-party
# services, not taken from the release archive: a release binary carries the Go standard
# library of its release day until the next Helm release, and the image scan fails on every
# standard-library CVE fixed in between. Here a Go fix is a change of this one pin. The stage
# runs on the build host's platform and cross-compiles for linux/amd64.
FROM --platform=$BUILDPLATFORM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS helm

ARG HELM_VERSION=v4.3.0
ARG HELM_COMMIT=bec5b06ed841fe5269972d864d5177944fd5970f

# The clone is checked against the commit the tag names; the linker flags are those of Helm's
# own Makefile for a tagged, clean tree, so `helm version` reports the release as upstream's does.
RUN set -eux; \
    git clone --depth 1 --branch "${HELM_VERSION}" https://github.com/helm/helm.git /src; \
    cd /src; \
    [ "$(git rev-parse HEAD)" = "${HELM_COMMIT}" ]; \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-w -s \
        -X helm.sh/helm/v4/internal/version.version=${HELM_VERSION} \
        -X helm.sh/helm/v4/internal/version.metadata= \
        -X helm.sh/helm/v4/internal/version.gitCommit=${HELM_COMMIT} \
        -X helm.sh/helm/v4/internal/version.gitTreeState=clean" \
      -o /out/helm ./cmd/helm

FROM ecofacis/xfsc-orce:2.0.13@sha256:52e4f98ff21a45225525057612f065ee8b32234f1f444d61cc83efded2949b80 AS orce

ARG KUBECTL_VERSION=v1.35.8
ARG KUBECTL_SHA256=874d5e72dbb819f43cff16bcd1e4f8bac5b7f2361fe1e55049b0a6c676fb0cbf

USER root
COPY --from=helm /out/helm /usr/local/bin/helm
RUN set -eux; \
    cd /tmp; \
    curl -fsSLo kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"; \
    echo "${KUBECTL_SHA256}  kubectl" | sha256sum -c -; \
    install -m 0755 kubectl /usr/local/bin/kubectl; \
    rm -f /tmp/kubectl; \
    apk upgrade --no-cache; \
    rm -rf /usr/local/bin/filebrowser /data/filebrowser; \
    # The upstream demo flows carry a live cloud API token, and their encrypted credentials ship
    # with the key that decrypts them (.config.runtime.json). This image loads its own flow file,
    # and ORCE generates a fresh runtime key at first start. Upstream sessions, user settings and
    # caches go too.
    rm -f /data/flows.json /data/.flows.json.backup /data/flows_cred.json /data/.flows_cred.json.backup \
          /data/.config.runtime.json /data/.config.runtime.json.backup /data/.sessions.json \
          /data/.config.users.json /data/.config.users.json.backup; \
    rm -rf /data/.npm; \
    mv /data/settings.js /data/settings.upstream.js; \
    # The upstream settings stay as the base of ours, without their fixed or sample password hashes.
    sed -i -E 's/((password|pass): *")[$]2[aby][$][^"]*"/\1"/g' /data/settings.upstream.js; \
    # Guard: no credential store, session or password hash is left under /data outside node_modules.
    # Each check is a command substitution, so an error in find or grep fails the build (set -e)
    # instead of reading as "nothing found".
    left="$(find /data -maxdepth 1 \( -name '*cred*' -o -name '.sessions.json' -o -name '.config.runtime.json*' \))"; \
    [ -z "$left" ]; \
    hits="$(grep -rlE '[$]2[aby][$][0-9]{2}[$]|_credentialSecret' /data || [ $? -eq 1 ])"; \
    [ -z "$(printf '%s\n' "$hits" | grep -v '^/data/node_modules/' || true)" ]

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
