# The TRAIN DNS trust zone manager (eclipse-xfsc/train-dns-trust-zone-manager): the authoritative name
# server for the trust framework's zone and the API that writes its records. Built from the upstream
# source at a pinned commit with the patches in patches/ applied on top, because the upstream image as
# shipped neither starts nor serves its zone after a restart (upstream issues #39, #40 and #41;
# docs/train-dns.md, "Operating the zone manager"). Built with the repository root as the context:
#
#   docker build --platform linux/amd64 -f deployment/docker/train-zone-manager/Dockerfile .
#
# The base is Debian 12 (bookworm), not the upstream `python:3.11` tag: that tag moved to Debian 13,
# whose python3-ldns is built for Python 3.13, so the zone manager dies at `import ldns` (#39).
# The source stage uses the full image, which has git; the image that ships is the slim one.
ARG SOURCE_BASE=python:3.11-bookworm@sha256:5887f265d8d44d8b4734d3658b21d668edf5aaf92e4945bc0c984afbfab105d3
ARG BASE=python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89
ARG UPSTREAM_COMMIT=a431f148c4ef1f3c897385e99b463c556f271070
ARG UPSTREAM_URL=https://github.com/eclipse-xfsc/train-dns-trust-zone-manager.git

FROM ${SOURCE_BASE} AS source
ARG UPSTREAM_COMMIT
ARG UPSTREAM_URL
WORKDIR /src
# Fetch by full commit, never by branch, and refuse anything else than that commit.
RUN git init -q . \
 && git fetch -q --depth 1 "$UPSTREAM_URL" "$UPSTREAM_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && [ "$(git rev-parse HEAD)" = "$UPSTREAM_COMMIT" ]
COPY deployment/docker/train-zone-manager/patches/ /patches/
# A patch that no longer applies fails the build here, rather than producing an unpatched image.
RUN git apply --verbose /patches/*.patch

FROM ${BASE}
ARG UPSTREAM_COMMIT
# NSD is the name server; python3-ldns is the DNSSEC signing binding the zone manager needs and
# pip cannot provide; ldnsutils brings drill for the readiness probe and ldns-key2ds for the DS.
# No cron and no systemd: the deployment schedules the re-sign itself. The nsd package generates a
# control key pair as it installs; it would ship baked into every copy of the image, and NSD takes
# control over a local socket here (patch 0004), so the pair is removed in the same layer.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends nsd python3-ldns ldnsutils >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nsd/nsd_control.key /etc/nsd/nsd_control.pem /etc/nsd/nsd_server.key /etc/nsd/nsd_server.pem
WORKDIR /usr/lib/zonemgr
COPY --from=source /src/zonedb/ zonedb/
COPY --from=source /src/pyproject.toml /src/setup.cfg /src/reload-nsd.sh /src/script.sh ./
COPY deployment/docker/train-zone-manager/zone-ready.sh /usr/local/bin/zone-ready
COPY deployment/docker/train-zone-manager/zone-keeper.sh /usr/local/bin/zone-keeper
# ZM_PATH and VAR_PATH are the upstream names: the source tree, and the volume with the database, the
# zone file and the NSD zone list. PYTHONPATH reaches the Debian-packaged ldns binding.
ENV ZM_PATH=/usr/lib/zonemgr/ \
    VAR_PATH=/var/lib/zonemgr/ \
    PORT_ENV=16001 \
    PYTHONPATH=/usr/lib/python3/dist-packages/
# Editable install, as upstream: the API resolves auth.conf relative to its own source file, so the
# package has to stay in /usr/lib/zonemgr. setuptools is moved to a current release first (the base
# image's copy carries fixed HIGH findings); pip and wheel are removed once the install is done, since
# nothing installs at runtime and pip's vendored urllib3 and msgpack carry fixed HIGH findings of
# their own. The self-check runs after that removal, on what actually ships.
# auth.conf is the API's OIDC settings; the deployment mounts it, the image ships none. The CLI
# imports the API module, so even `resign` needs the file present: the self-check uses a throwaway.
RUN chmod 0755 script.sh reload-nsd.sh /usr/local/bin/zone-ready /usr/local/bin/zone-keeper \
 && mkdir -p "$VAR_PATH" \
 && pip3 install --no-cache-dir -q -U pip setuptools wheel \
 && pip3 install --no-cache-dir -q -e . \
 && pip3 uninstall -y -q pip wheel \
 && rm -rf /usr/local/lib/python3.11/ensurepip/_bundled \
 && python3 -c 'import ldns' \
 && printf 'ISSUER_URL = "https://issuer.invalid"\nCLIENT_ID = "none"\nALLOW_UNSAFE_SSL = "false"\n' > auth.conf \
 && dns-zone-manager-server --help >/dev/null \
 && rm auth.conf
LABEL org.opencontainers.image.title="train-dns-trust-zone-manager" \
      org.opencontainers.image.source="https://github.com/eclipse-xfsc/train-dns-trust-zone-manager" \
      org.opencontainers.image.revision="${UPSTREAM_COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0"
EXPOSE 53/udp 53/tcp 16001/tcp
# address.env is written by `zone-keeper address` before the first start when the zone's public
# address is discovered from the LoadBalancer Service rather than given; absent, nothing changes.
CMD ["/bin/bash", "-c", "[ -f \"$VAR_PATH/address.env\" ] && . \"$VAR_PATH/address.env\"; exec ./script.sh \"$PORT_ENV\""]
