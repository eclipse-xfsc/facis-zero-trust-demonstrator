#!/usr/bin/env bash
# Stand the upstream TRAIN DNS zone manager up on the local kind cluster (scripts/dev/kind-cilium-up.sh):
# built from its own Dockerfile at a pinned commit, installed with its own Helm chart, with the two
# changes that chart needs to run anywhere but its authors' cluster — a ReadWriteOnce volume (the
# template asks for ReadWriteMany, which kind's provisioner cannot give) and a fixed ClusterIP for the
# DNS service instead of a LoadBalancer. Prints the DS the zone manager generated at first start,
# which it writes to its log once and never again. Nothing here touches a client cluster.
#
#   KIND_CONTEXT   kubectl context                                     (default: kind-ztd)
#   UPSTREAM       checkout of eclipse-xfsc/train-dns-trust-zone-manager (default: fetched to a temp dir)
#   COMMIT         upstream commit to build, full SHA (git fetches by full SHA only)
#                  (default: a431f14…, main on 2026-10-06)
#   NAMESPACE      namespace for the release                           (default: train)
#   DNS_IP         ClusterIP of the DNS service, inside kind's range   (default: 10.96.0.53)
set -euo pipefail
cd "$(dirname "$0")"
CONTEXT=${KIND_CONTEXT:-kind-ztd}; NS=${NAMESPACE:-train}; DNS_IP=${DNS_IP:-10.96.0.53}
COMMIT=${COMMIT:-a431f148c4ef1f3c897385e99b463c556f271070}
IMAGE=ztd/train-dns-zone-manager:${COMMIT:0:7}
k() { kubectl --context "$CONTEXT" "$@"; }

UPSTREAM=${UPSTREAM:-}
if [ -z "$UPSTREAM" ]; then
  UPSTREAM=$(mktemp -d)/zm
  git init -q "$UPSTREAM"
  git -C "$UPSTREAM" fetch -q --depth 1 https://github.com/eclipse-xfsc/train-dns-trust-zone-manager.git "$COMMIT"
  git -C "$UPSTREAM" checkout -q FETCH_HEAD
fi
echo "upstream: $UPSTREAM at $(git -C "$UPSTREAM" rev-parse --short HEAD)"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  # The upstream base tag python:3.11 resolves to Debian 13 since 2025, whose python3-ldns is built
  # for the system Python 3.13; the image's own Python 3.11 then cannot import _ldns and the zone
  # manager dies at start. Debian 12 ships Python 3.11, so its ldns binding matches. Upstream issue #39.
  sed -i.orig 's/^FROM python:3\.11$/FROM python:3.11-bookworm/' "$UPSTREAM/Dockerfile"
  # script.sh starts NSD before it writes the config that includes the zone, and its second
  # `service nsd start` is a no-op on a running daemon, so NSD serves no zone after any start —
  # first or restart — until something calls nsd-control reconfig (every write does; nothing else
  # does). Make the start itself do it. Upstream issue #40.
  grep -q 'nsd-control reconfig' "$UPSTREAM/script.sh" || sed -i.orig \
    's|^mv /tmp/zonemgr.conf /etc/nsd/nsd.conf.d/zonemgr.conf$|&\nnsd-control reconfig \&\& nsd-control reload   # load the zone list now; NSD is already running|' \
    "$UPSTREAM/script.sh"
  echo "building $IMAGE from the upstream Dockerfile, base pinned to python:3.11-bookworm, NSD reconfig at start (a few minutes)"
  docker build -q -t "$IMAGE" "$UPSTREAM" >/dev/null
fi
kind load docker-image "$IMAGE" --name "${CONTEXT#kind-}" >/dev/null
echo "image: $IMAGE loaded into ${CONTEXT#kind-}"

k create namespace "$NS" --dry-run=client -o yaml | k apply -f - >/dev/null
helm template zonemanager "$UPSTREAM/deployment/helm/nsd" -n "$NS" -f values.yaml \
  --set image.tag="${COMMIT:0:7}" \
  --set application.properties.zoneConfig.TF_DOMAIN_IP="$DNS_IP" \
  --set application.properties.zoneConfig.PRIMARY_SERVER_IP="$DNS_IP" \
  --set application.properties.zoneConfig.SECONDARY_SERVER_1_IP="$DNS_IP" \
  --set application.properties.zoneConfig.SECONDARY_SERVER_2_IP="$DNS_IP" \
| awk -v ip="$DNS_IP" '
    /^---/                  { dns=0 }
    /^  name: .*-dns$/      { dns=1 }                                   # the DNS Service document
    /^    - ReadWriteMany$/ { $0="    - ReadWriteOnce" }                # kind gives ReadWriteOnce only
    { print }
    dns && /^  type: ClusterIP$/ { print "  clusterIP: " ip; dns=0 }    # the address the zone file names
  ' > rendered.yaml
k apply -n "$NS" -f rendered.yaml >/dev/null
# auth.conf is mounted with subPath, which never picks up a ConfigMap change: restart to be sure the
# pod runs what was just applied. The zone survives on the volume ("zone DB file found" in the log).
k -n "$NS" rollout restart deployment/nsd-service >/dev/null
k -n "$NS" rollout status deployment/nsd-service --timeout=180s >/dev/null
# the zone manager prints the DS once, when add-zone creates the keys at first start
for _ in $(seq 1 30); do
  ds=$(k -n "$NS" logs deployment/nsd-service 2>/dev/null | awk '$4=="DS"' || true)
  [ -n "$ds" ] && break; sleep 2
done
echo "DNS service: $DNS_IP (udp+tcp 53); REST: nsd-service-rest:16001 in namespace $NS"
echo "DS printed at first start (or none if the volume already held a zone):"
printf '%s\n' "${ds:-<none>}"
