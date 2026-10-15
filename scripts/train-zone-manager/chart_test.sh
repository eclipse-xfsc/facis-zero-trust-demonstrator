#!/usr/bin/env bash
# The TRAIN DNS zone manager chart (deployment/helm/train-zone-manager) on a throwaway kind cluster
# laid out like a zone: Cilium as the CNI, the ztd umbrella with its default deny and its API lane,
# a local registry so the image is installed by digest. Six cases, each with its positive and its
# negative half:
#
#   1 install        from an empty namespace the pod is ready, the zone answers from outside the cluster
#                    over UDP and TCP, the DS is recorded; a server that stops serving the zone is
#                    pulled from the Service
#   2 reinstall      uninstall and install again keep the volumes and the key; with the volumes gone
#                    the key changes and the recorded DS no longer matches
#   3 backup         a backup taken by the keeper restores the same key onto a fresh state volume
#   4 resign         the keeper's resign moves the signature dates; a wrong database path fails
#   5 ports, planes  UDP and TCP 53 on one Service; the API answers the management plane and is
#                    refused to the data plane; the namespace is the management plane
#   6 gates          the repository's chart gate passes the chart
#
# A FAIL fails the script. Lines of evidence go to stdout and, when EVIDENCE is set, to that file.
#
#   scripts/train-zone-manager/chart_test.sh         builds the image, creates the cluster, runs every case
#   IMAGE=<ref>      an image already built (default: builds ztd/train-zone-manager:test)
#   EVIDENCE=<file>  also write the evidence there       KEEP=1  leave the cluster and registry behind
#
# Needs docker, kind, kubectl, helm, dig and curl; pulls Cilium's chart and the kind node image.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
chart=deployment/helm/train-zone-manager
umbrella=deployment/helm/ztd
cluster=ztd-zone-manager
reg_name=ztd-zone-manager-registry
reg="$reg_name:5000"            # the registry's name inside the kind network, used in the image reference
host_reg=127.0.0.1:5002         # the same registry from this machine, for the push
CILIUM_VERSION=${CILIUM_VERSION:-1.20.2}
IMAGE=${IMAGE:-}
zone=trust.ztd.test
mgmt=ztd-mgmt; data=ztd-data; release=train-zone-manager
node_port=30053
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
failed=0

say() { printf '%s\n' "$*"; [ -n "${EVIDENCE:-}" ] && printf '%s\n' "$*" >> "$EVIDENCE" || true; }
pass() { say "PASS  $*"; }
fail() { say "FAIL  $*"; failed=1; }
note() { say "      $*"; }
step() { say "== $*"; }

cleanup() {
  if [ -n "${KEEP:-}" ]; then
    echo "kept: cluster $cluster, registry $reg_name, KUBECONFIG=$KUBECONFIG"
    return
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$reg_name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

for tool in docker kind kubectl helm dig curl; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
[ -n "${EVIDENCE:-}" ] && : > "$EVIDENCE"
say "# TRAIN DNS zone manager chart: $(date -u +%FT%TZ)"

# ---------------------------------------------------------------- cluster, registry, umbrella
step "Cluster: kind with Cilium (cni.exclusive=false), a registry on the kind network"
kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
docker rm -f "$reg_name" >/dev/null 2>&1 || true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 60s --config - >/dev/null <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
nodes:
  - role: control-plane
  - role: worker
KIND
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
for node in $(kind get nodes --name "$cluster"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg"
  printf '[host."http://%s"]\n' "$reg" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg/hosts.toml"
done
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" -n kube-system \
  --set cni.exclusive=false --set ipam.mode=kubernetes --set image.pullPolicy=IfNotPresent \
  --wait --timeout 10m >/dev/null
kubectl -n kube-system rollout status ds/cilium --timeout=5m >/dev/null
kubectl wait --for=condition=Ready nodes --all --timeout=5m >/dev/null
server=$(kubectl version -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')
note "cluster $cluster: Kubernetes $server, Cilium $CILIUM_VERSION, cni.exclusive=false"

step "Umbrella: the zone layout with its default deny and the API lane"
scripts/secrets/kind-api-lane.sh > "$work/api-lane.yaml"
helm upgrade --install ztd "$umbrella" -n ztd-system --create-namespace -f "$umbrella/ci/values.yaml" \
  -f "$work/api-lane.yaml" --set openbao.enabled=false --wait --wait-for-jobs --timeout 5m >/dev/null
note "umbrella installed: $(kubectl get ns "$mgmt" -o jsonpath='{.metadata.labels.ztd\.facis\.io/plane}') plane $mgmt, $(kubectl get ns "$data" -o jsonpath='{.metadata.labels.ztd\.facis\.io/plane}') plane $data"

step "Image: built, pushed to the registry, referenced by digest"
if [ -z "$IMAGE" ]; then
  IMAGE=ztd/train-zone-manager:test
  docker build --platform linux/amd64 -q -f deployment/docker/train-zone-manager/Dockerfile -t "$IMAGE" . >/dev/null
fi
docker tag "$IMAGE" "$host_reg/ztd/train-zone-manager:test"
docker push -q "$host_reg/ztd/train-zone-manager:test" >/dev/null
digest=$(curl -fsSI -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
  "http://$host_reg/v2/ztd/train-zone-manager/manifests/test" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')
note "image $reg/ztd/train-zone-manager@$digest"
worker_ip=$(kubectl get node "$cluster-worker" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
cp_ip=$(kubectl get node "$cluster-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
values=(--set image.repository="$reg/ztd/train-zone-manager" --set image.digest="$digest"
  --set zone.name="$zone" --set zone.address="$worker_ip" --set storage.className=standard
  --set service.dns.type=NodePort --set service.dns.nodePort="$node_port"
  --set api.issuerUrl=https://issuer.invalid/realms/trust --set api.clientId=trust-framework-manager)

install() { helm upgrade --install "$release" "$chart" -n "$mgmt" "${values[@]}" --wait --wait-for-jobs --timeout 5m; }
uninstall() { helm uninstall "$release" -n "$mgmt" --wait --timeout 3m >/dev/null; }
# the live pod: never one that is terminating after an upgrade
pod() { kubectl -n "$mgmt" get pod -l app.kubernetes.io/name=train-zone-manager -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.deletionTimestamp}{"\n"}{end}' | awk 'NF==1{print $1; exit}'; }
keeper() { kubectl -n "$mgmt" exec "$(pod)" -c keeper -- "$@"; }
served_ds() { keeper zone-keeper ds 2>/dev/null | awk '{print $5}'; }            # the key tag
recorded_ds() { kubectl -n "$mgmt" get configmap train-zone-manager-ds -o jsonpath='{.data.ds}' 2>/dev/null | awk '{print $5}'; }
q() { dig @"$1" -p "$node_port" +norecurse +time=3 +tries=1 +noall +comments +answer "${@:2}"; }
status_of() { grep -o 'status: [A-Z]*' | head -1 | cut -d' ' -f2; }
aa_of() { grep -q '^;; flags: qr aa' && echo aa || echo noaa; }
ready() { kubectl -n "$mgmt" get pod "$(pod)" -o jsonpath='{.status.containerStatuses[?(@.name=="zone-manager")].ready}' 2>/dev/null; }

# ---------------------------------------------------------------- 1 install
step "1 install"
if out=$(install 2>&1); then
  pass "1a helm install --wait succeeded; zone-manager ready=$(ready)"
else
  fail "1a helm install failed:"; printf '%s\n' "$out" | tail -8 | sed 's/^/      /'
  kubectl -n "$mgmt" get pods -o wide | sed 's/^/      /'; kubectl -n "$mgmt" describe pod -l app.kubernetes.io/name=train-zone-manager | tail -25 | sed 's/^/      /'
fi
for ip in "$worker_ip" "$cp_ip"; do
  udp=$(q "$ip" "$zone" SOA || true); tcp=$(q "$ip" +tcp "$zone" SOA || true)
  where=$([ "$ip" = "$worker_ip" ] && echo "worker node" || echo "control-plane node, cross-node")
  if [ "$(printf '%s' "$udp" | status_of)" = NOERROR ] && [ "$(printf '%s' "$udp" | aa_of)" = aa ] \
     && [ "$(printf '%s' "$tcp" | status_of)" = NOERROR ] && [ "$(printf '%s' "$tcp" | aa_of)" = aa ]; then
    pass "1b the zone answers from outside the cluster over UDP and TCP via the $where ($ip:$node_port)"
  else
    fail "1b no authoritative answer via the $where ($ip): udp=$(printf '%s' "$udp" | grep -E 'status|flags' | tr '\n' ' ') tcp=$(printf '%s' "$tcp" | grep -E 'status|flags' | tr '\n' ' ')"
  fi
done
ds_served=$(served_ds || true); ds_recorded=$(recorded_ds || true)
if [ -n "$ds_recorded" ] && [ "$ds_recorded" = "$ds_served" ]; then
  pass "1c the DS is recorded in the ConfigMap and matches the served key (tag $ds_served)"
else
  fail "1c DS record: recorded '$ds_recorded', served '$ds_served'"
fi
# Negative: a server that stops serving the zone is pulled from the Service. NSD is stopped inside
# the container (the zone manager process keeps running, so the pod does not restart); the probe
# must turn the pod NotReady and the Service must lose its endpoint, then NSD is started again.
kubectl -n "$mgmt" exec "$(pod)" -c zone-manager -- nsd-control stop >/dev/null 2>&1 || true
for _ in $(seq 1 40); do [ "$(ready)" = false ] && break; sleep 1; done
endpoints=$(kubectl -n "$mgmt" get endpointslices -l kubernetes.io/service-name=train-zone-manager-dns -o jsonpath='{range .items[*]}{range .endpoints[*]}{.conditions.ready}{" "}{end}{end}')
if [ "$(ready)" = false ] && ! printf '%s' "$endpoints" | grep -q true; then
  pass "1d a server that stops serving the zone is NotReady and has no ready endpoint (endpoints: '${endpoints:-none}')"
else
  fail "1d after NSD stopped: ready=$(ready), endpoints='$endpoints'"
fi
kubectl -n "$mgmt" exec "$(pod)" -c zone-manager -- sh -c 'service nsd start >/dev/null 2>&1; nsd-control reconfig >/dev/null && nsd-control reload >/dev/null'
for _ in $(seq 1 40); do [ "$(ready)" = true ] && break; sleep 1; done
note "NSD started again: ready=$(ready)"

# ---------------------------------------------------------------- 2 reinstall
step "2 reinstall"
tag_before=$(served_ds)
uninstall
pvcs=$(kubectl -n "$mgmt" get pvc -o name | grep -c train-zone-manager || true)
if [ "$pvcs" = 2 ]; then pass "2a helm uninstall left both claims behind (resource-policy keep)"; else fail "2a claims after uninstall: $pvcs (want 2)"; fi
if install >/dev/null 2>&1; then
  tag_after=$(served_ds)
  if [ -n "$tag_before" ] && [ "$tag_before" = "$tag_after" ]; then pass "2b reinstalled on the kept volumes: same key tag $tag_after"; else fail "2b key tag changed across reinstall: $tag_before -> $tag_after"; fi
else
  fail "2b helm install after uninstall failed"
fi

# ---------------------------------------------------------------- 3 backup
step "3 backup"
if keeper zone-keeper backup-now >"$work/backup.log" 2>&1; then pass "3a the keeper took a backup: $(tail -1 "$work/backup.log" | sed 's/.*backup ok: //')"; else fail "3a backup-now failed: $(tail -2 "$work/backup.log" | tr '\n' ' ')"; fi
uninstall
kubectl -n "$mgmt" delete pvc train-zone-manager-data --wait >/dev/null
if install >/dev/null 2>&1; then
  tag_restored=$(served_ds)
  restore_log=$(kubectl -n "$mgmt" logs "$(pod)" -c restore 2>/dev/null | tail -1)
  if [ "$tag_restored" = "$tag_before" ]; then pass "3b a fresh state volume was restored from the backup: same key tag $tag_restored ($restore_log)"; else fail "3b key tag after restore: $tag_restored (want $tag_before); restore said: $restore_log"; fi
else
  fail "3b helm install on a fresh state volume failed"
fi
# Negative for 2 and 3: with both volumes gone the key changes and the old DS record no longer matches.
uninstall
kubectl -n "$mgmt" delete pvc train-zone-manager-data train-zone-manager-backup --wait >/dev/null
if install >/dev/null 2>&1; then
  tag_fresh=$(served_ds)
  if [ -n "$tag_fresh" ] && [ "$tag_fresh" != "$tag_before" ]; then
    pass "3c with both volumes gone a new key is created: tag $tag_before -> $tag_fresh; the DS the parent would hold is now wrong"
  else
    fail "3c key tag after deleting both volumes: $tag_fresh (was $tag_before)"
  fi
  if [ "$(recorded_ds)" = "$tag_fresh" ]; then note "the DS record was rewritten by the hook to $tag_fresh; the parent's DS is what has to change next"; fi
else
  fail "3c helm install on fresh volumes failed"
fi

# ---------------------------------------------------------------- 4 resign
step "4 resign"
rrsig() { dig @"$worker_ip" -p "$node_port" +norecurse +dnssec +time=3 +tries=1 +noall +answer "$zone" SOA | awk '$4=="RRSIG" && $5=="SOA"{print $9; exit}'; }
exp_before=$(rrsig); sleep 1
if keeper zone-keeper resign-now >"$work/resign.log" 2>&1; then
  exp_after=$(rrsig)
  if [ -n "$exp_before" ] && [ "$exp_after" -gt "$exp_before" ]; then pass "4a resign-now moved the served SOA signature: $exp_before -> $exp_after"; else fail "4a signature did not move: $exp_before -> $exp_after"; fi
else
  fail "4a resign-now failed: $(tail -2 "$work/resign.log" | tr '\n' ' ')"
fi
if keeper zone-keeper resign-now sqlite:////tmp/missing.db >"$work/missing.log" 2>&1; then
  fail "4b resign-now against a missing database exited 0"
else
  pass "4b resign-now against a missing database fails loudly"
fi
if kubectl -n "$mgmt" logs "$(pod)" -c keeper | grep -q "daily: next run at"; then pass "4c the keeper's daily loop is scheduled: $(kubectl -n "$mgmt" logs "$(pod)" -c keeper | grep -m1 'next run at' | sed 's/.*daily: //')"; else fail "4c no daily schedule in the keeper's log"; fi

# ---------------------------------------------------------------- 5 ports and planes
step "5 ports and planes"
ports=$(kubectl -n "$mgmt" get svc train-zone-manager-dns -o jsonpath='{range .spec.ports[*]}{.port}/{.protocol} {end}')
if [ "$ports" = "53/UDP 53/TCP " ]; then pass "5a the DNS Service carries $ports on one address"; else fail "5a DNS Service ports: '$ports'"; fi
plane=$(kubectl get ns "$mgmt" -o jsonpath='{.metadata.labels.ztd\.facis\.io/plane}')
if [ "$plane" = management ]; then pass "5b the release namespace $mgmt is the management plane"; else fail "5b $mgmt plane label: '$plane'"; fi
api_probe='import sys,requests
try:
    r=requests.get("http://train-zone-manager-api.ztd-mgmt.svc:16001/status",timeout=5); print("http", r.status_code)
except Exception as e: print("denied", type(e).__name__)'
toolbox() { # namespace name -> prints the probe's output
  kubectl -n "$1" run "$2" --image="$reg/ztd/train-zone-manager@$digest" --image-pull-policy=IfNotPresent --restart=Never \
    --labels="istio.io/dataplane-mode=none" --annotations="sidecar.istio.io/inject=false" --overrides='{"spec":{"automountServiceAccountToken":false}}' \
    --command -- python3 -c "$api_probe" >/dev/null
  kubectl -n "$1" wait --for=jsonpath='{.status.phase}'=Succeeded pod/"$2" --timeout=60s >/dev/null 2>&1 || true
  kubectl -n "$1" logs "$2" 2>/dev/null | tail -1
  kubectl -n "$1" delete pod "$2" --now >/dev/null 2>&1 || true
}
mgmt_answer=$(toolbox "$mgmt" api-probe-mgmt)
case "$mgmt_answer" in http*) pass "5c the API answers a management-plane pod: $mgmt_answer" ;; *) fail "5c the API does not answer the management plane: '$mgmt_answer'" ;; esac
data_answer=$(toolbox "$data" api-probe-data)
case "$data_answer" in denied*) pass "5d the API is refused to a data-plane pod: $data_answer" ;; *) fail "5d the data plane reached the API: '$data_answer'" ;; esac

# ---------------------------------------------------------------- 6 gates
step "6 gates"
if scripts/ci/check-charts.sh "$chart" >"$work/gate.log" 2>&1; then pass "6a the chart gate (lint, render) passes the chart"; else fail "6a the chart gate failed:"; tail -5 "$work/gate.log" | sed 's/^/      /'; fi

say "# result: $([ $failed = 0 ] && echo 'all cases passed' || echo 'at least one case FAILED')"
exit $failed
