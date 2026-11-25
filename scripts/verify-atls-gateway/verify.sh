#!/usr/bin/env bash
# The attested-channel gateway between two zones (ZT-28, ZT-65): two kind clusters, zone A and zone
# B, each a participant zone installed by scripts/install-zone (umbrella, SPIRE, Istio, zone-policy),
# plus the zone's attester (release ztd-cmcd, deployment/helm/cmcd) and the gateway (release
# ztd-atls-gateway, deployment/helm/atls-gateway), both built from the working tree. Each zone's
# evidence is provisioned the way the pipeline does it (docs/attestation-provisioning.md): rendered
# from deployment/attestation/<zone>.json, signed with CMC's metatool under a metadata CA created for
# the run, and handed to the zone as a Secret. Then:
#
#   startup     each gateway role verified its own zone's evidence against Git before serving
#   A -> B      a caller in zone A reaches an echo in zone B through A's egress and B's ingress over a
#               mutually attested channel: one HTTP answer, both ends recording the same channel
#               binding, TLS 1.3, the peer identity each expected
#   B -> A      the same the other way
#   plain TLS   a TLS client without the zone PKI and without attestation, reaching B's entry from
#               outside the mesh, is refused at the handshake, and the refusal is recorded
#   attester    with zone A's cmcd scaled to zero, a new call from A is refused (attester
#               unavailable); the attester back, the next call goes through
#   tamper      zone A's attestation configuration changed in place (a different rootfs digest):
#               the restarted ingress's new pod refuses to serve (exit status 2, evidence_rejected)
#               and is never Ready, so the rollout keeps the verified pod; restored, it serves again
#
#   scripts/verify-atls-gateway/verify.sh --kind [--out DIR]
#       DIR (default .dev/verify-atls-gateway) receives verdict.txt, the gateways' decision records,
#       the installer logs and environment.json. KEEP=1 keeps the two clusters and the registry.
#
# Needs docker, kind, kubectl, helm, cilium, jq, openssl, go, python3 with PyYAML. The two clusters
# (ztd-atls-a, ztd-atls-b) and the registry (kind-registry-atls) are this run's; an existing one
# refuses the run. Exit status: the number of failed checks; 125 refused.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env

mode="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kind) mode=kind; shift ;;
    --out) out=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 125 ;;
  esac
done
[ "$mode" = kind ] || { echo "refused: --kind" >&2; exit 125; }
out=${out:-.dev/verify-atls-gateway}
[ ! -e "$out" ] || [ -z "$(ls -A "$out")" ] || { echo "refused: $out is not empty" >&2; exit 125; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
for tool in docker kind kubectl helm cilium jq openssl go python3; do
  command -v "$tool" >/dev/null || { echo "refused: $tool is required" >&2; exit 125; }
done
python3 -c 'import yaml' 2>/dev/null || { echo "refused: python3 with PyYAML is required" >&2; exit 125; }

zones=(a b)
cluster_of() { echo "ztd-atls-$1"; }
reg_name=kind-registry-atls host_reg=${ATLS_HOST_REGISTRY:-127.0.0.1:5007}
ingress_node_port=30443
work="$(mktemp -d)"
failures=0
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
owned_clusters=() registry_owned=false

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  local z
  for z in "${zones[@]}"; do
    [ -f "$work/kubeconfig-$z" ] || continue
    kubectl --kubeconfig "$work/kubeconfig-$z" -n ztd-data logs -l app.kubernetes.io/name=atls-gateway --all-containers --prefix --tail=-1 \
      >"$out/gateway-pods-$z.log" 2>/dev/null || true
    kubectl --kubeconfig "$work/kubeconfig-$z" -n ztd-mgmt logs -l app.kubernetes.io/name=cmcd -c cmcd --tail=200 \
      >"$out/cmcd-$z.log" 2>/dev/null || true
  done
  if [ -n "${KEEP:-}" ]; then
    echo "kept: clusters $(cluster_of a) and $(cluster_of b), registry $reg_name; kubeconfigs under $out"
    cp "$work"/kubeconfig-* "$out/" 2>/dev/null || true
    rm -rf "$work"
    return
  fi
  for z in "${owned_clusters[@]+"${owned_clusters[@]}"}"; do kind delete cluster --name "$(cluster_of "$z")" >/dev/null 2>&1 || true; done
  if [ "$registry_owned" = true ]; then docker rm -f "$reg_name" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
set -E
trap 'echo "verify-atls-gateway: command failed at line $LINENO: $BASH_COMMAND" >&2' ERR

k() { local z=$1; shift; kubectl --kubeconfig "$work/kubeconfig-$z" "$@"; }
node_ip() { docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$(cluster_of "$1")-worker"; }
peer_of() { [ "$1" = a ] && echo b || echo a; }
# events ZONE ROLE: the decisions a gateway role recorded, one JSON object per line, from every pod
# of the role that exists (a rollout has two for a while; a Deployment's log would show one of them).
events() { k "$1" -n ztd-data logs -l "app.kubernetes.io/name=atls-gateway,app.kubernetes.io/component=$2" -c atls-gateway --tail=-1 2>/dev/null | grep '^{' || true; }
# await ZONE ROLE JQ [SECONDS]: wait until a recorded decision matches JQ.
await() {
  local deadline=$(($(date +%s) + ${4:-60}))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if events "$1" "$2" | jq -e "select($3)" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

# --- 0. refuse to touch what is not ours -------------------------------------------------------
for z in "${zones[@]}"; do
  if kind get clusters 2>/dev/null | grep -Fxq "$(cluster_of "$z")"; then
    echo "refused: kind cluster $(cluster_of "$z") exists" >&2; exit 125
  fi
done
if docker inspect "$reg_name" >/dev/null 2>&1; then echo "refused: registry $reg_name exists" >&2; exit 125; fi

# --- 1. tools and images from the working tree ---------------------------------------------------
step "The gateway and attester images, and the provisioning tools, from the working tree"
cmc=github.com/Fraunhofer-AISEC/cmc
cmc_version=$(go list -m -f '{{.Version}}' "$cmc")
mkdir -p "$work/bin"
GOBIN=$work/bin go install "$cmc/tools/metatool@$cmc_version"
go build -o "$work/bin/attestation-provision" ./cmd/attestation-provision
# Built for the platform the kind nodes run, the Docker server's own (linux/amd64 on the runners and
# the zones, linux/arm64 on an Apple-silicon workstation); the release builds are linux/amd64.
platform=linux/$(docker version -f '{{.Server.Arch}}')
for image in atls-gateway cmcd; do
  docker build -q --platform "$platform" -f "deployment/docker/$image/Dockerfile" -t "$host_reg/$image:atls" . >/dev/null
done
docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
registry_owned=true
for _ in $(seq 1 30); do curl -sf -o /dev/null "http://$host_reg/v2/" && break; sleep 1; done
for image in atls-gateway cmcd; do docker push -q "$host_reg/$image:atls" >/dev/null; done
# digest_of IMAGE: the digest the registry holds for the pushed image.
digest_of() { docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/$1:atls" | sed 's/.*@//'; }
digest_gateway=$(digest_of atls-gateway) digest_cmcd=$(digest_of cmcd)
[ -f deployment/helm/ztd/charts/gatekeeper-3.23.1.tgz ] || { helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts >/dev/null 2>&1 || true; helm dependency build deployment/helm/ztd >/dev/null; }
scripts/ci/verify-chart-dependencies.sh deployment/helm/ztd >/dev/null

# --- 2. the PKIs of the run ------------------------------------------------------------------------
# cert NAME SUBJECT ISSUER EXTENSIONS: a P-256 key and certificate for NAME, signed by ISSUER ("self").
pki=$work/pki; mkdir -p "$pki"
cert() {
  local name=$1 subject=$2 issuer=$3
  printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s\n' "$4" >"$pki/$name.cnf"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$pki/$name.key" 2>/dev/null
  if [ "$issuer" = self ]; then
    openssl req -new -x509 -sha256 -days 2 -key "$pki/$name.key" -subj "$subject" -config "$pki/$name.cnf" -extensions v3 -out "$pki/$name.pem" 2>/dev/null
  else
    openssl req -new -sha256 -key "$pki/$name.key" -subj "$subject" -config "$pki/$name.cnf" -out "$pki/$name.csr" 2>/dev/null
    openssl x509 -req -sha256 -days 2 -in "$pki/$name.csr" -CA "$pki/$issuer.pem" -CAkey "$pki/$issuer.key" -CAcreateserial \
      -extfile "$pki/$name.cnf" -extensions v3 -out "$pki/$name.pem" 2>/dev/null
  fi
}
ca_ext=$'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign'
leaf_ext=$'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature'
step "PKIs of the run: the metadata CA and pipeline signer; the zone PKI issuing both gateways' identities"
cert metadata-ca "/CN=ztd attestation metadata CA" self "$ca_ext"
cert signer "/CN=ztd pipeline metadata signer" metadata-ca "$leaf_ext"
cert zone-ca "/CN=ztd zone PKI" self "$ca_ext"
for z in "${zones[@]}"; do
  cert "gateway-$z" "/CN=zone-$z gateway" zone-ca "$leaf_ext"$'\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=URI:spiffe://zone-'"$z"'/gateway'
done
# A client holding a certificate outside the zone PKI, speaking TLS and no attestation.
cert stranger-ca "/CN=not the zone PKI" self "$ca_ext"
cert stranger "/CN=stranger" stranger-ca "$leaf_ext"$'\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:spiffe://zone-a/gateway'

# --- 3. the two zones ---------------------------------------------------------------------------
# zone_up ZONE: a kind cluster with Cilium as the zones run it (cni.exclusive=false), one worker.
zone_up() {
  local z=$1 cluster
  cluster=$(cluster_of "$z")
  export KUBECONFIG="$work/kubeconfig-$z"
  owned_clusters+=("$z")   # before creating: a half-created cluster is this run's to delete
  kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 0s --config - <<EOF >"$out/kind-create-$z.txt" 2>&1
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking: {disableDefaultCNI: true}
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
nodes:
  - role: control-plane
  - role: worker
EOF
  chmod 600 "$KUBECONFIG"
  local node
  for node in $(kind get nodes --name "$cluster"); do
    docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg_name:5000"
    printf '[host."http://%s:5000"]\n' "$reg_name" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg_name:5000/hosts.toml"
  done
  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
  helm repo update cilium >/dev/null
  helm upgrade --install cilium cilium/cilium --version 1.20.2 -n kube-system --kube-context "kind-$cluster" \
    --set cni.exclusive=false --set ipam.mode=kubernetes --set image.pullPolicy=IfNotPresent --set operator.replicas=1 \
    --wait --timeout 10m >"$out/cilium-install-$z.txt" 2>&1
  kubectl wait --for=condition=Ready nodes --all --timeout=5m >/dev/null
  unset KUBECONFIG
}
step "Two kind zones with Cilium"
for z in "${zones[@]}"; do zone_up "$z"; done
kind_subnet=$(docker network inspect kind -f '{{json .IPAM.Config}}' | jq -r '[.[] | .Subnet | select(contains(":") | not)][0] // empty')
[ -n "$kind_subnet" ] || { echo "no IPv4 subnet on the kind network" >&2; exit 1; }
for z in "${zones[@]}"; do echo "zone $z: worker $(node_ip "$z")"; done

# --- 4. each zone's evidence, provisioned as the pipeline does it ------------------------------------
# provision ZONE: render the zone's reference values and measurement log from Git, sign the reference
# values with the pipeline signer under the metadata CA; the material of the zone's cmcd.
provision() {
  local z=$1 dir=$work/zone-$z config=deployment/attestation/zone-$z.json
  mkdir -p "$dir/signed"
  "$work/bin/attestation-provision" render --zone "$config" --out "$dir/render" --signed-at "$started" >/dev/null
  local f
  for f in manifest.json image-description.json; do
    "$work/bin/metatool" sign --in "$dir/render/unsigned/$f" --out "$dir/signed/$f" \
      --keys "$pki/signer.key" --x5cs "$pki/signer.pem,$pki/metadata-ca.pem" >>"$out/metatool-$z.log" 2>&1
  done
  cp "$dir/render/measurements.json" "$dir/signed/measurements.json"
  cp "$pki/metadata-ca.pem" "$dir/signed/metadata-ca.pem"
}
step "Each zone's evidence from deployment/attestation/<zone>.json, signed by the run's pipeline signer"
for z in "${zones[@]}"; do provision "$z"; done

# --- 5. the zone files and the base releases ----------------------------------------------------------
zone_file() {
  local z=$1 peer
  peer=$(peer_of "$z")
  python3 - deployment/helm/ztd/ci/values.yaml "$work/zone-$z.yaml" "$z" "$peer" "$(node_ip "$peer")" "$ingress_node_port" "$kind_subnet" \
    "$reg_name:5000/atls-gateway@$digest_gateway" "$reg_name:5000/cmcd@$digest_cmcd" "$pki/zone-ca.pem" "$pki/metadata-ca.pem" <<'PY'
import sys, yaml
src, dst, z, peer, peer_ip, node_port, subnet, gw_image, cmcd_image, zone_ca, metadata_ca = sys.argv[1:]
zone = yaml.safe_load(open(src))
zone["zone"]["name"] = f"zone-{z}"
image = lambda ref: {"repository": ref.split("@")[0], "digest": ref.split("@")[1]}
zone["cmcd"] = {"install": True, "namespace": "ztd-mgmt", "values": {"image": image(cmcd_image), "materialSecret": "cmcd-material"}}
zone["atlsGateway"] = {"install": True, "namespace": "ztd-data", "values": {
    "image": image(gw_image), "tlsSecret": "atls-gateway-tls", "trustCaCert": open(zone_ca).read(),
    "attestation": {"metadataCaCert": open(metadata_ca).read(), "timeoutSeconds": 60},
    # The entry on the zone's worker, its source address kept: the peer's egress leaves its node with
    # that node's address, and the lane admits the kind network the two zones share.
    "nodeSelector": {"kubernetes.io/hostname": f"ztd-atls-{z}-worker"},
    "ingress": {"enabled": True, "peerIdentity": f"spiffe://zone-{peer}/gateway",
                "upstream": {"name": "ztd-echo", "port": 8080},
                "service": {"type": "NodePort", "port": 443, "nodePort": int(node_port), "externalTrafficPolicy": "Local"},
                "sourceRanges": [subnet]},
    "egress": {"enabled": True, "callers": [{"serviceAccount": "ztd-caller", "podSelector": {"app.kubernetes.io/name": "ztd-caller"}}],
               "peer": {"name": f"zone-{peer}", "address": peer_ip, "port": int(node_port), "identity": f"spiffe://zone-{peer}/gateway"}}}}
yaml.safe_dump(zone, open(dst, "w"), sort_keys=False)
PY
  cp "$work/zone-$z.yaml" "$out/zone-$z.yaml"
}
step "The base releases of each zone through scripts/install-zone (umbrella, SPIRE, Istio, zone-policy)"
for z in "${zones[@]}"; do
  zone_file "$z"
  if ZONE_VALUES="$work/zone-$z.yaml" KUBE_CONTEXT="kind-$(cluster_of "$z")" KUBECONFIG="$work/kubeconfig-$z" \
      scripts/install-zone/install.sh install ztd spire-crds spire istio-base istiod istio-cni zone-policy >"$out/install-base-$z.txt" 2>&1; then
    pass "zone $z: base releases installed (umbrella, SPIRE, Istio sidecar mode, zone-policy)"
  else
    fail "zone $z: base releases: $(tail -3 "$out/install-base-$z.txt")"; exit "$failures"
  fi
done

# --- 6. the material, then the attester and the gateway ---------------------------------------------------
step "Each zone's material as Secrets, then the attester and the gateway through scripts/install-zone"
for z in "${zones[@]}"; do
  k "$z" -n ztd-mgmt create secret generic cmcd-material --from-file="$work/zone-$z/signed" >/dev/null
  k "$z" -n ztd-data create secret tls atls-gateway-tls --cert="$pki/gateway-$z.pem" --key="$pki/gateway-$z.key" >/dev/null
  if ZONE_VALUES="$work/zone-$z.yaml" KUBE_CONTEXT="kind-$(cluster_of "$z")" KUBECONFIG="$work/kubeconfig-$z" \
      scripts/install-zone/install.sh install ztd-cmcd ztd-atls-gateway >"$out/install-gateway-$z.txt" 2>&1; then
    pass "zone $z: ztd-cmcd (management plane) and ztd-atls-gateway (data plane, both roles) installed from the zone file"
  else
    fail "zone $z: attester or gateway release: $(tail -3 "$out/install-gateway-$z.txt")"
    k "$z" -n ztd-data get pods -o wide >>"$out/install-gateway-$z.txt" 2>&1 || true
    k "$z" -n ztd-data describe pods -l app.kubernetes.io/name=atls-gateway >>"$out/install-gateway-$z.txt" 2>&1 || true
    k "$z" -n ztd-data logs -l app.kubernetes.io/name=atls-gateway --all-containers --prefix --tail=50 >>"$out/install-gateway-$z.txt" 2>&1 || true
    exit "$failures"
  fi
  for role in ingress egress; do
    if await "$z" "$role" '.decision == "started" and .reason == "evidence_verified"' 120; then
      pass "zone $z $role: the startup check verified the zone's own evidence against Git before serving"
    else
      fail "zone $z $role: no startup decision recorded: $(events "$z" "$role" | tail -3)"
    fi
  done
done

# --- 7. the fixtures: an echo and a caller in each data plane ---------------------------------------
# The echo answers HTTP with the request it saw; the caller is the one principal the egress admits.
# Both are meshed (the plane namespace injects the proxy) and registered with SPIRE by the label.
fixtures() {
  local z=$1 td
  td=$(python3 -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["zone"]["trustDomain"])' "$work/zone-$z.yaml")
  k "$z" -n ztd-data apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: ztd-echo}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ztd-caller}
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: ztd-echo}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ztd-echo}}
  template:
    metadata:
      labels: {app.kubernetes.io/name: ztd-echo, spiffe.io/spire-managed-identity: "true"}
      annotations: {sidecar.istio.io/nativeSidecar: "true"}
    spec:
      serviceAccountName: ztd-echo
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: echo
          image: registry.k8s.io/e2e-test-images/agnhost:2.53
          args: [netexec, --http-port=8080]
          ports: [{name: http, containerPort: 8080}]
          readinessProbe: {httpGet: {path: /, port: 8080}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
---
# The upstream's port is a TCP port of the mesh (name tcp-…): the ingress forwards the peer's bytes as
# they are, and an HTTP port would make its sidecar route by the request's Host header, which names
# the peer zone's egress, not this upstream.
apiVersion: v1
kind: Service
metadata: {name: ztd-echo}
spec: {selector: {app.kubernetes.io/name: ztd-echo}, ports: [{name: tcp-http, port: 8080, targetPort: 8080}]}
---
# The echo admits the gateway's ingress only (the mesh default deny admits nothing else).
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: ztd-echo-from-gateway}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ztd-echo}}
  action: ALLOW
  rules:
    - from: [{source: {principals: ["$td/ns/ztd-data/sa/atls-gateway"]}}]
      to: [{operation: {ports: ["8080"]}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: ztd-caller}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ztd-caller}}
  template:
    metadata:
      labels: {app.kubernetes.io/name: ztd-caller, spiffe.io/spire-managed-identity: "true"}
      annotations: {sidecar.istio.io/nativeSidecar: "true"}
    spec:
      serviceAccountName: ztd-caller
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: caller
          image: $CURL_IMAGE
          command: [sleep, infinity]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
  k "$z" -n ztd-data rollout status deploy/ztd-echo --timeout=240s >/dev/null
  k "$z" -n ztd-data rollout status deploy/ztd-caller --timeout=240s >/dev/null
}
step "An echo and a caller in each zone's data plane"
for z in "${zones[@]}"; do fixtures "$z"; done

# call ZONE PATH: an HTTP call from the zone's caller through its egress; prints "<status> <body>".
call() {
  k "$1" -n ztd-data exec deploy/ztd-caller -c caller -- \
    curl -s -m 20 -o /dev/stderr -w '%{http_code}' "http://ztd-atls-gateway-egress:8080$2" 2>"$work/body" || true
  printf ' %s' "$(tr -d '\n' <"$work/body" | head -c 200)"
}

# --- 8. a call each way over the attested channel -----------------------------------------------------------
step "A call each way: caller -> egress -> (attested channel) -> peer ingress -> peer echo"
for z in "${zones[@]}"; do
  peer=$(peer_of "$z")
  result=$(call "$z" "/echo?msg=from-zone-$z")
  echo "zone $z -> zone $peer: $result" | tee -a "$out/calls.txt"
  if [[ "$result" == 200\ * ]] && [[ "$result" == *"from-zone-$z"* ]]; then
    pass "zone $z -> zone $peer: the caller's HTTP request was answered by the peer zone's echo (200)"
  else
    fail "zone $z -> zone $peer: the call did not go through: $result"
  fi
  left=$(events "$z" egress | jq -c 'select(.decision == "established")' | tail -1)
  right=$(events "$peer" ingress | jq -c 'select(.decision == "established")' | tail -1)
  echo "$left" >>"$out/established-$z-egress.json"; echo "$right" >>"$out/established-$peer-ingress.json"
  if [ -n "$left" ] && [ -n "$right" ] && [ "$(jq -r .binding <<<"$left")" = "$(jq -r .binding <<<"$right")" ] \
      && [ "$(jq -r .reason <<<"$left")" = mutual_attestation ] && [ "$(jq -r .reason <<<"$right")" = mutual_attestation ] \
      && [ "$(jq -r .tlsVersion <<<"$left")" = 772 ] && [ "$(jq -r .tlsVersion <<<"$right")" = 772 ] \
      && [ "$(jq -r .peer <<<"$left")" = "spiffe://zone-$peer/gateway" ] && [ "$(jq -r .peer <<<"$right")" = "spiffe://zone-$z/gateway" ]; then
    pass "zone $z -> zone $peer: both ends recorded one channel (mutual attestation, TLS 1.3, the same binding $(jq -r '.binding[:16]' <<<"$left")…, the peer identity each expected)"
  else
    fail "zone $z -> zone $peer: the two ends' records differ: $left | $right"
  fi
done

# --- 9. a plain TLS client at B's entry -----------------------------------------------------------------
step "A TLS client outside the zone PKI, without attestation, at zone B's entry"
ip_b=$(node_ip b)
before=$(events b ingress | jq -c 'select(.decision == "refused")' | wc -l | tr -d ' ')
k a create namespace ztd-stranger >/dev/null 2>&1 || true
k a -n ztd-stranger create secret generic stranger --from-file=cert.pem="$pki/stranger.pem" --from-file=key.pem="$pki/stranger.key" >/dev/null 2>&1 || true
stranger_out=$(k a -n ztd-stranger run stranger --rm -i --restart=Never --quiet --pod-running-timeout=3m --image "$CURL_IMAGE" \
  --overrides='{"spec":{"volumes":[{"name":"s","secret":{"secretName":"stranger"}}],"containers":[{"name":"stranger","image":"'"$CURL_IMAGE"'","command":["curl","-sS","-m","25","-k","-o","/dev/null","-w","status=%{http_code}","--cert","/s/cert.pem","--key","/s/key.pem","https://'"$ip_b:$ingress_node_port"'/"],"volumeMounts":[{"name":"s","mountPath":"/s"}]}]}}' 2>&1 || true)
echo "stranger: $stranger_out" | tee -a "$out/calls.txt"
# The refusal expected of a TLS 1.3 client whose certificate is not the zone PKI's: not any refusal
# recorded since the count was taken, the identity one.
stranger_reason='atls: peer certificate identity rejected'
if [[ "$stranger_out" != *"status=2"* ]] && [[ "$stranger_out" != *"status=3"* ]] && await b ingress '.decision == "refused"' 30 \
    && [ "$(events b ingress | jq -c 'select(.decision == "refused")' | wc -l | tr -d ' ')" -gt "$before" ] \
    && [ "$(events b ingress | jq -c 'select(.decision == "refused")' | tail -n +"$((before + 1))" | jq -r 'select(.reason == "'"$stranger_reason"'") | .reason' | head -1)" = "$stranger_reason" ]; then
  pass "zone B entry: the stranger's TLS got no application answer and the ingress recorded the refusal ($stranger_reason)"
else
  fail "zone B entry: the stranger was not refused as recorded ($(events b ingress | jq -r 'select(.decision == "refused") | .reason' | tail -n +"$((before + 1))" | tr '\n' ';')): $stranger_out"
fi
k a delete namespace ztd-stranger --wait=false >/dev/null 2>&1 || true

# --- 10. zone A's attester away, then back ------------------------------------------------------------------
step "Zone A's attester scaled to zero: a new handshake is refused; back, the next call goes through"
before_away=$(events a egress | jq -c 'select(.decision == "refused" and .reason == "atls: local attester unavailable")' | wc -l | tr -d ' ')
k a -n ztd-mgmt scale deploy/ztd-cmcd --replicas=0 >/dev/null
k a -n ztd-mgmt wait --for=delete pod -l app.kubernetes.io/name=cmcd --timeout=120s >/dev/null 2>&1 || true
# A new connection: the egress pool does not reuse the caller's finished stream.
result=$(call a "/echo?msg=attester-away")
echo "zone a -> zone b with A's cmcd away: $result" | tee -a "$out/calls.txt"
if [[ "$result" != 200\ * ]] && await a egress '.decision == "refused" and .reason == "atls: local attester unavailable"' 30 \
    && [ "$(events a egress | jq -c 'select(.decision == "refused" and .reason == "atls: local attester unavailable")' | wc -l | tr -d ' ')" -gt "$before_away" ]; then
  pass "zone A: with its attester away the egress refused the new channel (atls: local attester unavailable), and the caller got no answer"
else
  fail "zone A: a channel was established without the zone's attester, or no refusal was recorded: $result"
fi
k a -n ztd-mgmt scale deploy/ztd-cmcd --replicas=1 >/dev/null
k a -n ztd-mgmt rollout status deploy/ztd-cmcd --timeout=180s >/dev/null
sleep 3
result=$(call a "/echo?msg=attester-back")
echo "zone a -> zone b with A's cmcd back: $result" | tee -a "$out/calls.txt"
if [[ "$result" == 200\ * ]] && [[ "$result" == *attester-back* ]]; then
  pass "zone A: with its attester back the next call went through"
else
  fail "zone A: the call did not recover after the attester came back: $result"
fi

# --- 11. zone A's configuration tampered in place --------------------------------------------------------------
step "Zone A's attestation configuration changed in place: the restarted ingress refuses to serve; restored, it serves"
# The pod verified at install is replaced by the rollout once the restored pod is Ready; its record
# is kept now and the later pods' records are appended, so decisions-a-ingress.jsonl holds all of them.
events a ingress >"$work/decisions-a-ingress.jsonl"
original=$(k a -n ztd-data get configmap ztd-atls-gateway-attestation -o jsonpath='{.data.zone\.json}')
tampered=$(printf 'facis-ztd zone-a atls-gateway rootfs 2' | openssl dgst -sha256 -r | cut -d' ' -f1)
jq -n --arg z "$(jq --arg d "$tampered" '.components[0].rootfs_sha256 = $d' <<<"$original")" '{data: {"zone.json": $z}}' \
  | k a -n ztd-data patch configmap ztd-atls-gateway-attestation --type merge -p "$(cat)" >/dev/null
k a -n ztd-data rollout restart deploy/ztd-atls-gateway-ingress >/dev/null
tamper_ok=false
for _ in $(seq 1 60); do
  pod=$(k a -n ztd-data get pods -l app.kubernetes.io/component=ingress --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || true)
  [ -n "$pod" ] || { sleep 2; continue; }
  code=$(k a -n ztd-data get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="atls-gateway")].lastState.terminated.exitCode}' 2>/dev/null || true)
  if [ "$code" = 2 ] && k a -n ztd-data logs "$pod" -c atls-gateway --previous 2>/dev/null | grep -q '"reason":"evidence_rejected"'; then
    tamper_ok=true; break
  fi
  sleep 2
done
k a -n ztd-data logs "$pod" -c atls-gateway --previous >"$out/tampered-ingress-a.log" 2>/dev/null || true
grep '^{' "$out/tampered-ingress-a.log" >>"$work/decisions-a-ingress.jsonl" || true
# The new pod never became Ready, so the rollout kept the verified pod: the entry stayed up on the
# configuration it was verified against.
verified_pod_kept=$(k a -n ztd-data get pods -l app.kubernetes.io/component=ingress -o jsonpath='{range .items[*]}{.status.containerStatuses[?(@.name=="atls-gateway")].ready}{" "}{end}' 2>/dev/null | tr ' ' '\n' | grep -c true || true)
if [ "$tamper_ok" = true ] && [ "$verified_pod_kept" -ge 1 ]; then
  pass "zone A ingress: with the configuration changed under it, the new pod exited 2, recorded evidence_rejected and was never Ready; the rollout kept the verified pod serving"
else
  fail "zone A ingress: the tampered configuration did not stop the new pod, or no verified pod stayed Ready (last exit code '$code', ready pods $verified_pod_kept)"
fi
jq -n --arg z "$original" '{data: {"zone.json": $z}}' | k a -n ztd-data patch configmap ztd-atls-gateway-attestation --type merge -p "$(cat)" >/dev/null
k a -n ztd-data rollout restart deploy/ztd-atls-gateway-ingress >/dev/null
k a -n ztd-data rollout status deploy/ztd-atls-gateway-ingress --timeout=240s >/dev/null
result=$(call b "/echo?msg=after-restore")
echo "zone b -> zone a after the restore: $result" | tee -a "$out/calls.txt"
if [[ "$result" == 200\ * ]] && [[ "$result" == *after-restore* ]]; then
  pass "zone A ingress: restored to the configuration in Git it serves again (zone B's call answered)"
else
  fail "zone A ingress: did not serve after the restore: $result"
fi

# --- records ------------------------------------------------------------------------------------------
for z in "${zones[@]}"; do
  for role in ingress egress; do
    if [ "$z-$role" = a-ingress ]; then
      { cat "$work/decisions-a-ingress.jsonl"; events a ingress; } >"$out/decisions-a-ingress.jsonl"
    else
      events "$z" "$role" >"$out/decisions-$z-$role.jsonl" || true
    fi
  done
  k "$z" get nodes -o wide >"$out/nodes-$z.txt" 2>/dev/null || true
  k "$z" -n ztd-data get pods,svc,networkpolicy,ciliumnetworkpolicy,peerauthentication,authorizationpolicy -o wide >"$out/data-plane-$z.txt" 2>/dev/null || true
  k "$z" -n ztd-mgmt get pods,svc,networkpolicy -o wide >"$out/management-plane-$z.txt" 2>/dev/null || true
done
jq -n --arg started "$started" --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg commit "$(git rev-parse HEAD)" \
  --arg dirty "$([ -z "$(git status --porcelain)" ] && echo false || echo true)" --arg cmc "$cmc_version" \
  --arg k8s "$(kubectl --kubeconfig "$work/kubeconfig-a" version -o json 2>/dev/null | jq -r .serverVersion.gitVersion)" \
  --arg kind_node "$KIND_NODE_IMAGE" --arg go "$(go version | awk '{print $3}')" --argjson failures "$failures" \
  --arg gateway "$digest_gateway" --arg cmcd "$digest_cmcd" --arg platform "$platform" \
  '{proof: "verify-atls-gateway", started: $started, ended: $ended, commit: $commit, dirty: ($dirty == "true"), cmc_version: $cmc,
    kubernetes: $k8s, kind_node_image: $kind_node, go: $go, platform: $platform, images: {"atls-gateway": $gateway, cmcd: $cmcd}, failures: $failures}' \
  >"$out/environment.json"
echo
if [ "$failures" -eq 0 ]; then
  echo "verdict: all checks passed" | tee -a "$out/verdict.txt"
else
  echo "verdict: $failures check(s) failed" | tee -a "$out/verdict.txt"
fi
exit "$failures"
