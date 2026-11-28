#!/usr/bin/env bash
# Two-tenant isolation (ZT-53), both directions, each denial read from the layer that enforces it.
#
#   scripts/verify-tenants/verify.sh --kind [--out DIR]
#       a throwaway kind cluster: Cilium, the kind zone with tenant-a and tenant-b as planes.extra
#       data-plane namespaces (umbrella, SPIRE, Istio, zone-policy, OpenBao, the two ztd-tenant-*
#       releases, all through scripts/install-zone), and each tenant's guard (deployment/helm/guard in
#       tenant mode, built from the working tree). Deleted on exit; KEEP=1 keeps it.
#   ZTD_CONFIRM_CONTEXT=<context> scripts/verify-tenants/verify.sh --live --trust-domain TD --out DIR
#       [--guard --issuer URL --issuer-key PEM]
#       a zone where the tenants are installed already; --guard when their guards are too, with the
#       issuer whose key set the guards trust and its private signing key (EC P-256, kid "tenants"),
#       which the proof needs to mint the members' tokens; refused without them.
#
# For each tenant X and the other tenant Y (A->B and B->A):
#   data         X's Participant reaches X's data service (control). Y's is dropped by the network layer
#                (Cilium's flow record, verdict DROPPED, from the agent on the caller's node); behind a
#                probe-scoped opening (one NetworkPolicy pair admitting this run's probe only), X's data
#                service's own sidecar refuses it (403 RBAC, its rbac.denied counter and denial log).
#   secret store Both Participants are dropped by the network layer on the way to the management plane's
#                OpenBao; behind a probe-scoped opening, OpenBao's sidecar refuses them.
#   credentials  Y's administrator (a TokenRequest token, never printed) reads or changes X's
#                tenant-credentials: 403 from the API server; X's administrator reads its own: 200.
#   policy       the same for X's guard policy (ConfigMap ztd-policy-config), read and change.
#   guard        (kind, --guard) X's member through X's guard: 200 from X's data service; Y's member through
#                X's guard: 403 POL-RULE-DENY m3-tenant-membership, with X's guard and policy events (IF-01
#                v2) carrying tenant X. On kind the guard's token issuer key set and token-store calls
#                are an Envoy stand-in (the real chain: TestTwoTenantsWithRealConnectorStorePolicyPostgresAndOpenBao).
# Probe objects carry ztd.facis.io/probe-run=<run> and are removed on exit; the objects of the
# tenant namespaces and of the management namespace are compared before and after.
# Needs kubectl, jq, curl, openssl; --kind also docker, kind, helm, python3 with PyYAML.
# Exit status: the number of failed checks; 125 refused.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
mode="" out="" guard=no td="" issuer="" issuer_key=""
while [ $# -gt 0 ]; do
  case "$1" in
    --kind) mode=kind; guard=yes; shift ;;
    --live) mode=live; shift ;;
    --guard) guard=yes; shift ;;
    --trust-domain) td=$2; shift 2 ;;
    --issuer) issuer=$2; shift 2 ;;
    --issuer-key) issuer_key=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 125 ;;
  esac
done
[ -n "$mode" ] || { echo "refused: --kind or --live" >&2; exit 125; }
[ "$mode" = kind ] && out=${out:-.dev/verify-tenants}
[ -n "$out" ] || { echo "refused: --out DIR" >&2; exit 125; }
[ ! -e "$out" ] || [ -z "$(ls -A "$out")" ] || { echo "refused: $out is not empty" >&2; exit 125; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tenants=(tenant-a tenant-b)
store_ns=ztd-mgmt store_svc=ztd-openbao store_port=8200
run=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
work="$(mktemp -d)"
cluster=${TENANTS_KIND_CLUSTER:-ztd-tenants}
cluster_owned=false registry_owned=false
reg_name=kind-registry-tenants host_reg=${TENANTS_HOST_REGISTRY:-127.0.0.1:5006}
failures=0
pass() { echo "PASS  $*" | tee -a "$out/verdict.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/verdict.txt"; failures=$((failures + 1)); }
step() { echo; echo "== $*"; }
row() { printf '%s\n' "$*" | tr ' ' '\t' >> "$out/cases.tsv"; }   # case from to layer expected observed

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  kubectl delete pod,networkpolicy -A -l "ztd.facis.io/probe-run=$run" --wait=true --timeout=120s >/dev/null 2>&1 || true
  if [ -n "${KEEP:-}" ] && [ "$mode" = kind ]; then echo "kept: cluster $cluster, KUBECONFIG=$KUBECONFIG"; return; fi
  if [ "$cluster_owned" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
  if [ "$registry_owned" = true ]; then docker rm -f "$reg_name" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
set -E
trap 'echo "verify-tenants: command failed at line $LINENO: $BASH_COMMAND" >&2' ERR

b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
ec_xy() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 64 > "$work/point"
  printf '%s %s\n' "$(head -c 32 "$work/point" | b64url)" "$(tail -c 32 "$work/point" | b64url)"
}
# shellcheck disable=SC2001 # a regex over the whole string
es256() {
  local ints r s
  openssl dgst -sha256 -sign "$1" -out "$work/sig.der"
  ints=$(openssl asn1parse -inform DER -in "$work/sig.der" | sed -n 's/.*INTEGER *:\([0-9A-F]*\).*/\1/p')
  r=$(printf '%064s' "$(sed -n 1p <<<"$ints" | sed 's/^00//')" | tr ' ' 0)
  s=$(printf '%064s' "$(sed -n 2p <<<"$ints" | sed 's/^00//')" | tr ' ' 0)
  printf '%b' "$(sed 's/../\\x&/g' <<<"$r$s")" | b64url
}
jws() { local input; input="$(printf '%s' "$2" | b64url).$(printf '%s' "$3" | b64url)"; printf '%s.%s' "$input" "$(printf '%s' "$input" | es256 "$1")"; }
jwk_of() { local xy; xy=$(ec_xy "$1"); jq -nc --arg x "${xy% *}" --arg y "${xy#* }" '{crv: "P-256", kty: "EC", x: $x, y: $y}'; }
jkt_of() { jwk_of "$1" | jq -cS . | tr -d '\n' | openssl dgst -sha256 -binary | b64url; }

if [ "$mode" = live ] && [ "$guard" = yes ]; then
  if [ -z "$issuer" ] || [ ! -f "$issuer_key" ] || ! openssl pkey -in "$issuer_key" -noout 2>/dev/null; then
    echo "refused: --guard needs --issuer URL and --issuer-key PEM (the key the guards' issuer key set publishes)" >&2; exit 125
  fi
  cp "$issuer_key" "$work/issuer.pem"
fi
if [ "$mode" = live ]; then
  context=$(kubectl config current-context)
  [ "${ZTD_CONFIRM_CONTEXT:-}" = "$context" ] || { echo "refused: ZTD_CONFIRM_CONTEXT=$context is required" >&2; exit 125; }

else
  for tool in docker kind helm python3; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 125; }; done
  export KUBECONFIG="$work/kubeconfig"
  context=kind-$cluster
  step "Images of the guard and the policy evaluator from the working tree"
  for image in guard policy-evaluator; do
    docker build -q -f "deployment/docker/$image/Dockerfile" -t "$host_reg/$image:tenants" . >/dev/null
  done
  step "kind with Cilium and the kind zone with the two tenants"
  if kind get clusters | grep -Fxq "$cluster" || docker inspect "$reg_name" >/dev/null 2>&1; then
    echo "refusing to replace an existing local cluster or registry" >&2; exit 125
  fi
  cluster_owned=true
  kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 0s --config - <<'EOF' >/dev/null
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking: {disableDefaultCNI: true}
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
  registry_owned=true
  docker run -d --name "$reg_name" --network kind -p "$host_reg:5000" "$REGISTRY_IMAGE" >/dev/null
  for node in $(kind get nodes --name "$cluster"); do
    docker exec "$node" mkdir -p "/etc/containerd/certs.d/$reg_name:5000"
    printf '[host."http://%s:5000"]\n' "$reg_name" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$reg_name:5000/hosts.toml"
  done
  for _ in $(seq 1 20); do curl -sf -o /dev/null "http://$host_reg/v2/" && break; sleep 1; done
  declare -A digest
  for image in guard policy-evaluator; do
    docker push -q "$host_reg/$image:tenants" >/dev/null
    digest[$image]=$(docker image inspect --format '{{index .RepoDigests 0}}' "$host_reg/$image:tenants" | sed 's/.*@//')
  done
  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
  helm repo update cilium >/dev/null
  helm upgrade --install cilium cilium/cilium --version 1.20.2 -n kube-system --kube-context "$context" \
    --set cni.exclusive=false --set ipam.mode=kubernetes --set image.pullPolicy=IfNotPresent \
    --set hubble.enabled=true --set operator.replicas=1 --wait --timeout 10m > "$out/cilium-install.txt" 2>&1 || { fail "cilium: $(tail -2 "$out/cilium-install.txt")"; exit "$failures"; }
  kubectl wait --for=condition=Ready nodes --all --timeout=5m >/dev/null
  [ -f deployment/helm/ztd/charts/gatekeeper-3.23.1.tgz ] || { helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts >/dev/null 2>&1 || true; helm dependency build deployment/helm/ztd >/dev/null; }
  scripts/ci/verify-chart-dependencies.sh deployment/helm/ztd >/dev/null
  issuer=https://issuer.tenants.invalid
  openssl ecparam -name prime256v1 -genkey -noout -out "$work/issuer.pem" 2>/dev/null
  # The kind zone with the two tenants and their guards, all installed by the zone installer.
  python3 - deployment/helm/ztd/ci/values.yaml "$work/zone.yaml" "$ENVOY_IMAGE" "$issuer" \
      "$reg_name:5000/guard@${digest[guard]}" "$reg_name:5000/policy-evaluator@${digest[policy-evaluator]}" <<'PY'
import sys, yaml
zone = yaml.safe_load(open(sys.argv[1]))
zone["planes"]["extra"] += [{"name": "tenant-a", "plane": "data", "tenant": True}, {"name": "tenant-b", "plane": "data", "tenant": True}]
envoy = {"repository": sys.argv[3].split("@")[0].rsplit(":", 1)[0], "digest": sys.argv[3].split("@")[1]}
native = {"sidecar.istio.io/nativeSidecar": "true"}
zone["tenants"] = {"install": True, "names": ["tenant-a", "tenant-b"],
                   "values": {"data": {"image": envoy}, "podAnnotations": native},
                   "guard": {"install": True, "values": {
                       "zone": "a", "images": {"guard": {"repository": sys.argv[5].split("@")[0], "digest": sys.argv[5].split("@")[1]},
                                               "policy": {"repository": sys.argv[6].split("@")[0], "digest": sys.argv[6].split("@")[1]}, "envoy": envoy},
                       "config": {"issuer": sys.argv[4], "jwks_url": "http://ztd-connector:8080/.well-known/jwks.json",
                                  "inbound_audience": "https://guard.facis.invalid", "upstream_audience": "https://resource.facis.invalid", "peer_zone": "zone-b"},
                       "policyRevision": "tenants-kind-1", "networkPolicy": {"istiod": {"enabled": True}}, "podAnnotations": native}}}
yaml.safe_dump(zone, open(sys.argv[2], "w"), sort_keys=False)
PY
  cp "$work/zone.yaml" "$out/kind-zone.yaml"
  if ZONE_VALUES="$work/zone.yaml" KUBE_CONTEXT="$context" scripts/install-zone/install.sh install \
      ztd spire-crds spire istio-base istiod istio-cni zone-policy ztd-openbao \
      ztd-tenant-tenant-a ztd-guard-tenant-a ztd-tenant-tenant-b ztd-guard-tenant-b > "$out/install-zone.txt" 2>&1; then
    pass "kind zone installed through scripts/install-zone: tenant-a and tenant-b as planes.extra tenant entries, each with its ztd-tenant release and its guard (ztd-guard-<tenant>, tenant mode)"
  else
    fail "install-zone: $(tail -3 "$out/install-zone.txt")"; exit "$failures"
  fi
  td=$(python3 -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["zone"]["trustDomain"])' "$work/zone.yaml")

  step "An Envoy stand-in for each tenant guard's issuer key set and token store"
  jwks=$(jwk_of "$work/issuer.pem" | jq -c '{keys: [. + {kid: "tenants", alg: "ES256", use: "sig"}]}')
  for t in "${tenants[@]}"; do
    other=tenant-a; [ "$t" = tenant-a ] && other=tenant-b
    # The stand-in answers the key set, the replay check (always fresh) and the substitution (a fixed
    # upstream credential); it is reachable by this tenant's guard only.
    jq -n --arg jwks "$jwks" '
      def route(p; body): {match: {path: p}, direct_response: {status: 200, body: {inline_string: body}}, response_headers_to_add: [{header: {key: "content-type", value: "application/json"}}]};
      {static_resources: {listeners: [{name: "stub", address: {socket_address: {address: "0.0.0.0", port_value: 8080}},
        filter_chains: [{filters: [{name: "envoy.filters.network.http_connection_manager", typed_config: {
          "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", stat_prefix: "stub",
          route_config: {virtual_hosts: [{name: "stub", domains: ["*"], routes: [
            route("/.well-known/jwks.json"; $jwks), route("/internal/replay-check"; "{\"fresh\":true}"),
            route("/internal/substitute"; "{\"authorization\":\"DPoP stand-in-upstream\",\"dpop\":\"stand-in-proof\",\"expires_at\":\"2099-01-01T00:00:00Z\"}")]}]},
          http_filters: [{name: "envoy.filters.http.router", typed_config: {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]}]}]}}' > "$work/stub-$t.json"
    kubectl -n "$t" create configmap tenants-stand-in --from-file=envoy.yaml="$work/stub-$t.json" >/dev/null
    kubectl -n "$t" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: ztd-token-store}
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: tenants-stand-in}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ztd-token-store}}
  template:
    metadata:
      labels: {app.kubernetes.io/name: ztd-token-store, spiffe.io/spire-managed-identity: "true"}
      annotations: {sidecar.istio.io/nativeSidecar: "true"}
    spec:
      serviceAccountName: ztd-token-store
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: envoy
          image: "$ENVOY_IMAGE"
          args: ["-c", "/etc/stub/envoy.yaml", "--log-level", "warning"]
          volumeMounts: [{name: config, mountPath: /etc/stub}, {name: tmp, mountPath: /tmp}]
          readinessProbe: {tcpSocket: {port: 8080}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumes: [{name: config, configMap: {name: tenants-stand-in}}, {name: tmp, emptyDir: {}}]
---
apiVersion: v1
kind: Service
metadata: {name: ztd-token-store}
spec: {selector: {app.kubernetes.io/name: ztd-token-store}, ports: [{name: http, port: 8080}]}
---
apiVersion: v1
kind: Service
metadata: {name: ztd-connector}
spec: {selector: {app.kubernetes.io/name: ztd-token-store}, ports: [{name: http, port: 8080}]}
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: tenants-stand-in}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ztd-token-store}}
  action: ALLOW
  rules: [{from: [{source: {principals: ["$td/ns/$t/sa/ztd-guard"]}}]}]
EOF
    if kubectl -n "$t" rollout status deploy/tenants-stand-in deploy/ztd-guard deploy/ztd-policy-evaluator --timeout=300s >/dev/null; then
      pass "$t: guard (target tenant $t, callers of $other admitted to the guard only), policy evaluator and stand-in ready"
    else
      fail "$t: guard, policy evaluator or stand-in not ready"
    fi
  done
fi
k() { kubectl "$@"; }
[ -n "$td" ] || { echo "refused: --trust-domain TD" >&2; exit 125; }
{ echo "mode: $mode"; echo "context: $context"; echo "trust domain: $td"; echo "probe run: $run"; echo "started: $(date -u +%FT%TZ)"; } > "$out/run.txt"
printf 'case\tfrom\tto\tlayer\texpected\tobserved\n' > "$out/cases.tsv"

snapshot() {
  k get networkpolicy,authorizationpolicy,peerauthentication,role,rolebinding,serviceaccount,secret,configmap,deployment,service \
    -n "$1" -o json 2>/dev/null | jq '[.items[] | {kind, name: .metadata.name, resourceVersion: .metadata.resourceVersion}] | sort_by(.kind, .name)'
}
for ns in "${tenants[@]}" "$store_ns"; do snapshot "$ns" > "$out/before-$ns.json"; done

step "Probes: one meshed pod per tenant under its Participant's identity"
curl_image=$(sed -n 's/^ *image: *\(docker\.io\/curlimages\/curl:[^ ]*\).*/\1/p' deployment/helm/ztd/values.yaml | head -1)
for t in "${tenants[@]}"; do
  k -n "$t" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: tenant-probe-$run
  labels: {app.kubernetes.io/name: ztd-participant, spiffe.io/spire-managed-identity: "true", ztd.facis.io/probe-run: "$run"}
  annotations: {sidecar.istio.io/nativeSidecar: "true"}
spec:
  serviceAccountName: ztd-participant
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 100, runAsGroup: 101, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: curl
      image: "$curl_image"
      command: [sh, -c, "trap 'exit 0' TERM; while :; do sleep 10 & wait \$!; done"]
      resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 64Mi}}
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
EOF
done
for t in "${tenants[@]}"; do k -n "$t" wait --for=condition=Ready "pod/tenant-probe-$run" --timeout=300s >/dev/null; done
pass "probes ready: tenant-probe-$run in ${tenants[*]}, each meshed under its tenant's ztd-participant"

# call FROM URL OUT [curl args]: from FROM's probe; status code or 000
call() {
  local from=$1 url=$2 file=$3; shift 3
  k -n "$from" exec "tenant-probe-$run" -c curl -- curl -sS -m 8 -w '\nHTTP_CODE=%{http_code}\n' "$@" "$url" > "$file" 2>&1 || true
  sed -n 's/^HTTP_CODE=\([0-9]*\).*/\1/p' "$file" | tail -1
}
# flows FROM DEST-IP OUT: Cilium's DROPPED flows from FROM's probe to DEST-IP, from the agent on its node
flows() {
  local node agent ip
  node=$(k -n "$1" get pod "tenant-probe-$run" -o jsonpath='{.spec.nodeName}')
  ip=$(k -n "$1" get pod "tenant-probe-$run" -o jsonpath='{.status.podIP}')
  agent=$(k -n kube-system get pod -l k8s-app=cilium --field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].metadata.name}')
  k -n kube-system exec "$agent" -c cilium-agent -- hubble observe --since 2m --verdict DROPPED --from-ip "$ip" --to-ip "$2" -o compact > "$3" 2>&1 || true
  grep -q 'DROPPED' "$3"
}
# rbac DEST-NS DEST-SELECTOR: the receiver sidecar's rbac.denied counters, summed
rbac() {
  local pod
  pod=$(k -n "$1" get pod -l "$2" -o jsonpath='{.items[0].metadata.name}')
  k -n "$1" exec "$pod" -c istio-proxy -- pilot-agent request GET stats 2>/dev/null | awk -F': ' '/rbac\.denied/ {s += $2} END {print s + 0}'
}
# opening FROM DEST-NS DEST-LABEL-KEY DEST-LABEL-VALUE PORT: the probe-scoped NetworkPolicy pair
opening() {
  k -n "$1" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: probe-$run-to-$2, labels: {ztd.facis.io/probe-run: "$run"}}
spec:
  podSelector: {matchLabels: {ztd.facis.io/probe-run: "$run"}}
  policyTypes: [Egress]
  egress: [{to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $2}}, podSelector: {matchLabels: {$3: $4}}}], ports: [{port: $5, protocol: TCP}]}]
EOF
  k -n "$2" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: probe-$run-from-$1, labels: {ztd.facis.io/probe-run: "$run"}}
spec:
  podSelector: {matchLabels: {$3: $4}}
  policyTypes: [Ingress]
  ingress: [{from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $1}}, podSelector: {matchLabels: {ztd.facis.io/probe-run: "$run"}}}], ports: [{port: $5, protocol: TCP}]}]
EOF
  sleep 5
}
close_opening() { k -n "$1" delete networkpolicy "probe-$run-to-$2" >/dev/null; k -n "$2" delete networkpolicy "probe-$run-from-$1" >/dev/null; sleep 3; }
# two_layers NAME FROM DEST-NS SELECTOR(k=v) URL PORT: network drop, then the mesh refusal behind an opening
two_layers() {
  local name=$1 from=$2 dns=$3 sel=$4 url=$5 port=$6 ip code before after
  ip=$(k -n "$dns" get pod -l "$sel" -o jsonpath='{.items[0].status.podIP}')
  code=$(call "$from" "$url" "$out/$name-network.http")
  if [ "$code" = 000 ] && flows "$from" "$ip" "$out/$name-network-flows.txt"; then
    pass "$name: network layer drops it (no answer; Cilium DROPPED flow from the $from probe to $ip, $name-network-flows.txt)"; row "$name $from $dns network denied dropped"
  else
    fail "$name: network layer: status $code, flows $(head -c 200 "$out/$name-network-flows.txt" 2>/dev/null)"; row "$name $from $dns network denied status-$code"
  fi
  opening "$from" "$dns" "${sel%%=*}" "${sel#*=}" "$port"
  before=$(rbac "$dns" "$sel")
  code=$(call "$from" "$url" "$out/$name-mesh.http")
  sleep 3
  after=$(rbac "$dns" "$sel")
  k -n "$dns" logs "$(k -n "$dns" get pod -l "$sel" -o jsonpath='{.items[0].metadata.name}')" -c istio-proxy --since=1m 2>/dev/null \
    | grep -F "ns/$from/sa/ztd-participant" > "$out/$name-mesh-receiver-log.txt" || true
  close_opening "$from" "$dns"
  # An HTTP listener answers 403 RBAC: access denied; a TCP one closes the connection (000). Either
  # way the receiver's own RBAC counter is the evidence.
  if { [ "$code" = 000 ] || { [ "$code" = 403 ] && grep -q 'RBAC: access denied' "$out/$name-mesh.http"; }; } && [ "$after" -gt "$before" ]; then
    pass "$name: behind a probe-scoped opening the receiver's sidecar refuses it (status $code, rbac.denied $before -> $after)"; row "$name $from $dns mesh denied $code-rbac"
  else
    fail "$name: mesh layer: status $code, rbac.denied $before -> $after"; row "$name $from $dns mesh denied status-$code"
  fi
}

# API calls as a tenant's administrator: a short-lived TokenRequest token in a header file, never printed.
server=$(k config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
k config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$work/ca.crt" 2>/dev/null || true
api() { # api TENANT-OF-ADMIN METHOD PATH OUT [data]: status code; the body is kept only when not 200
  local code ca=()
  [ -s "$work/ca.crt" ] && ca=(--cacert "$work/ca.crt")
  printf 'Authorization: Bearer %s\n' "$(k -n "$1" create token tenant-admin --duration=10m)" > "$work/auth"
  code=$(curl -sS -m 15 "${ca[@]}" -H @"$work/auth" -X "$2" ${5:+-H 'Content-Type: application/merge-patch+json' --data "$5"} \
    -o "$work/api-body" -w '%{http_code}' "$server$3" 2>/dev/null || echo 000)
  rm -f "$work/auth"
  if [ "$code" = 200 ]; then echo '{"withheld": "a 200 body is not recorded"}' > "$4"; else jq '{kind, status, reason, code, message}' "$work/api-body" > "$4" 2>/dev/null || cp "$work/api-body" "$4"; fi
  rm -f "$work/api-body"
  echo "$code"
}

for x in "${tenants[@]}"; do
  y=tenant-a; [ "$x" = tenant-a ] && y=tenant-b
  step "$y -> $x"
  code=$(call "$x" "http://tenant-data.$x:8080/" "$out/data-own-$x.http")
  if [ "$code" = 200 ] && grep -q "\"tenant\":\"$x\"" "$out/data-own-$x.http"; then
    pass "data, control: $x's Participant reads $x's data service (200, tenant $x)"; row "data-own $x $x - allowed 200"
  else
    fail "data, control: $x -> $x: status $code"; row "data-own $x $x - allowed status-$code"
  fi
  two_layers "data-$y-to-$x" "$y" "$x" app.kubernetes.io/name=tenant-data "http://tenant-data.$x:8080/" 8080
  # Selected by a label Cilium keeps in the identity (it drops statefulset.kubernetes.io/pod-name).
  two_layers "secret-store-$x" "$x" "$store_ns" app.kubernetes.io/name=openbao "http://$store_svc.$store_ns:$store_port/v1/sys/health" "$store_port"

  for object in "secrets/tenant-credentials credentials" "configmaps/ztd-policy-config policy"; do
    read -r path what <<<"$object"
    own=$(api "$x" GET "/api/v1/namespaces/$x/$path" "$out/$what-own-$x-read.json")
    read_code=$(api "$y" GET "/api/v1/namespaces/$x/$path" "$out/$what-$y-reads-$x.json")
    change_code=$(api "$y" PATCH "/api/v1/namespaces/$x/$path" "$out/$what-$y-changes-$x.json" '{"metadata":{"labels":{"ztd.facis.io/probe-run":"'"$run"'"}}}')
    # Live without the guard there is no ztd-policy-config: the owner's 404 shows authorization passed.
    want_own=200; [ "$what" = policy ] && [ "$guard" = no ] && want_own=404
    if [ "$own" = "$want_own" ]; then pass "$what, control: $x's administrator reads $x's $path ($own)"; else fail "$what, control: $x's administrator: $own"; fi
    row "$what-own $x $x api allowed $own"
    if [ "$read_code" = 403 ] && [ "$change_code" = 403 ] && jq -se 'all(.[]; .reason == "Forbidden")' "$out/$what-$y-reads-$x.json" "$out/$what-$y-changes-$x.json" >/dev/null; then
      pass "$what: $y's administrator can neither read nor change $x's $path (403 Forbidden from the API server, both)"
    else
      fail "$what: $y's administrator on $x's $path: read $read_code, change $change_code"
    fi
    row "$what-read $y $x api denied $read_code"; row "$what-change $y $x api denied $change_code"
  done

  if [ "$guard" = yes ]; then
    for caller in "$x" "$y"; do
      openssl ecparam -name prime256v1 -genkey -noout -out "$work/$caller.pem" 2>/dev/null
      now=$(date +%s) url="http://ztd-guard.$x:8080/demo"
      token=$(jws "$work/issuer.pem" '{"alg":"ES256","typ":"at+jwt","kid":"tenants"}' \
        "$(jq -nc --arg iss "$issuer" --arg sub "$caller-member" --arg jkt "$(jkt_of "$work/$caller.pem")" --argjson now "$now" --arg jti "$run-$caller-$x" \
          '{iss: $iss, aud: "https://guard.facis.invalid", sub: $sub, client_id: $sub, jti: $jti, scope: "report:summary", cnf: {jkt: $jkt}, iat: $now, exp: ($now + 300)}')")
      ath=$(printf '%s' "$token" | openssl dgst -sha256 -binary | b64url)
      proof=$(jws "$work/$caller.pem" "$(jwk_of "$work/$caller.pem" | jq -c '{alg: "ES256", typ: "dpop+jwt", jwk: .}')" \
        "$(jq -nc --arg u "$url" --arg a "$ath" --argjson i "$now" --arg j "$run-proof-$caller-$x" '{jti: $j, htm: "POST", htu: $u, iat: $i, ath: $a}')")
      code=$(call "$caller" "$url" "$out/guard-$caller-to-$x.http" -i -X POST -H "Authorization: DPoP $token" -H "DPoP: $proof")
      sleep 2
      # A refusal names its correlation id (x-request-id); an allowed request's is the guard's last
      # allowed event for this caller.
      id=$(grep -i '^x-request-id:' "$out/guard-$caller-to-$x.http" | head -1 | tr -d '\r' | awk '{print $2}' || true)
      [ -n "$id" ] || id=$(k -n "$x" logs deploy/ztd-guard -c guard --since=5m 2>/dev/null | jq -Rr --arg c "ns/$caller/sa/ztd-participant" \
        'fromjson? | select(.payload.state == "allowed" and (.payload.caller_spiffe_id | endswith($c))) | .correlation_id' | tail -1)
      k -n "$x" logs deploy/ztd-guard -c guard --since=5m 2>/dev/null | grep -F "\"$id\"" > "$out/guard-$caller-to-$x-guard-event.json" || true
      k -n "$x" logs deploy/ztd-policy-evaluator -c policy-evaluator --since=5m 2>/dev/null | grep -F "\"$id\"" > "$out/guard-$caller-to-$x-policy-event.json" || true
      tenant_ok=$(jq -s --arg x "$x" 'length == 2 and all(.[]; .version == 2 and .payload.tenant == $x)' "$out/guard-$caller-to-$x-guard-event.json" "$out/guard-$caller-to-$x-policy-event.json" 2>/dev/null || echo false)
      if [ "$caller" = "$x" ]; then
        if [ "$code" = 200 ] && grep -q "\"tenant\":\"$x\"" "$out/guard-$caller-to-$x.http" && [ "$tenant_ok" = true ]; then
          pass "guard, control: $x's member through $x's guard reaches $x's data (200); guard and policy events carry tenant $x (request $id)"
        else fail "guard, control: $x -> $x guard: status $code, events tenant ok: $tenant_ok"; fi
        row "guard-own $x $x policy allowed $code"
      else
        rule=$(jq -r '.payload.rule_id' "$out/guard-$caller-to-$x-policy-event.json" 2>/dev/null || true)
        if [ "$code" = 403 ] && grep -q '"rule_id":"m3-tenant-membership"' "$out/guard-$caller-to-$x.http" && [ "$rule" = m3-tenant-membership ] && [ "$tenant_ok" = true ]; then
          pass "guard: $caller's member through $x's guard: 403 POL-RULE-DENY m3-tenant-membership, decided by $x's policy, both events carry tenant $x (request $id)"
        else fail "guard: $caller -> $x guard: status $code, policy rule ${rule:-none}, events tenant ok: $tenant_ok"; fi
        row "guard-cross $caller $x policy denied $code"
      fi
    done
  fi
done

step "Cleanup and the namespaces as found"
k delete pod,networkpolicy -A -l "ztd.facis.io/probe-run=$run" --wait=true --timeout=120s >/dev/null 2>&1 || true
if [ -z "$(k get pod,networkpolicy -A -l "ztd.facis.io/probe-run=$run" -o name 2>/dev/null)" ]; then
  pass "cleanup: no probe pod or network policy of run $run remains"
else
  fail "cleanup: probe objects of run $run remain"
fi
changed=""
for ns in "${tenants[@]}" "$store_ns"; do
  snapshot "$ns" > "$out/after-$ns.json"
  diff "$out/before-$ns.json" "$out/after-$ns.json" > "$out/objects-$ns.diff" || changed="$changed $ns"
done
if [ -z "$changed" ]; then pass "no object of ${tenants[*]} or $store_ns changed (resourceVersions equal before and after)"; else fail "objects changed in:$changed (objects-<ns>.diff)"; fi
echo "finished: $(date -u +%FT%TZ)" >> "$out/run.txt"
echo "verdict: $([ "$failures" = 0 ] && echo PASS || echo "FAIL ($failures)")" | tee -a "$out/verdict.txt"
exit "$failures"
