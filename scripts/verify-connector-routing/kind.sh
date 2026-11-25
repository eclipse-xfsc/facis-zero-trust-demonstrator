#!/usr/bin/env bash
# The kind rehearsal of the Zero Trust Connector routing (ZT-26), on a kind zone installed with
# scripts/dev/kind-cilium-up.sh and scripts/install-zone/install.sh (the releases up to zone-policy):
#   1 a peer zone's entry outside the cluster: a container on the kind network serving TLS with a CA of
#     this run, its access log in the run directory;
#   2 the egress role: the connector-gateway release in the data-plane namespace, routed to that entry;
#   3 the ingress role, rehearsed as zone B takes it: zone B's hand-applied entry
#     (fixtures/hand-applied-entry.yaml) in a copy of its M3 namespace (fixtures/m3-namespace.yaml) is
#     adopted by the chart, while a client outside the cluster calls it every half second; the Service
#     keeps its UID and node port (the calls lost while the hand-applied pod, which has no preStop
#     pause, is replaced are recorded), and a later rollout of the chart's entry loses no call;
#   4 verify.sh for each role (ROLE=egress, ROLE=ingress), the caller's service account created beforehand,
#     which the proof must use and leave in place;
# then removes everything it set up. Exits with verify.sh's status, or 125 when a set-up step fails
# (1-124: a rehearsal check failed, added to verify.sh's count).
# Environment: KUBE_CONTEXT (default kind-ztd), ZTD_EVIDENCE_DIR (the run directory, outside the repository).
# shellcheck disable=SC1091,SC2329,SC2015,SC2319
set -uo pipefail
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
case $CONTEXT in kind-?*) ;; *) echo "kind.sh: kind contexts only" >&2; exit 125;; esac
cd "$(dirname "$0")" || exit 125
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/connector-gateway
# shellcheck source=scripts/lib/proof.sh
. "$REPO/scripts/lib/proof.sh"
ENVOY=$(sed -n 's/^ENVOY_IMAGE=//p' "$REPO/scripts/tools/pins.env")
ENVOY_REPO=${ENVOY%%:*}; ENVOY_DIGEST=${ENVOY##*@}
TD=$(yaml_get "$REPO/deployment/helm/ztd/ci/values.yaml" zone trustDomain)
NS=ztd-data M3=ztd-m3-rt PEER=ztd-rt-peer CLIENT=ztd-rt-client
EVID=${ZTD_EVIDENCE_DIR:-$(mktemp -d)}; mkdir -p "$EVID/peer"; EVID=$(realpath "$EVID")
case $EVID/ in "$REPO"/*) echo "kind.sh: run directory inside the repository" >&2; exit 125;; esac
W=$(mktemp -d)
k() { kubectl --context "$CONTEXT" "$@"; }
h() { helm --kube-context "$CONTEXT" "$@"; }
fail=0
note() { printf '%s\n' "$*" | tee -a "$EVID/rehearsal.md"; }
rcheck() { if [ "$1" -eq 0 ]; then note "- PASS: $2"; else note "- **FAIL**: $2"; fail=$((fail+1)); fi; }
die() { echo "kind.sh: $*" >&2; exit 125; }
cleanup() {
  h -n "$NS" uninstall ztd-connector-gateway --wait >/dev/null 2>&1
  k delete namespace "$M3" --wait=false >/dev/null 2>&1; k -n istio-system delete networkpolicy "$M3-to-istiod" --ignore-not-found >/dev/null 2>&1
  docker rm -f "$PEER" "$CLIENT" >/dev/null 2>&1
  rm -rf "$W"
}
trap cleanup EXIT

# CA and certificates of this run; no key leaves $W except the peer's, mounted into its container.
ca() { openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$W/ca.crt" -subj "/CN=ztd-rt CA" -days 1 2>/dev/null; }
leaf() { # leaf <name> <san>
  openssl req -newkey rsa:2048 -nodes -keyout "$W/$1.key" -out "$W/$1.csr" -subj "/CN=$1" 2>/dev/null &&
  openssl x509 -req -in "$W/$1.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial -days 1 -out "$W/$1.crt" \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2") 2>/dev/null
}
ca || die "CA"

note "# Connector routing rehearsal on $CONTEXT" ""
# 1 the peer entry: a container on the kind network, started idle so its address is known before its certificate
docker rm -f "$PEER" "$CLIENT" >/dev/null 2>&1
docker run -d --name "$PEER" --network kind --user 0 --entrypoint sleep -v "$EVID/peer:/v" "$ENVOY" infinity >/dev/null || die "peer container"
PIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PEER")
leaf peer "IP:$PIP" && cp "$W/peer.crt" "$W/peer.key" "$EVID/peer/" || die "peer certificate"
cat > "$EVID/peer/envoy.yaml" <<EOF
static_resources:
  listeners:
    - name: entry
      address: {socket_address: {address: 0.0.0.0, port_value: 8443}}
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates: [{certificate_chain: {filename: /v/peer.crt}, private_key: {filename: /v/peer.key}}]
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: entry
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: /v/access.log
                      log_format: {json_format: {method: "%REQ(:METHOD)%", path: "%REQ(:PATH)%", status: "%RESPONSE_CODE%", user_agent: "%REQ(USER-AGENT)%", authority: "%REQ(:AUTHORITY)%"}}
                route_config:
                  virtual_hosts:
                    - name: entry
                      domains: ["*"]
                      routes: [{match: {prefix: "/"}, direct_response: {status: 200, body: {inline_string: "peer-entry zone-b\n"}}}]
                http_filters: [{name: envoy.filters.http.router, typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}]
EOF
touch "$EVID/peer/access.log"
docker exec -d "$PEER" envoy -c /v/envoy.yaml --log-level warning || die "peer envoy"
note "Peer entry: container $PEER on the kind network, TLS on 8443 with a certificate for its address, CA of this run."

# 2 the egress role
h -n "$NS" upgrade --install ztd-connector-gateway "$CHART" --wait --timeout 5m \
  --set image.repository="$ENVOY_REPO" --set image.digest="$ENVOY_DIGEST" --set trustDomain="$TD" \
  --set egress.enabled=true --set-json 'egress.callers=[{"serviceAccount":"backend","podSelector":{"app.kubernetes.io/name":"backend"}}]' \
  --set egress.peer.name=zone-b --set egress.peer.address="$PIP" --set egress.peer.port=8443 \
  --set-file egress.peer.caCert="$W/ca.crt" >/dev/null || die "egress gateway release"
note "Egress gateway: release ztd-connector-gateway in $NS, routed to the peer entry."

# 3 the ingress role: zone B's hand-applied entry, adopted
sed -e "s/__NS__/$M3/g" -e "s|__TD__|$TD|g" fixtures/m3-namespace.yaml | k apply -f - >/dev/null || die "M3 namespace"
leaf entry "DNS:entry.ztd-rt.test" || die "entry certificate"
k -n "$M3" create secret tls ztd-edge-tls --cert "$W/entry.crt" --key "$W/entry.key" >/dev/null || die "entry secret"
sed -e "s/__NS__/$M3/g" -e "s|__IMAGE__|$ENVOY|" fixtures/hand-applied-entry.yaml | k apply -f - >/dev/null || die "hand-applied entry"
k -n "$M3" rollout status deploy/ztd-participant --timeout=180s >/dev/null && k -n "$M3" rollout status deploy/ztd-edge --timeout=180s >/dev/null || die "entry not ready"
NODEIP=$(k get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
NODEPORT=$(k -n "$M3" get svc ztd-edge -o jsonpath='{.spec.ports[0].nodePort}')
UID_BEFORE=$(k -n "$M3" get svc ztd-edge -o jsonpath='{.metadata.uid}')
loop() { # loop: an outside client calling the entry every half second until stopped
  docker rm -f "$CLIENT" >/dev/null 2>&1
  docker run -d --name "$CLIENT" --network kind -v "$W/ca.crt:/ca.crt:ro" --entrypoint sh \
    docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b \
    -c "while true; do curl -s -o /dev/null -w '%{http_code}\n' -m 5 --cacert /ca.crt -A ztd-rt-entry-loop --resolve entry.ztd-rt.test:$NODEPORT:$NODEIP https://entry.ztd-rt.test:$NODEPORT/hostname; sleep 0.5; done" >/dev/null || die "client"
}
loop
sleep 5
before=$(docker logs "$CLIENT" 2>/dev/null | grep -c '^200$')
[ "$before" -gt 0 ]; rcheck $? "the hand-applied entry serves the outside client before the adoption ($before calls answered 200)"
h -n "$M3" upgrade --install ztd-edge "$CHART" --take-ownership --force-conflicts --wait --timeout 5m \
  --set name=ztd-edge --set image.repository="$ENVOY_REPO" --set image.digest="$ENVOY_DIGEST" \
  --set ingress.enabled=true --set ingress.tlsSecret=ztd-edge-tls --set 'ingress.sourceRanges={0.0.0.0/0}' \
  --set ingress.service.type=NodePort --set ingress.upstream.name=ztd-participant --set ingress.upstream.port=8080 \
  > "$EVID/adoption-helm.txt" 2>&1; rcheck $? "the chart adopts the entry (helm --take-ownership, server-side apply)"
k -n "$M3" rollout status deploy/ztd-edge --timeout=180s >/dev/null
k -n "$M3" delete authorizationpolicy ztd-m3-edge-public >/dev/null; rcheck $? "the hand-applied rule ztd-m3-edge-public is removed, the chart's ztd-edge-public in its place"
sleep 5
docker kill "$CLIENT" >/dev/null 2>&1
codes=$(docker logs "$CLIENT" 2>/dev/null)
docker run --rm --network kind -v "$W/ca.crt:/ca.crt:ro" docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b \
  -s -m 5 --cacert /ca.crt -A ztd-rt-entry-after --resolve "entry.ztd-rt.test:$NODEPORT:$NODEIP" "https://entry.ztd-rt.test:$NODEPORT/hostname" > "$W/after" 2>&1
grep -q ztd-participant "$W/after"; rcheck $? "after the adoption the entry still serves the outside client ($(head -c 60 "$W/after"))"
[ "$(k -n "$M3" get svc ztd-edge -o jsonpath='{.metadata.uid}')" = "$UID_BEFORE" ] && [ "$(k -n "$M3" get svc ztd-edge -o jsonpath='{.spec.ports[0].nodePort}')" = "$NODEPORT" ]
rcheck $? "the entry's Service kept its UID and node port (a load balancer keeps its address)"
# Envoy writes its access log in batches (about every 10 s): read again for up to 60 s.
for _ in $(seq 12); do k -n "$M3" logs deploy/ztd-edge -c envoy 2>/dev/null | grep -q '"ztd-rt-entry-after"' && break; sleep 5; done
k -n "$M3" logs deploy/ztd-edge -c envoy 2>/dev/null | grep -q '"ztd-rt-entry-after"'; rcheck $? "the entry's access log records the outside call"
spec=$(k -n "$M3" get deploy ztd-edge -o json | jq -c '.spec.template.spec | {args: .containers[0].args, mounts: [.containers[0].volumeMounts[].mountPath], volumes: [.volumes[].name]}')
note "  Adopted pod spec: $spec"
# The hand-applied pod has no preStop pause, so its replacement may lose the calls in flight; recorded, not checked.
note "  Calls during the adoption (client every 0.5 s, before + during + after): $(sort <<<"$codes" | uniq -c | paste -sd' ' -)"
loop; sleep 3
k -n "$M3" rollout restart deploy/ztd-edge >/dev/null && k -n "$M3" rollout status deploy/ztd-edge --timeout=180s >/dev/null
sleep 8; docker kill "$CLIENT" >/dev/null 2>&1
codes=$(docker logs "$CLIENT" 2>/dev/null)
note "  Calls during a rollout of the chart's entry: $(sort <<<"$codes" | uniq -c | paste -sd' ' -)"
grep -q '^200$' <<<"$codes" && ! grep -qv '^200$' <<<"$codes"; rcheck $? "a rollout of the chart's entry loses no call of the outside client (preStop pause)"

# 4 the routing proof on both roles. The caller's service account exists before the proof (as a zone's
# participant backend's would): the proof must use it and leave it in place.
created_sa=0
if ! k -n "$NS" get serviceaccount backend >/dev/null 2>&1; then
  k -n "$NS" create serviceaccount backend >/dev/null || die "the caller's service account"
  created_sa=1
fi
SA_UID=$(k -n "$NS" get serviceaccount backend -o jsonpath='{.metadata.uid}')
ZTD_EVIDENCE_DIR=$EVID/verify-egress KUBE_CONTEXT=$CONTEXT ROLE=egress ROUTE_EXPECT="peer-entry zone-b" \
  PEER_LOG_CMD="cat '$EVID/peer/access.log'" ./verify.sh
rc_e=$?
ZTD_EVIDENCE_DIR=$EVID/verify-ingress KUBE_CONTEXT=$CONTEXT ROLE=ingress \
  DIRECT_EXTERNAL="$PIP:8443/https" DIRECT_TARGETS="$M3/ztd-participant:8080/http $M3/ztd-edge:443/https" ENTRY_PORTS=443/TCP \
  ENTRY_NAMESPACE=$M3 ENTRY_NAME=ztd-edge ./verify.sh
rc_i=$?
[ "$(k -n "$NS" get serviceaccount backend -o jsonpath='{.metadata.uid}' 2>/dev/null)" = "$SA_UID" ]
rcheck $? "the service account backend, there before the proofs, is the same object after both (uid $SA_UID)"
[ "$created_sa" = 1 ] && k -n "$NS" delete serviceaccount backend >/dev/null 2>&1   # only when this rehearsal created it
rc=$(( rc_e >= 125 || rc_i >= 125 ? 125 : rc_e + rc_i ))
note "" "verify.sh exit $rc; rehearsal failures $fail; records in $EVID"
total=$((rc + fail)); [ "$rc" -ge 125 ] && total=$rc
exit $(( total > 124 && rc < 125 ? 124 : total ))
