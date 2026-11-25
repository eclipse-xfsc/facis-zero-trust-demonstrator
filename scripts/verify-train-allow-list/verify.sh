#!/usr/bin/env bash
# The TRAIN allow list of the zone entry (ZT-18), on local Docker services, no Kubernetes:
#
#   counter-connector (egress gateway, its own client certificate)
#     --TLS--> entry (ingress gateway, ingress.peerAllowList) --ext_authz--> connector admit-peers
#                 |                                                             | retrieves, verifies
#                 v                                                             v
#              upstream stand-in                               our TSPA image (+ Keycloak test realm)
#
# Both gateways are Envoy (the pinned image) running the configuration the connector-gateway chart
# renders for the role; `connector admit-peers` is built from the working tree and shares the
# entry's network namespace, as a container of the entry's pod would. The TSPA is the patched
# image (deployment/docker/tspa, as scripts/verify-tspa-vc/run.sh starts it) with a fresh signing
# key; the trust list issuer's DID document is served over HTTPS under a run CA. A trust list
# naming one counter-connector is published through the TSPA's API, then:
#
#   1. the listed counter-connector is served, and the decision event names the retrieved list;
#   2. an unlisted one (a certificate of the same CA) is refused 403 CHAN-ZONE-UNKNOWN, with the
#      denied event, and nothing reaches the upstream;
#   3. a client without a certificate does not complete the TLS handshake;
#   4. the listed one is refused once its entry is withdrawn from the list, served again once
#      it is published again;
#   5. with the TSPA stopped it is refused 503 CHAN-TRUST-UNREACHABLE (fail closed).
#
#   scripts/verify-train-allow-list/verify.sh [--out DIR] [--image TSPA_IMAGE]
#       default .dev/train-allow-list (git-ignored), ztd-tspa:local
#
# Writes run.txt (PASS/FAIL lines, the verdict), record.json (one object per case: status, reason
# code, the decision event), events.jsonl (every event of admit-peers), vc.json and
# trust-list.json (as published for case 1). Keys are generated into a temporary directory and
# removed with it. Needs docker, helm, go, curl, jq and OpenSSL 3 (set OPENSSL otherwise).
# pass and fail always succeed, so `check && pass || fail` is an if-then-else here.
# shellcheck disable=SC2015
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
out=.dev/train-allow-list
image=ztd-tspa:local
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in docker helm go curl jq; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }; done
openssl=${OPENSSL:-openssl}
"$openssl" genpkey -algorithm ed25519 >/dev/null 2>&1 || { echo "$openssl cannot generate Ed25519 keys; set OPENSSL to an OpenSSL 3" >&2; exit 2; }
docker image inspect "$image" >/dev/null 2>&1 || { echo "no image $image: build deployment/docker/tspa first" >&2; exit 2; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.json "$out"/*.jsonl "$out"/run.txt

# As scripts/verify-tspa-vc/run.sh: upstream's test realm (client xfsctest with enrolltf).
realm_url=https://raw.githubusercontent.com/eclipse-xfsc/train-trust-framework-manager/ecd5fdc1b01d4aac2e0cbcb1d44dff1ac0202c17/keycloak/realm-export.json
keycloak_image=quay.io/keycloak/keycloak:26.0.8@sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858
curl_image=docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b
did=did:web:tspa.local.test
key_id=trust-list-1
framework=facis-ztd.local
listed=did:web:connector-a.facis-ztd.local
unlisted=did:web:connector-x.facis-ztd.local
entry_name=entry.zone-b.test
refresh=2   # seconds a verified list is kept in this run
net=train-allow-$$
chart=deployment/helm/connector-gateway
work="$(mktemp -d)"
failures=0
pass() { echo "PASS  $*" | tee -a "$out/run.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/run.txt"; failures=$((failures + 1)); }
cleanup() {
  docker rm -f "$net-tspa" "$net-keycloak" "$net-static" "$net-entry" "$net-admit" "$net-listed" "$net-unlisted" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
in_net() { docker run --rm --network "$net" "$curl_image" "$@"; }

# --- keys and certificates of the run -----------------------------------------------------------
# ca NAME: a CA; leaf CA NAME SAN: a certificate with that one subject alternative name.
ca() { "$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$1" \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign' \
  -keyout "$work/$1.key" -out "$work/$1.crt" 2>/dev/null; }
leaf() {
  mkdir -p "$work/$2"
  "$openssl" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" -keyout "$work/$2/tls.key" -out "$work/$2.csr" 2>/dev/null
  "$openssl" x509 -req -in "$work/$2.csr" -CA "$work/$1.crt" -CAkey "$work/$1.key" -CAcreateserial -days 2 \
    -extfile <(printf 'subjectAltName=%s\n' "$3") -out "$work/$2/tls.crt" 2>/dev/null
  chmod 644 "$work/$2/tls.key"   # read by another user in the container; removed with $work
}
ca entry-ca; ca peers-ca; ca trust-ca
leaf entry-ca entry "DNS:$entry_name"
leaf peers-ca listed "URI:$listed"
leaf peers-ca unlisted "URI:$unlisted"
leaf trust-ca static "DNS:tspa.local.test"

"$openssl" genpkey -algorithm ed25519 -out "$work/key.pem" 2>/dev/null
"$openssl" pkey -in "$work/key.pem" -outform DER 2>/dev/null | tail -c 32 | b64url > "$work/d"
"$openssl" pkey -in "$work/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | b64url > "$work/x"
mkdir -p "$work/secret" "$work/static/.well-known"
jq -n --rawfile d "$work/d" --rawfile x "$work/x" --arg kid "$key_id" \
  '{kty: "OKP", crv: "Ed25519", d: ($d | rtrimstr("\n")), x: ($x | rtrimstr("\n")), kid: $kid, use: "sig"}' > "$work/secret/signing-key.jwk"
chmod 600 "$work/secret/signing-key.jwk"
rm -f "$work/key.pem" "$work/d"
jq -n --arg did "$did" --arg vm "$did#$key_id" --rawfile x "$work/x" \
  '{"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"], id: $did,
    verificationMethod: [{id: $vm, type: "JsonWebKey2020", controller: $did,
      publicKeyJwk: {kty: "OKP", crv: "Ed25519", x: ($x | rtrimstr("\n"))}}],
    assertionMethod: [$vm]}' > "$work/static/did.json"

# --- TRAIN: Keycloak and our TSPA ----------------------------------------------------------------
curl -fsSL "$realm_url" -o "$work/realm-export.json"
docker network create "$net" >/dev/null
docker run -d --name "$net-keycloak" --network "$net" --network-alias keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$("$openssl" rand -hex 12)" \
  -v "$work/realm-export.json:/opt/keycloak/data/import/realm-export.json:ro" \
  "$keycloak_image" start-dev --import-realm >/dev/null
props=$(jq -nc --arg did "$did" --arg key "$key_id" '{
  spring: {cloud: {kubernetes: {config: {enabled: false}, reload: {enabled: false}}},
           security: {oauth2: {resourceserver: {jwt: {"issuer-uri": "http://keycloak:8080/realms/gxfs-dev-test"}}}}},
  zonemanager: {query: {status: false}},
  tspa: {"signing-key-file": "/var/run/tspa/signing-key.jwk"},
  trustlist: {vc: {issuer: $did, validity: "P30D", signer: {type: "INTERNAL", key: $key}}},
  "well-known": {signer: {type: "INTERNAL", key: $key}},
  storage: {type: {trustlist: "INTERNAL"}},
  request: {get: {mapping: "http://tspa:16003/tspa-service/tspa/v1/"}}}')
docker run -d --name "$net-tspa" --network "$net" --network-alias tspa -e SPRING_APPLICATION_JSON="$props" \
  -v "$work/secret:/var/run/tspa:ro" "$image" >/dev/null
api=http://tspa:16003/tspa-service/tspa/v1
tspa_ready() {
  for _ in $(seq 1 90); do
    in_net -fs -o /dev/null http://tspa:16003/tspa-service/api/docs 2>/dev/null && return 0
    sleep 2
  done
  return 1
}
tspa_ready || { fail "the TSPA did not start"; exit 1; }
secret=$(jq -r '.clients[] | select(.clientId == "xfsctest") | .secret' "$work/realm-export.json")
# tspa METHOD PATH [FILE]: an authenticated call with a fresh enrolltf token; prints the HTTP status.
tspa() {
  local token=""
  for _ in $(seq 1 30); do
    token=$(in_net -s -m 20 -d client_id=xfsctest -d "client_secret=$secret" -d grant_type=client_credentials \
      http://keycloak:8080/realms/gxfs-dev-test/protocol/openid-connect/token 2>/dev/null | jq -r '.access_token // empty' 2>/dev/null || true)
    [ -n "$token" ] && break
    sleep 2
  done
  docker run --rm -i --network "$net" "$curl_image" -s -o /dev/null -w '%{http_code}' -X "$1" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' --data-binary @- "$api$2" < "${3:-/dev/null}"
}
# The entry of the permitted counter-connector: its identity is the service's ServiceTypeIdentifier.
uuid=7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt18
jq --arg id "$listed" --arg uuid "$uuid" '.TrustServiceProvider.UUID = $uuid
  | .TrustServiceProvider.TSPName = "ZT Connector A - counter-connector of the zone B entry"
  | .TrustServiceProvider.TSPTradeName = "zt-connector-a"
  | .TrustServiceProvider.TSPServices.TSPService[0] |= (.ServiceName = "zero-trust-connector" | .ServiceTypeIdentifier = $id
      | .ServiceDigitalIdentity.DigitalId.DID = $id)' scripts/verify-tspa-api/payloads/tsp-v1.json > "$work/tsp.json"
[ "$(tspa PUT "/init/json/$framework/trust-list" scripts/verify-tspa-api/payloads/trustlist-init.json)" = 201 ] \
  && pass "trust list of $framework created at the TSPA" || fail "trust list not created"
[ "$(tspa PUT "/$framework/trust-list/tsp" "$work/tsp.json")" = 201 ] \
  && pass "trust list names the permitted counter-connector $listed" || fail "entry not published"
in_net -fs "$api/$framework/vc/trust-list" > "$out/vc.json"
in_net -fs "$api/$framework/trust-list" > "$out/trust-list.json"
expires=$(jq -r .expirationDate "$out/vc.json")

# --- the DID document host and the upstream stand-in (one Envoy) ---------------------------------
cat > "$work/static/envoy.yaml" <<'EOF'
static_resources:
  listeners:
    - name: did
      address: {socket_address: {address: 0.0.0.0, port_value: 443}}
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates: [{certificate_chain: {filename: /tls/tls.crt}, private_key: {filename: /tls/tls.key}}]
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: did
                route_config:
                  virtual_hosts:
                    - name: did
                      domains: ["*"]
                      routes:
                        - match: {path: /.well-known/did.json}
                          direct_response: {status: 200, body: {filename: /static/did.json}}
                http_filters: [{name: envoy.filters.http.router, typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}]
    - name: upstream
      address: {socket_address: {address: 0.0.0.0, port_value: 8080}}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: upstream
                access_log:
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                      log_format: {text_format_source: {inline_string: "UPSTREAM %REQ(:PATH)%\n"}}
                route_config:
                  virtual_hosts:
                    - name: upstream
                      domains: ["*"]
                      routes:
                        - match: {prefix: /}
                          direct_response: {status: 200, body: {inline_string: "upstream reached"}}
                http_filters: [{name: envoy.filters.http.router, typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}]
EOF
envoy() { # envoy NAME ALIASES... -- MOUNTS...: the pinned Envoy, as root (it binds 443 and reads the run's files)
  local name=$1 aliases=(); shift
  while [ "$1" != -- ]; do aliases+=(--network-alias "$1"); shift; done; shift
  docker run -d --name "$net-$name" --network "$net" ${aliases[@]+"${aliases[@]}"} -e ENVOY_UID=0 "$@" \
    "$ENVOY_IMAGE" envoy -c /etc/gateway/envoy.yaml --log-level warning --file-flush-interval-msec 100 >/dev/null
}
mkdir -p "$work/static-conf" && mv "$work/static/envoy.yaml" "$work/static-conf/"
envoy static tspa.local.test ztd-participant -- -v "$work/static-conf:/etc/gateway:ro" -v "$work/static:/static:ro" -v "$work/static:/tls:ro"

# --- the entry: the chart's ingress role with the allow list, and connector admit-peers ----------
# gateway_config RELEASE-VALUES...: the envoy.yaml of the rendered ConfigMap.
gateway_config() { helm template gw "$chart" -n ztd "$@" --show-only templates/config.yaml \
  | awk '/^  envoy.yaml: \|/{on=1; next} on && !/^    / && !/^$/{on=0} on{sub(/^    /, ""); print}'; }
mkdir -p "$work/entry-conf"
gateway_config --set name=ztd-edge --set ingress.enabled=true --set ingress.tlsSecret=ztd-edge-tls \
  --set 'ingress.sourceRanges={0.0.0.0/0}' --set ingress.upstream.name=ztd-participant \
  --set ingress.peerAllowList.enabled=true --set ingress.peerAllowList.zone=b \
  --set ingress.peerAllowList.image.digest="sha256:$(printf '0%.0s' $(seq 64))" \
  --set ingress.peerAllowList.tspaUrl="$api" --set ingress.peerAllowList.framework="$framework" \
  --set ingress.peerAllowList.issuerDid="$did" \
  --set-file ingress.peerAllowList.clientCaCert="$work/peers-ca.crt" \
  --set 'ingress.peerAllowList.egress[0].to[0].podSelector.matchLabels.app=tspa' > "$work/entry-conf/envoy.yaml"
cp "$work/peers-ca.crt" "$work/entry-conf/peers-ca.crt"
cp "$work/trust-ca.crt" "$work/entry-conf/trust-ca.crt"
grep -q 'envoy.filters.http.ext_authz' "$work/entry-conf/envoy.yaml" && grep -q 'require_client_certificate: true' "$work/entry-conf/envoy.yaml" \
  && pass "the chart renders the entry with the allow list check and a required client certificate" || fail "entry render"
envoy entry "$entry_name" -- -v "$work/entry-conf:/etc/gateway:ro" -v "$work/entry:/etc/tls:ro"
arch=$(docker version --format '{{.Server.Arch}}')
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$work/bin/connector" ./services/connector
docker run -d --name "$net-admit" --network "container:$net-entry" -v "$work/bin:/bin-run:ro" -v "$work/entry-conf:/etc/gateway:ro" \
  --entrypoint /bin-run/connector "$curl_image" admit-peers --zone b --tspa-url "$api" --trust-framework "$framework" \
  --trust-list-issuer "$did" --trust-ca-file /etc/gateway/trust-ca.crt --refresh "${refresh}s" >/dev/null
entry_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$net-entry")

# --- the counter-connectors: the chart's egress role, each with its own client certificate -------
for peer in listed unlisted; do
  mkdir -p "$work/$peer-conf"
  gateway_config --set trustDomain=zone-a.trust.invalid --set egress.enabled=true \
    --set 'egress.callers[0].serviceAccount=backend' --set 'egress.callers[0].podSelector.app=backend' \
    --set egress.peer.name=zone-b --set egress.peer.address="$entry_ip" --set egress.peer.port=8443 \
    --set egress.peer.serverName="$entry_name" --set egress.peer.clientTlsSecret=client-tls \
    --set-file egress.peer.caCert="$work/entry-ca.crt" > "$work/$peer-conf/envoy.yaml"
  cp "$work/entry-ca.crt" "$work/$peer-conf/peer-ca.crt"
  envoy "$peer" "peer-$peer" -- -v "$work/$peer-conf:/etc/gateway:ro" -v "$work/$peer:/etc/client-tls:ro"
done
code() { in_net -s -m 30 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true; }
for _ in $(seq 1 30); do
  [ "$(code http://peer-listed:8080/)" = 200 ] && [ "$(code http://peer-unlisted:8080/)" = 403 ] && break
  sleep 1
done
sleep "$((refresh + 1))"   # the warm-up's list is past its interval: case 1 retrieves it again

# --- the cases -----------------------------------------------------------------------------------
events() { docker logs "$net-admit" 2>/dev/null | grep '^{' || true; }
upstream_hits() { docker logs "$net-static" 2>/dev/null | grep -c "^UPSTREAM $1\$" || true; }
echo '[]' > "$out/record.json"
# attempt CASE PEER: one request through the counter-connector; records its status, the reason code
# of its answer and the decision event admit-peers wrote for it.
attempt() {
  local name=$1 peer=$2 before path event
  path="/$(tr ' ' '-' <<<"$name")"
  before=$(events | wc -l)
  in_net -s -m 30 -D - "http://peer-$peer:8080$path" | tr -d '\r' > "$work/answer" || true
  sleep 1
  event=$(events | sed -n "$((before + 1))p")
  jq --arg case "$name" --arg peer "$peer" --arg status "$(sed -n '1s/^HTTP[^ ]* \([0-9]*\).*/\1/p' "$work/answer")" \
    --arg header "$(sed -n 's/^x-facis-reason-code: //p' "$work/answer" | head -1)" \
    --arg body "$(tail -1 "$work/answer")" --arg hits "$(upstream_hits "$path")" --argjson event "${event:-null}" \
    '. + [{case: $case, peer: $peer, status: ($status | tonumber? // 0), reason_code: $header,
           body: $body, upstream_requests: ($hits | tonumber), event: $event}]' "$out/record.json" > "$work/record" && mv "$work/record" "$out/record.json"
}
# expect CASE STATUS CODE STATE PEER-ID UPSTREAM: the recorded case against what it must be.
expect() {
  if jq -e --arg case "$1" --argjson status "$2" --arg code "$3" --arg state "$4" --arg id "$5" --argjson hits "$6" '
      .[] | select(.case == $case) | .status == $status and .reason_code == $code and .upstream_requests == $hits
        and .event.kind == "decision" and .event.payload.state == $state and (.event.payload.reason_code // "") == $code
        and (.event.payload.detail | contains($id))
        and ($code == "" or (.body | fromjson | .reason_code) == $code)' "$out/record.json" >/dev/null; then
    pass "$1: HTTP $2 ${3:-served}, decision event $4"
  else
    fail "$1: $(jq -c --arg case "$1" '.[] | select(.case == $case)' "$out/record.json")"
  fi
}
attempt "listed peer" listed
expect "listed peer" 200 "" allowed "peer=$listed listed active in the trust list of $framework, issuer $did, valid until " 1
# "On the basis of the retrieved trust list": the event's deadline is the published VC's expiry.
to_epoch() { date -u -j -f '%Y-%m-%dT%H:%M:%S%z' "$(sed -E 's/\.[0-9]+//; s/([+-][0-9]{2}):([0-9]{2})$/\1\2/; s/Z$/+0000/' <<<"$1")" +%s 2>/dev/null \
  || date -u -d "$1" +%s; }
until=$(jq -r '.[0].event.payload.detail // "" | sub(".* valid until "; "")' "$out/record.json")
[ -n "$until" ] && [ "$(to_epoch "$until")" = "$(to_epoch "$expires")" ] \
  && pass "the admission is valid until the retrieved trust-list VC expires ($until)" || fail "admission deadline '$until', VC expires $expires"
attempt "unlisted peer" unlisted
expect "unlisted peer" 403 CHAN-ZONE-UNKNOWN denied "peer=$unlisted" 0

# No certificate: the entry does not complete the handshake, and no request exists to decide on.
before=$(events | wc -l)
code=$(docker run --rm --network "$net" -v "$work/entry-ca.crt:/ca.crt:ro" "$curl_image" -s -m 10 -o /dev/null -w '%{http_code}' \
  --cacert /ca.crt "https://$entry_name:8443/no-certificate" || true)
if [ "$code" = 000 ] && [ "$(events | wc -l)" -eq "$before" ] && [ "$(upstream_hits /no-certificate)" = 0 ]; then
  pass "a client without a certificate does not complete the TLS handshake with the entry"
else
  fail "no certificate: HTTP $code"
fi

# The admission follows the list: withdrawn, the same peer is refused; published again, served.
[ "$(tspa DELETE "/$framework/trust-list/tsp/$uuid")" = 200 ] || fail "entry not withdrawn"
sleep "$((refresh + 1))"
attempt "withdrawn peer" listed
expect "withdrawn peer" 403 CHAN-ZONE-UNKNOWN denied "peer=$listed" 0
[ "$(tspa PUT "/$framework/trust-list/tsp" "$work/tsp.json")" = 201 ] || fail "entry not published again"
sleep "$((refresh + 1))"
attempt "peer listed again" listed
expect "peer listed again" 200 "" allowed "peer=$listed listed active" 1

# The list cannot be retrieved: fail closed.
docker stop "$net-tspa" >/dev/null
sleep "$((refresh + 1))"
attempt "trust list unavailable" listed
expect "trust list unavailable" 503 CHAN-TRUST-UNREACHABLE denied "framework=$framework" 0

events > "$out/events.jsonl"
{
  echo "tspa image $image ($(docker image inspect -f '{{.Id}}' "$image"))"
  echo "envoy image $ENVOY_IMAGE"
  echo "trust list VC valid until $expires"
} >> "$out/run.txt"
[ "$failures" -eq 0 ] && echo "verdict: PASS" | tee -a "$out/run.txt" || { echo "verdict: FAIL ($failures)" | tee -a "$out/run.txt"; exit 1; }
