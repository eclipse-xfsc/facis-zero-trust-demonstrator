#!/usr/bin/env bash
# Our patched TSPA (deployment/docker/tspa) on Docker, end to end: a fresh Ed25519 signing key in a
# file mounted read-only (as the Kubernetes Secret is on a zone), Keycloak with upstream's test realm
# for the enrolltf token, then the trust list is created, an entry is published, and the signed
# trust-list VC, the list and the issuer's DID document (built from the key's public half) are
# written to --out. It checks that the VC carries a validity window of the configured period and
# that a second publication renews it. The private key is generated into a temporary directory
# and removed with it; it is never printed.
#
#   scripts/verify-tspa-vc/run.sh [--out DIR] [--image IMAGE]   default .dev/tspa-vc, ztd-tspa:local
#
# Needs docker, curl, jq and OpenSSL 3 (Ed25519; set OPENSSL when the first openssl on PATH is
# not). The DID is did:web:tspa.local.test: a local name, served by nothing; the verifier's tests
# serve the DID document themselves.
# pass and fail always succeed, so `check && pass || fail` is an if-then-else here.
# shellcheck disable=SC2015
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
out=.dev/tspa-vc
image=ztd-tspa:local
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
for tool in docker curl jq; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }; done
openssl=${OPENSSL:-openssl}
"$openssl" genpkey -algorithm ed25519 >/dev/null 2>&1 || { echo "$openssl cannot generate Ed25519 keys; set OPENSSL to an OpenSSL 3" >&2; exit 2; }
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -f "$out"/*.json "$out"/run.txt

# Upstream's test realm (client xfsctest with enrolltf) at the commit the image is built from.
realm_url=https://raw.githubusercontent.com/eclipse-xfsc/train-trust-framework-manager/ecd5fdc1b01d4aac2e0cbcb1d44dff1ac0202c17/keycloak/realm-export.json
keycloak_image=quay.io/keycloak/keycloak:26.0.8@sha256:09a381c715ab0b111835b70f2905955274843a219c6f27efb348e4d9f4086858
curl_image=docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b
did=did:web:tspa.local.test
key_id=trust-list-1
framework=facis-ztd.local
validity=P30D
net=tspa-vc-$$
work="$(mktemp -d)"
failures=0
pass() { echo "PASS  $*" | tee -a "$out/run.txt"; }
fail() { echo "FAIL  $*" | tee -a "$out/run.txt"; failures=$((failures + 1)); }
cleanup() {
  docker rm -f "$net-tspa" "$net-nokey" "$net-keycloak" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }

# The signing key: a private OKP JWK in a file of its own, mode 600, never printed.
"$openssl" genpkey -algorithm ed25519 -out "$work/key.pem" 2>/dev/null
"$openssl" pkey -in "$work/key.pem" -outform DER 2>/dev/null | tail -c 32 | b64url > "$work/d"
"$openssl" pkey -in "$work/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | b64url > "$work/x"
mkdir -p "$work/secret"
jq -n --rawfile d "$work/d" --rawfile x "$work/x" --arg kid "$key_id" \
  '{kty: "OKP", crv: "Ed25519", d: ($d | rtrimstr("\n")), x: ($x | rtrimstr("\n")), kid: $kid, use: "sig"}' > "$work/secret/signing-key.jwk"
chmod 600 "$work/secret/signing-key.jwk"
rm -f "$work/key.pem"   # $work/d stays, mode 600, for the leak check; removed with $work
jq -n --arg did "$did" --arg vm "$did#$key_id" --rawfile x "$work/x" \
  '{"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"], id: $did,
    verificationMethod: [{id: $vm, type: "JsonWebKey2020", controller: $did,
      publicKeyJwk: {kty: "OKP", crv: "Ed25519", x: ($x | rtrimstr("\n"))}}],
    assertionMethod: [$vm]}' > "$out/did.json"

curl -fsSL "$realm_url" -o "$work/realm-export.json"
docker network create "$net" >/dev/null
docker run -d --name "$net-keycloak" --network "$net" --network-alias keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 12)" \
  -v "$work/realm-export.json:/opt/keycloak/data/import/realm-export.json:ro" \
  "$keycloak_image" start-dev --import-realm >/dev/null
props=$(jq -nc --arg did "$did" --arg key "$key_id" --arg validity "$validity" '{
  spring: {cloud: {kubernetes: {config: {enabled: false}, reload: {enabled: false}}},
           security: {oauth2: {resourceserver: {jwt: {"issuer-uri": "http://keycloak:8080/realms/gxfs-dev-test"}}}}},
  zonemanager: {query: {status: false}},
  tspa: {"signing-key-file": "/var/run/tspa/signing-key.jwk"},
  trustlist: {vc: {issuer: $did, validity: $validity, signer: {type: "INTERNAL", key: $key}}},
  "well-known": {signer: {type: "INTERNAL", key: $key}},
  storage: {type: {trustlist: "INTERNAL"}},
  request: {get: {mapping: "http://tspa:16003/tspa-service/tspa/v1/"}}}')
docker run -d --name "$net-tspa" --network "$net" --network-alias tspa -e SPRING_APPLICATION_JSON="$props" \
  -v "$work/secret:/var/run/tspa:ro" "$image" >/dev/null

# In-network calls: Keycloak's iss and TSPA's request.get.mapping are the network names.
in_net() { docker run --rm --network "$net" "$curl_image" "$@"; }
for _ in $(seq 1 90); do
  in_net -fs -o /dev/null http://tspa:16003/tspa-service/api/docs 2>/dev/null && break
  sleep 2
done
secret=$(jq -r '.clients[] | select(.clientId == "xfsctest") | .secret' "$work/realm-export.json")
# new_token: a fresh enrolltf token in $token (the realm's tokens live a few minutes, and a
# publication waits for the signature).
new_token() {
  token=""
  for _ in $(seq 1 30); do
    token=$(in_net -s -m 20 -d client_id=xfsctest -d "client_secret=$secret" -d grant_type=client_credentials \
      http://keycloak:8080/realms/gxfs-dev-test/protocol/openid-connect/token 2>/dev/null | jq -r '.access_token // empty' 2>/dev/null || true)
    [ -n "$token" ] && return 0
    sleep 2
  done
  return 1
}
new_token || true
[ -n "$token" ] && pass "enrolltf token from the test realm" || { fail "no token"; exit 1; }
api=http://tspa:16003/tspa-service/tspa/v1
# put PATH FILE: an authenticated PUT; prints the HTTP status.
put() { docker run --rm -i --network "$net" "$curl_image" -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' --data-binary @- "$api$1" < "$2"; }
[ "$(put "/init/json/$framework/trust-list" scripts/verify-tspa-api/payloads/trustlist-init.json)" = 201 ] \
  && pass "trust list created" || fail "trust list not created"
[ "$(put "/$framework/trust-list/tsp" scripts/verify-tspa-api/payloads/tsp-v1.json)" = 201 ] \
  && pass "entry published" || fail "entry not published"
in_net -fs "$api/$framework/vc/trust-list" > "$out/vc.json"
in_net -fs "$api/$framework/trust-list" > "$out/trust-list.json"

issued=$(jq -r .issuanceDate "$out/vc.json")
expires=$(jq -r '.expirationDate // empty' "$out/vc.json")
to_epoch() { date -u -j -f '%Y-%m-%dT%H:%M:%S%z' "$(sed -E 's/([+-][0-9]{2}):([0-9]{2})$/\1\2/; s/Z$/+0000/' <<<"$1")" +%s 2>/dev/null \
  || date -u -d "$1" +%s; }
if [ -n "$expires" ] && [ $(( $(to_epoch "$expires") - $(to_epoch "$issued") )) -eq $((30 * 86400)) ]; then
  pass "VC validity window $issued .. $expires (P30D)"
else
  fail "VC window: issued $issued, expires ${expires:-none}"
fi
jq -e --arg did "$did" --arg vm "$did#$key_id" '.issuer == $did and .proof.type == "JsonWebSignature2020" and .proof.verificationMethod == $vm' \
  "$out/vc.json" >/dev/null && pass "VC signed JsonWebSignature2020 by $did#$key_id" || fail "VC proof: $(jq -c .proof "$out/vc.json")"
# The private scalar, matched as a fixed string (from stdin, never on a command line).
if docker exec -i "$net-tspa" sh -c 'grep -rlF -f - /tmp/train-tspa /usr/local/tomcat/logs 2>/dev/null' < "$work/d" | grep -q . \
  || docker logs "$net-tspa" 2>&1 | grep -qF -f "$work/d"; then
  fail "the private key reached the store or the logs"
else
  pass "the private key is in no stored file, no Tomcat log and not on stdout"
fi

# Re-publication renews the window.
sleep 2
uuid=$(jq -r .TrustServiceProvider.UUID scripts/verify-tspa-api/payloads/tsp-v2.json)
new_token
code=$(docker run --rm -i --network "$net" "$curl_image" -s -o /dev/null -w '%{http_code}' -X PATCH -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' --data-binary @- "$api/$framework/trust-list/tsp/$uuid" < scripts/verify-tspa-api/payloads/tsp-v2.json)
[ "$code" = 200 ] && pass "entry replaced (PATCH $code)" || fail "PATCH answered $code"
in_net -fs "$api/$framework/vc/trust-list" > "$work/vc2.json"
if [ "$(jq -r .issuanceDate "$work/vc2.json")" != "$issued" ] && [ "$(jq -r .expirationDate "$work/vc2.json")" != "$expires" ]; then
  pass "re-publication renews the window ($(jq -r .issuanceDate "$work/vc2.json") .. $(jq -r .expirationDate "$work/vc2.json"))"
  cp "$work/vc2.json" "$out/vc.json"
  in_net -fs "$api/$framework/trust-list" > "$out/trust-list.json"
else
  fail "re-publication kept the window"
fi
# Without its key file the image signs nothing: the published key is not in it to fall back on.
docker run -d --name "$net-nokey" --network "$net" --network-alias tspa-nokey \
  -e SPRING_APPLICATION_JSON="$(jq -c '.tspa."signing-key-file" = "/var/run/tspa/absent.jwk"
    | .request.get.mapping = "http://tspa-nokey:16003/tspa-service/tspa/v1/"' <<<"$props")" "$image" >/dev/null
for _ in $(seq 1 90); do
  in_net -fs -o /dev/null http://tspa-nokey:16003/tspa-service/api/docs 2>/dev/null && break
  sleep 2
done
new_token
nokey=http://tspa-nokey:16003/tspa-service/tspa/v1
code=$(docker run --rm -i --network "$net" "$curl_image" -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' --data-binary @- "$nokey/init/json/$framework/trust-list" < scripts/verify-tspa-api/payloads/trustlist-init.json)
vc_code=$(in_net -s -o /dev/null -w '%{http_code}' "$nokey/$framework/vc/trust-list" || true)
if [ "$code" != 201 ] && [ "$vc_code" != 200 ]; then
  pass "without its key file nothing is signed (create answered $code, VC $vc_code)"
else
  fail "without its key file: create $code, VC $vc_code"
fi

echo "image $image" >> "$out/run.txt"
[ "$failures" -eq 0 ] && echo "verdict: PASS" | tee -a "$out/run.txt" || { echo "verdict: FAIL ($failures)" | tee -a "$out/run.txt"; exit 1; }
