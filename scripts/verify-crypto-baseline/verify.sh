#!/usr/bin/env bash
# Inspects the keys and certificates the configuration generates, against the cryptographic
# baseline (docs/crypto-baseline.md): the admission provider's certificates as the chart renders
# them, the SPIRE server's CA key type as the pinned chart renders it with the zone's values, and
# the keys of a Keycloak that first held the realm with Keycloak's default keys and then had the
# chart's realm applied by the chart's own import tool, as an upgrade does.
# Needs helm, openssl, jq, python3 with PyYAML, and Docker for the Keycloak leg. Not a zone:
# what a deployed zone holds is inspected on that zone.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
work=$(mktemp -d)
net="ztd-crypto-$$"
kc="ztd-crypto-kc-$$"
trap 'docker rm -f "$kc" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; docker rmi "$kc-snapshot" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

fail=0
check() { if [ "$2" = "$3" ]; then echo "ok    $1"; else echo "FAIL  $1: got '$2', want '$3'"; fail=1; fi; }

# The value of a key of a rendered manifest, as text: yaml_get <file> <kind> <python expression on d>.
yaml_get() {
  python3 -c '
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d["kind"] == sys.argv[2] and eval(sys.argv[3]):
        print(eval(sys.argv[4])); break' "$@"
}

# --- admission provider -----------------------------------------------------------------------
helm template admission deployment/helm/admission -f deployment/helm/admission/ci/values.yaml >"$work/admission.yaml"
for cert in ca.crt tls.crt; do
  yaml_get "$work/admission.yaml" Secret 'd.get("type") == "kubernetes.io/tls"' "d['data']['$cert']" | base64 -d >"$work/$cert"
  key=$(openssl x509 -in "$work/$cert" -noout -text | awk '/Public Key Algorithm|ASN1 OID|Signature Algorithm/ { print $NF }' | sort -u | tr '\n' ' ')
  check "admission provider $cert is ECDSA P-256, signed with SHA-256" "$key" "ecdsa-with-SHA256 id-ecPublicKey prime256v1 "
done

# --- SPIRE ------------------------------------------------------------------------------------
spire_version=$(sed -n 's/^SPIRE_VERSION=\([^ ]*\).*/\1/p' scripts/install-zone/install.sh)
spire_repo=$(sed -n 's/^SPIRE_REPO=//p' scripts/install-zone/install.sh)
helm template spire spire --repo "$spire_repo" --version "$spire_version" -f deployment/helm/values/spire.yaml \
  --set global.spire.trustDomain=zone.example --set global.spire.clusterName=zone \
  --set global.spire.persistence.storageClass=standard --set global.spire.caSubject.commonName=zone.example >"$work/spire.yaml"
check "the rendered SPIRE server configuration sets ca_key_type ec-p256" \
  "$(yaml_get "$work/spire.yaml" ConfigMap '"server.conf" in d.get("data", {})' 'd["data"]["server.conf"]' | jq -r '.server.ca_key_type')" "ec-p256"

# --- Keycloak ---------------------------------------------------------------------------------
kc_image=$(sed -n 's/^  image: \(quay.io\/keycloak\/.*\)/\1/p' deployment/helm/facis-ztd-keycloak/values.yaml)
cli_image=$(sed -n 's/^  image: \(docker.io\/adorsys\/.*\)/\1/p' deployment/helm/facis-ztd-keycloak/values.yaml)
admin_pass=$(openssl rand -hex 16)
helm template kc deployment/helm/facis-ztd-keycloak >"$work/keycloak.yaml"
yaml_get "$work/keycloak.yaml" ConfigMap '"facis-ztd.json" in d.get("data", {})' 'd["data"]["facis-ztd.json"]' >"$work/realm.json"
# The same realm without its key providers: what an installation from before the baseline holds.
python3 - "$work/realm.json" "$work/realm-before.json" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
before, count = re.subn(r'  "components": \{.*?\n  \},\n', '', text, flags=re.S)
assert count == 1, "the realm has no components block"
open(sys.argv[2], 'w').write(before)
PY

docker network create "$net" >/dev/null
docker run -d --name "$kc" --network "$net" -p 127.0.0.1::8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$admin_pass" "$kc_image" start-dev >/dev/null
port=$(docker port "$kc" 8080/tcp | sed 's/.*://')
url="http://127.0.0.1:$port"

apply() { # apply <realm file>: the chart's import job, with its arguments and settings
  docker run --rm --network "$net" -v "$1:/config/facis-ztd.json:ro" \
    -e KEYCLOAK_URL="http://$kc:8080" -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD="$admin_pass" \
    -e KEYCLOAK_AVAILABILITYCHECK_ENABLED=true -e KEYCLOAK_AVAILABILITYCHECK_TIMEOUT=300s \
    -e IMPORT_FILES_LOCATIONS=/config/facis-ztd.json -e IMPORT_CACHE_ENABLED=false \
    -e IMPORT_REMOTESTATE_ENABLED=true -e IMPORT_REMOTESTATE_ENCRYPTIONKEY="$admin_pass" \
    -e IMPORT_VARSUBSTITUTION_ENABLED=true -e IMPORT_VARSUBSTITUTION_NESTED=false \
    -e IMPORT_USERS_MERGEROLES=false -e IMPORT_USERS_MERGEGROUPS=false -e LOGGING_LEVEL_ROOT=WARN \
    -e DEMO_OPERATOR_PASSWORD_JSON="\"$admin_pass-1\"" -e DEMO_OBSERVER_PASSWORD_JSON="\"$admin_pass-2\"" \
    -e BDD_OPERATOR_PASSWORD_JSON="\"$admin_pass-3\"" -e BDD_OBSERVER_PASSWORD_JSON="\"$admin_pass-4\"" \
    "$cli_image" --import.managed.client=no-delete --import.managed.role=no-delete \
    --import.managed.client-scope=no-delete --import.managed.required-action=no-delete >"$work/apply.log" 2>&1 \
    || { cat "$work/apply.log"; return 1; }
}

rsa_bits() { # the realm's active RSA keys, as "<algorithm>=<bits>" sorted; their key ids go to $work/kids
  token=$(curl -fsS "$url/realms/master/protocol/openid-connect/token" -d grant_type=password -d client_id=admin-cli \
    -d username=admin --data-urlencode "password=$admin_pass" | jq -r .access_token)
  curl -fsS -H "authorization: Bearer $token" "$url/admin/realms/facis-ztd/keys" >"$work/keys.json"
  jq -r '[.keys[] | select(.status == "ACTIVE") | .algorithm + "=" + .kid] | sort | join(" ")' "$work/keys.json" >"$work/kids"
  jq -r '.keys[] | select(.type == "RSA" and .status == "ACTIVE") | .algorithm + " " + .publicKey' "$work/keys.json" |
    while read -r algorithm key; do
      bits=$(printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$key" | openssl pkey -pubin -noout -text | sed -n '1s/[^0-9]//gp')
      echo "$algorithm=$bits"
    done | sort | tr '\n' ' '
}

apply "$work/realm-before.json"
check "before: the realm's RSA keys are Keycloak's default size" "$(rsa_bits)" "RS256=2048 RSA-OAEP=2048 "
apply "$work/realm.json"
check "after the chart's realm is applied, the RSA keys are 4096 bits and key transport is RSA-OAEP-256" "$(rsa_bits)" "RS256=4096 RSA-OAEP-256=4096 "
kids=$(cat "$work/kids")
apply "$work/realm.json"
rsa_bits >/dev/null
check "applying the same realm again keeps every active key, by key id" "$(cat "$work/kids")" "$kids"
docker stop "$kc" >/dev/null
docker commit "$kc" "$kc-snapshot" >/dev/null
docker run --rm --entrypoint sh "$kc-snapshot" -c '/opt/keycloak/bin/kc.sh export --realm facis-ztd --file /tmp/realm.json >/dev/null 2>&1; cat /tmp/realm.json' >"$work/export.json"
sizes=$(python3 - "$work/export.json" <<'PY'
import base64, json, sys
providers = json.load(open(sys.argv[1]))["components"]["org.keycloak.keys.KeyProvider"]
print(" ".join(sorted("%s=%d" % (p["providerId"], len(base64.urlsafe_b64decode(p["config"]["secret"][0] + "=="))) for p in providers if "secret" in p["config"])))
PY
)
check "the stored AES secret is 32 bytes and the HMAC secret 128" "$sizes" "aes-generated=32 hmac-generated=128"

exit "$fail"
