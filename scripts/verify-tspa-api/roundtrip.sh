#!/usr/bin/env bash
# Round-trip against a local TSPA. Every step appends to evidence.md.
set -u
cd "$(dirname "$0")"
BASE=http://localhost:16003/tspa-service
FW=facis-ztd.local
UUID=7d3c1e2a-5b6f-4c8d-9e0f-facis0000zt35
OUT=evidence.md
# Where things live. Defaults match this folder; TSPA_REPO must point at a clone of
# eclipse-xfsc/train-trust-framework-manager (the Keycloak realm export with the test client secret is read from it).
PAYLOADS=${PAYLOADS:-payloads}
TSPA_REPO=${TSPA_REPO:-../tspa}
mkdir -p bodies
: > "$OUT"
echo "# TSPA local round-trip evidence ($(date -Is))" >> "$OUT"
TOKEN=""

# call <label> <method> <url-path> [json-file|-] [auth|noauth] [expect]
call() {
  local label=$1 method=$2 path=$3 data=${4:--} auth=${5:-noauth} expect=${6:-}
  local url="$BASE$path" file="bodies/$(printf '%s' "$label" | tr -c 'A-Za-z0-9' '_').txt"
  local args=(-s -o "$file" -w '%{http_code}' -X "$method" "$url")
  [ "$data" != "-" ] && args+=(-H 'Content-Type: application/json' --data-binary @"$PAYLOADS/$data")
  [ "$auth" = "auth" ] && args+=(-H "Authorization: Bearer $TOKEN")
  local code; code=$(curl "${args[@]}")
  {
    echo; echo "### $label"; echo
    echo "- Request: \`$method $url\`  (auth: $auth${data:+, body: $data})"
    echo "- HTTP status: **$code**${expect:+  (expected $expect)}"
    echo '- Response (first 800 bytes):'; echo; echo '```'; head -c 800 "$file"; echo; echo '```'
  } >> "$OUT"
  echo "[$code] $label"
}

echo "## 0. Health" >> "$OUT"
call "health" GET /actuator/health

echo; echo "## 1. Token (client_credentials on the compose Keycloak, requested from inside the docker network so iss matches)" >> "$OUT"
SECRET=$(python3 -c "import json;print([c for c in json.load(open('$TSPA_REPO/keycloak/realm-export.json'))['clients'] if c['clientId']=='xfsctest'][0]['secret'])")
TOKEN=$(docker run --rm --network train-network curlimages/curl:8.10.1 -s \
  -d client_id=xfsctest -d "client_secret=$SECRET" -d grant_type=client_credentials \
  http://keycloak:8080/realms/gxfs-dev-test/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
if [ -z "$TOKEN" ]; then echo "no token obtained" | tee -a "$OUT"; exit 1; fi
python3 - "$TOKEN" >> "$OUT" <<'PY'
import sys,json,base64
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print("\nDecoded access-token claims relevant to TSPA:\n")
print("```json"); print(json.dumps({k:c.get(k) for k in ['iss','azp','preferred_username','realm_access','exp']}, indent=2)); print("```")
PY
echo "token ok"
echo; echo "## 1b. Cleanup from previous runs (ignore result)" >> "$OUT"
call "1b DELETE trust-list (cleanup)" DELETE "/tspa/v1/$FW/trust-list" - auth

echo; echo "## 2. Negative tests before anything exists" >> "$OUT"
call "2a PUT tsp without token" PUT "/tspa/v1/$FW/trust-list/tsp" tsp-v1.json noauth "401; upstream quirk gives 200+empty body, see 6b"
call "2b PUT tsp with token but no trust list yet" PUT "/tspa/v1/$FW/trust-list/tsp" tsp-v1.json auth 404

echo; echo "## 3. Trust framework (calls the external Zone Manager; expected to fail offline)" >> "$OUT"
call "3 PUT trustframework" PUT "/tspa/v1/trustframework/$FW" framework.json auth "500 offline"

echo; echo "## 4. Trust list init + first measurement" >> "$OUT"
call "4a PUT init json trust-list" PUT "/tspa/v1/init/json/$FW/trust-list" trustlist-init.json auth 201
call "4b PUT tsp v1 (TEEM 1111...)" PUT "/tspa/v1/$FW/trust-list/tsp" tsp-v1.json auth 201
call "4c GET trust-list" GET "/tspa/v1/$FW/trust-list"
grep -q 1111111111111111 bodies/4c_GET_trust_list.txt && echo "- Check: measurement 1111... present in trust list: **yes**" >> "$OUT" || echo "- Check: measurement 1111... present: **NO**" >> "$OUT"
grep -q '"ServiceTypeIdentifier" : "did:web:connector-b.facis-ztd.local"' bodies/4c_GET_trust_list.txt && echo "- Check: read-back entry has ServiceTypeIdentifier = did:web:connector-b.facis-ztd.local (TCR lookup key): **yes**" >> "$OUT" || echo "- Check: ServiceTypeIdentifier = connector DID: **NO**" >> "$OUT"

echo; echo "## 5. Idempotency" >> "$OUT"
call "5a PUT tsp v1 again (same UUID)" PUT "/tspa/v1/$FW/trust-list/tsp" tsp-v1.json auth "error"
call "5b PATCH tsp -> v2 (TEEM 2222...)" PATCH "/tspa/v1/$FW/trust-list/tsp/$UUID" tsp-v2.json auth 200
call "5c GET trust-list after PATCH" GET "/tspa/v1/$FW/trust-list"
{ grep -q 2222222222222222 bodies/5c_GET_trust_list_after_PATCH.txt && echo "- Check: 2222... present: **yes**" || echo "- Check: 2222... present: **NO**"
  grep -q 1111111111111111 bodies/5c_GET_trust_list_after_PATCH.txt && echo "- Check: 1111... still present: **yes (unexpected)**" || echo "- Check: 1111... gone: **yes**"
  grep -q '"ServiceTypeIdentifier" : "did:web:connector-b.facis-ztd.local"' bodies/5c_GET_trust_list_after_PATCH.txt && echo "- Check: ServiceTypeIdentifier still = connector DID after PATCH: **yes**" || echo "- Check: ServiceTypeIdentifier after PATCH: **NO**"; } >> "$OUT"
call "5d PATCH with UUID mismatch (url uuid != body uuid)" PATCH "/tspa/v1/$FW/trust-list/tsp/00000000-0000-0000-0000-000000000000" tsp-v2.json auth "error"

echo; echo "## 6. Signed VC (what the TCR would consume)" >> "$OUT"
call "6 GET vc trust-list" GET "/tspa/v1/$FW/vc/trust-list"
python3 - >> "$OUT" <<'PY' 2>/dev/null || true
import json
try:
    v=json.load(open('bodies/6_GET_vc_trust_list.txt'))
    print("\nVC summary:\n"); print("```json")
    print(json.dumps({"issuer":v.get("issuer"),"type":v.get("type"),"proof.type":(v.get("proof") or {}).get("type"),"proof.verificationMethod":(v.get("proof") or {}).get("verificationMethod"),"credentialSubject.keys":list((v.get("credentialSubject") or {}).keys()) if isinstance(v.get("credentialSubject"),dict) else str(type(v.get("credentialSubject")))},indent=2)); print("```")
except Exception as e: print("\n(VC body is not JSON:",e,")")
PY

echo; echo "## 6b. Auth matrix on the write endpoint (list must stay unchanged)" >> "$OUT"
before=$(curl -s "$BASE/tspa/v1/$FW/trust-list" | grep -c "$UUID")
SAVE=$TOKEN; TOKEN="not.a.jwt"
call "6b-1 PUT tsp with a malformed bearer token (Authorization: Bearer not.a.jwt)" PUT "/tspa/v1/$FW/trust-list/tsp" tsp-v1.json auth 401
TOKEN=$SAVE
T2=$(docker run --rm --network train-network curlimages/curl:8.10.1 -s -d client_id=xfsctest -d "client_secret=$SECRET" -d grant_type=password -d username=testuser -d password=testuser http://keycloak:8080/realms/gxfs-dev-test/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
SAVE=$TOKEN; TOKEN=$T2
call "6b-2 PUT tsp with a VALID token whose realm roles lack enrolltf (testuser: enrolltf only as client role)" PUT "/tspa/v1/$FW/trust-list/tsp" tsp-v1.json auth 403
TOKEN=$SAVE
python3 - "$T2" >> "$OUT" <<'PY'
import sys,json,base64
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p))
print("- testuser token claims: `realm_access.roles` = %s ; `resource_access.xfsctest.roles` = %s" % (c.get('realm_access',{}).get('roles'), (c.get('resource_access',{}).get('xfsctest') or {}).get('roles')))
PY
after=$(curl -s "$BASE/tspa/v1/$FW/trust-list" | grep -c "$UUID")
echo "- Check: TSP entries with our UUID before/after the three rejected writes: **$before / $after**" >> "$OUT"

echo; echo "## 7. Delete path (auth + cleanup)" >> "$OUT"
call "7a DELETE tsp without token" DELETE "/tspa/v1/$FW/trust-list/tsp/$UUID" - noauth "401; upstream quirk gives 200+empty body"
call "7b DELETE tsp with token" DELETE "/tspa/v1/$FW/trust-list/tsp/$UUID" - auth 200
call "7c GET trust-list after delete" GET "/tspa/v1/$FW/trust-list"
grep -q "$UUID" bodies/7c_GET_trust_list_after_delete.txt && echo "- Check: TSP still present: **yes (unexpected)**" >> "$OUT" || echo "- Check: TSP removed: **yes**" >> "$OUT"
echo; echo "done -> $OUT"
