{{/*
OpenBao helpers (docs/secrets.md).

ztd.openbao.address: the server the bootstrap and the verification talk to - the external address
when one is configured, otherwise the bundled server's Service, named the way the upstream chart
names it (its fullname: the release name when that already contains "openbao", else
<release>-openbao).
*/}}
{{- define "ztd.openbao.address" -}}
{{- if .Values.openbaoExternal.address -}}
{{- .Values.openbaoExternal.address -}}
{{- else -}}
{{- $fullname := printf "%s-openbao" .Release.Name -}}
{{- if contains "openbao" .Release.Name }}{{ $fullname = .Release.Name }}{{ end -}}
{{- printf "http://%s.%s.svc:8200" $fullname .Values.planes.management.namespace -}}
{{- end -}}
{{- end }}

{{/*
ztd.openbao.bootstrapScript: the bootstrap Job's script (POSIX sh, curl image). See the state table in
openbao-bootstrap.yaml. Inputs: BAO_ADDR, SECRET. Never prints a credential.
*/}}
{{- define "ztd.openbao.bootstrapScript" -}}
umask 077
W=/work
SA=/var/run/secrets/kubernetes.io/serviceaccount
API=https://kubernetes.default.svc
NS=$(cat "$SA/namespace")
printf 'Authorization: Bearer %s' "$(cat "$SA/token")" > "$W/kauth"

say() { echo "bootstrap: $*"; }
die() { echo "bootstrap: FAIL $*"; exit 1; }

# kube METHOD PATH [CONTENT-TYPE BODY-FILE] -> HTTP code; response in $W/kbody
kube() {
  if [ $# -gt 2 ]; then
    curl -sS --cacert "$SA/ca.crt" -H "@$W/kauth" -X "$1" -H "Content-Type: $3" --data-binary "@$4" -o "$W/kbody" -w '%{http_code}' "$API$2"
  else
    curl -sS --cacert "$SA/ca.crt" -H "@$W/kauth" -X "$1" -o "$W/kbody" -w '%{http_code}' "$API$2?pretty=false"
  fi
}
# bao METHOD PATH [BODY-FILE] -> HTTP code; response in $W/bbody. Token from $W/btoken when present.
bao() {
  set -- "$1" "$2" "${3:-}"
  auth=""; [ -f "$W/btoken" ] && auth="@$W/btoken"
  curl -sS -X "$1" ${auth:+-H "$auth"} ${3:+--data-binary "@$3"} -o "$W/bbody" -w '%{http_code}' "$BAO_ADDR/v1/$2"
}
use_token() { printf 'X-Vault-Token: %s' "$1" > "$W/btoken"; }
no_token() { rm -f "$W/btoken"; }
jstr() { tr -d '\n' < "$2" | sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p"; }
jbool() { tr -d '\n ' < "$2" | grep -o "\"$1\":[a-z]*" | head -1 | cut -d: -f2; }
# field KEY -> the decoded value of one key of the Secret read last into $W/secret
field() {
  sed -n 's/.*"data":{\([^}]*\)}.*/\1/p' "$W/secret" | tr ',' '\n' | sed -n "s/^\"$1\":\"\(.*\)\"$/\1/p" | base64 -d
}
read_secret() {
  code=$(kube GET "/api/v1/namespaces/$NS/secrets/$SECRET")
  case "$code" in
    200) cp "$W/kbody" "$W/secret"; have_secret=yes ;;
    404) : > "$W/secret"; have_secret=no ;;
    *) die "reading Secret $SECRET: HTTP $code" ;;
  esac
}
# patch_secret JSON-OBJECT-BODY (merge patch, e.g. {"stringData":{"state":"configured"}})
patch_secret() {
  printf '%s' "$1" > "$W/req"
  code=$(kube PATCH "/api/v1/namespaces/$NS/secrets/$SECRET" application/merge-patch+json "$W/req")
  rm -f "$W/req"
  [ "$code" = 200 ] || die "patching Secret $SECRET: HTTP $code"
}
health() {
  bao GET "sys/health?uninitcode=200&sealedcode=200&standbycode=200" >/dev/null || true
  initialized=$(jbool initialized "$W/bbody"); sealed=$(jbool sealed "$W/bbody")
}

say "waiting for $BAO_ADDR"
no_token
for i in $(seq 1 60); do
  code=$(bao GET "sys/health?uninitcode=200&sealedcode=200&standbycode=200" || true)
  [ "$code" = 200 ] && break
  [ "$i" = 60 ] && die "OpenBao did not answer (last HTTP $code)"
  sleep 5
done
health
read_secret
say "initialized=$initialized sealed=$sealed secret=$have_secret"

if [ "$initialized" = false ]; then
  [ "$have_secret" = no ] || die "OpenBao is not initialised but Secret $SECRET exists: its storage was lost. The Secret is never overwritten; remove it deliberately to start over (docs/secrets.md)."
  printf '{"secret_shares":1,"secret_threshold":1}' > "$W/req"
  code=$(bao PUT sys/init "$W/req")
  [ "$code" = 200 ] || die "sys/init: HTTP $code"
  unseal=$(tr -d '\n ' < "$W/bbody" | sed -n 's/.*"keys_base64":\["\([^"]*\)".*/\1/p')
  root=$(jstr root_token "$W/bbody")
  rm -f "$W/bbody"
  [ -n "$unseal" ] && [ -n "$root" ] || die "sys/init returned no key or token"
  printf '{"apiVersion":"v1","kind":"Secret","type":"Opaque","metadata":{"name":"%s","labels":{"app.kubernetes.io/name":"%s"}},"stringData":{"unseal-key":"%s","root-token":"%s","state":"initialized"}}' \
    "$SECRET" "$SECRET" "$unseal" "$root" > "$W/req"
  stored=no
  for i in 1 2 3 4 5; do
    code=$(kube POST "/api/v1/namespaces/$NS/secrets" application/json "$W/req")
    [ "$code" = 201 ] && { stored=yes; break; }
    sleep 3
  done
  rm -f "$W/req"
  [ "$stored" = yes ] || die "OpenBao was initialised but its keys could not be stored (HTTP $code); they are lost - remove the OpenBao volume and reinstall (docs/secrets.md)"
  say "initialised; unseal key and root token stored in Secret $SECRET"
  read_secret
elif [ "$have_secret" = no ]; then
  die "OpenBao is initialised but Secret $SECRET is missing; refusing to re-initialise (docs/secrets.md)"
fi

if [ "$sealed" != false ]; then
  printf '{"key":"%s"}' "$(field unseal-key)" > "$W/req"
  code=$(bao PUT sys/unseal "$W/req"); rm -f "$W/req"
  [ "$code" = 200 ] && [ "$(jbool sealed "$W/bbody")" = false ] || die "unseal: HTTP $code"
  say "unsealed"
fi

state=$(field state)
if [ "$state" = initialized ]; then
  root=$(field root-token)
  [ -n "$root" ] || die "state=initialized without a root token"
  use_token "$root"
  # mount PATH TYPE OPTIONS-JSON CHECK-PATTERN
  mount() {
    code=$(bao GET "sys/mounts/$1")
    if [ "$code" = 200 ]; then
      tr -d '\n ' < "$W/bbody" | grep -q "$4" || die "$1/ exists but is not $2 as required"
    else
      printf '{"type":"%s","options":%s}' "$2" "$3" > "$W/req"
      code=$(bao POST "sys/mounts/$1" "$W/req"); rm -f "$W/req"
      [ "$code" = 204 ] || die "enabling $2 at $1/: HTTP $code"
    fi
    say "$1/ is $2"
  }
  mount secret kv '{"version":"2"}' '"type":"kv".*"version":"2"'
  mount transit transit '{}' '"type":"transit"'
  printf '{}' > "$W/req"
  code=$(bao POST transit/keys/ztd-fixture "$W/req")
  case "$code" in 200|204) ;; *) die "transit key ztd-fixture: HTTP $code" ;; esac
  code=$(bao GET secret/data/ztd-fixture/canary)
  if [ "$code" = 404 ]; then
    printf '{"data":{"value":"%s"}}' "$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')" > "$W/req"
    code=$(bao POST secret/data/ztd-fixture/canary "$W/req")
    [ "$code" = 200 ] || die "fixture KV value: HTTP $code"
  fi
  printf '%s' '{"policy":"path \"sys/mounts/*\" { capabilities = [\"read\"] }\npath \"secret/data/ztd-fixture/*\" { capabilities = [\"read\"] }\npath \"transit/encrypt/ztd-fixture\" { capabilities = [\"update\"] }\npath \"transit/decrypt/ztd-fixture\" { capabilities = [\"update\"] }\npath \"auth/token/renew-self\" { capabilities = [\"update\"] }\npath \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n"}' > "$W/req"
  code=$(bao PUT sys/policies/acl/ztd-verify "$W/req"); rm -f "$W/req"
  [ "$code" = 204 ] || die "policy ztd-verify: HTTP $code"
  verify=$(field verify-token)
  valid=no
  if [ -n "$verify" ]; then
    use_token "$verify"; [ "$(bao GET auth/token/lookup-self)" = 200 ] && valid=yes
    use_token "$root"
  fi
  if [ "$valid" = no ]; then
    printf '{"policies":["ztd-verify"],"period":"768h","display_name":"ztd-verify"}' > "$W/req"
    code=$(bao POST auth/token/create-orphan "$W/req"); rm -f "$W/req"
    [ "$code" = 200 ] || die "verification token: HTTP $code"
    verify=$(jstr client_token "$W/bbody"); rm -f "$W/bbody"
    patch_secret "{\"stringData\":{\"verify-token\":\"$verify\"}}"
    say "verification token issued"
  fi
  use_token "$verify"
  [ "$(bao GET auth/token/lookup-self)" = 200 ] || die "the verification token does not work"
  [ "$(bao GET secret/data/ztd-fixture/canary)" = 200 ] || die "the verification token cannot read the fixture"
  rm -f "$W/bbody"
  patch_secret '{"stringData":{"state":"configured"}}'
  say "configured"
  read_secret
  state=configured
fi

[ "$state" = configured ] || die "unknown state '$state' in Secret $SECRET"
root=$(field root-token)
if [ -n "$root" ]; then
  use_token "$root"
  code=$(bao GET auth/token/lookup-self)
  case "$code" in
    200)
      code=$(bao POST auth/token/revoke-self)
      [ "$code" = 204 ] || die "revoking the root token: HTTP $code"
      patch_secret '{"data":{"root-token":null}}'
      say "root token revoked and removed" ;;
    403)
      patch_secret '{"data":{"root-token":null}}'
      say "root token was already revoked; removed" ;;
    *) die "checking the root token: HTTP $code" ;;
  esac
fi
use_token "$(field verify-token)"
code=$(bao POST auth/token/renew-self)
[ "$code" = 200 ] || die "renewing the verification token: HTTP $code (expired? see docs/secrets.md)"
rm -f "$W/bbody" "$W/btoken" "$W/secret"
say "done: initialised, unsealed, kv-v2 at secret/, transit at transit/, root token revoked"
{{- end }}
