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
ztd.openbao.validateServiceTokens: the entries of openbaoBootstrap.serviceTokens must be distinct and
must not name a reserved engine, the umbrella's own engines, each other's engines or each other's
"-storage" engines; and they need the bundled OpenBao, whose bootstrap issues them.
*/}}
{{- define "ztd.openbao.validateServiceTokens" -}}
{{- $tokens := .Values.openbaoBootstrap.serviceTokens | default list -}}
{{- if and $tokens (not .Values.openbao.enabled) -}}
{{- fail "openbaoBootstrap.serviceTokens needs the bundled OpenBao (openbao.enabled): with an external or absent OpenBao nothing issues the tokens or creates their Secrets" -}}
{{- end -}}
{{- $names := dict -}}
{{- range $tokens -}}
{{- if eq .name "bootstrap" -}}{{- fail "openbaoBootstrap.serviceTokens: the name \"bootstrap\" is taken by the bootstrap's own Secret" -}}{{- end -}}
{{- if hasKey $names .name -}}{{- fail (printf "openbaoBootstrap.serviceTokens: the name %q appears twice" .name) -}}{{- end -}}
{{- $_ := set $names .name true -}}
{{- $first := index (splitList "/" .transitMount) 0 -}}
{{- if has $first (list "transit" "secret" "sys" "auth" "identity" "cubbyhole") -}}
{{- fail (printf "openbaoBootstrap.serviceTokens: transitMount %q is a reserved or shared engine; a component gets an engine of its own" .transitMount) -}}
{{- end -}}
{{- if hasSuffix "-storage" .transitMount -}}{{- fail (printf "openbaoBootstrap.serviceTokens: transitMount %q ends in -storage, the suffix of a component's data-key engine" .transitMount) -}}{{- end -}}
{{- end -}}
{{- range $me := $tokens -}}
{{- range $other := $tokens -}}
{{- if ne $other.name $me.name -}}
{{- if eq $other.transitMount $me.transitMount -}}{{- fail (printf "openbaoBootstrap.serviceTokens: %q and %q share the transitMount %q; an engine is one identity" $me.name $other.name $me.transitMount) -}}{{- end -}}
{{- if or (hasPrefix (printf "%s/" $me.transitMount) $other.transitMount) (hasPrefix (printf "%s-storage/" $me.transitMount) $other.transitMount) -}}{{- fail (printf "openbaoBootstrap.serviceTokens: transitMount %q (%s) is nested under %q or its -storage engine (%s); OpenBao engines cannot nest" $other.transitMount $other.name $me.transitMount $me.name) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
ztd.openbao.servicePolicy: the HCL of a service token's policy for engine .mount (and .mount-storage).
*/}}
{{- define "ztd.openbao.servicePolicy" -}}
path "sys/mounts" { capabilities = ["read"] }
path "sys/mounts/{{ .mount }}/tune" { capabilities = ["read"] }
path "{{ .mount }}/keys" { capabilities = ["list"] }
path "{{ .mount }}/keys/*" { capabilities = ["create", "read", "update", "list"] }
path "{{ .mount }}/keys/+/config" { capabilities = ["deny"] }
path "{{ .mount }}/keys/+/rotate" { capabilities = ["deny"] }
path "{{ .mount }}/keys/+/trim" { capabilities = ["deny"] }
path "{{ .mount }}/keys/+/import" { capabilities = ["deny"] }
path "{{ .mount }}/keys/+/import_version" { capabilities = ["deny"] }
path "{{ .mount }}/export/*" { capabilities = ["deny"] }
path "{{ .mount }}/sign/*" { capabilities = ["update"] }
path "{{ .mount }}/verify/*" { capabilities = ["update"] }
path "sys/mounts/{{ .mount }}-storage/tune" { capabilities = ["read"] }
path "{{ .mount }}-storage/keys" { capabilities = ["list"] }
path "{{ .mount }}-storage/keys/*" { capabilities = ["create", "read", "update", "list"] }
path "{{ .mount }}-storage/keys/+/config" { capabilities = ["update"] }
path "{{ .mount }}-storage/export/*" { capabilities = ["deny"] }
path "{{ .mount }}-storage/sign/*" { capabilities = ["update"] }
path "{{ .mount }}-storage/verify/*" { capabilities = ["update"] }
path "{{ .mount }}-storage/encrypt/*" { capabilities = ["update"] }
path "{{ .mount }}-storage/decrypt/*" { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }
{{- end }}
{{- define "ztd.openbao.servicePolicyHash" -}}{{ include "ztd.openbao.servicePolicy" . | sha256sum | trunc 16 }}{{- end }}

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
# field_of FILE KEY -> the decoded value of one data key of the Secret JSON in FILE; field KEY reads
# the bootstrap's own Secret ($W/secret).
field_of() {
  sed -n 's/.*"data":{\([^}]*\)}.*/\1/p' "$1" | tr ',' '\n' | sed -n "s/^\"$2\":\"\(.*\)\"$/\1/p" | base64 -d
}
field() { field_of "$W/secret" "$1"; }
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
# mount PATH TYPE OPTIONS-JSON CHECK-PATTERN (with the token in use)
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
# Service tokens (docs/secrets.md): two transit engines (NAME's identity keys and its data keys), one
# policy limited to them and one periodic orphan token per entry of openbaoBootstrap.serviceTokens, the token in Secret ztd-openbao-NAME
# (key openbao-token) in this namespace. Issued while the root token exists; checked and renewed on
# every later run.
# svc_read NAME -> the Secret into $W/svcsecret; svc_have=yes|no (read_secret for a named Secret)
svc_read() {
  code=$(kube GET "/api/v1/namespaces/$NS/secrets/ztd-openbao-$1")
  case "$code" in
    200) cp "$W/kbody" "$W/svcsecret"; svc_have=yes ;;
    404) : > "$W/svcsecret"; svc_have=no ;;
    *) die "reading Secret ztd-openbao-$1: HTTP $code" ;;
  esac
}
svc_field() { field_of "$W/svcsecret" "$1"; }
# svc_token_valid NAME -> 0 when the Secret holds a token that answers lookup-self AND carries the
# policy ztd-svc-NAME (a foreign token planted in the Secret is not "valid"); 2 when OpenBao did not
# answer a 2xx/4xx (an outage, not a verdict); 1 otherwise. The token in use before the call is in
# use again after it.
svc_token_valid() {
  svc_read "$1"
  [ "$svc_have" = yes ] || return 1
  t=$(svc_field openbao-token); [ -n "$t" ] || return 1
  rm -f "$W/btoken.keep"; [ -f "$W/btoken" ] && cp "$W/btoken" "$W/btoken.keep"
  use_token "$t"; code=$(bao GET auth/token/lookup-self || true); code=${code:-000}
  if [ -f "$W/btoken.keep" ]; then mv "$W/btoken.keep" "$W/btoken"; else no_token; fi
  case "$code" in
    200) tr -d '\n ' < "$W/bbody" | sed -n 's/.*"policies":\[\([^]]*\)\].*/\1/p' | grep -q "\"ztd-svc-$1\"" ;;
    4*) return 1 ;;
    *) return 2 ;;
  esac
}
# svc_patch_hash NAME HASH: record which policy text the Secret's token was issued or checked under.
svc_patch_hash() {
  printf '{"stringData":{"policy-sha256":"%s"}}' "$2" > "$W/req"
  code=$(kube PATCH "/api/v1/namespaces/$NS/secrets/ztd-openbao-$1" application/merge-patch+json "$W/req" || true); rm -f "$W/req"
  [ "$code" = 200 ] || die "recording the policy hash in Secret ztd-openbao-$1: HTTP $code"
}
# svc_store NAME TOKEN HASH: the token (and the hash of its policy) into Secret ztd-openbao-NAME; on
# failure the token is revoked before the Job dies, so nothing valid is left unreferenced.
svc_store() {
  if [ "$svc_have" = yes ]; then
    printf '{"stringData":{"openbao-token":"%s","policy-sha256":"%s"}}' "$2" "$3" > "$W/req"
    code=$(kube PATCH "/api/v1/namespaces/$NS/secrets/ztd-openbao-$1" application/merge-patch+json "$W/req" || true); rm -f "$W/req"
    [ "$code" = 200 ] && return 0
  else
    printf '{"apiVersion":"v1","kind":"Secret","type":"Opaque","metadata":{"name":"ztd-openbao-%s","labels":{"app.kubernetes.io/name":"ztd-openbao-bootstrap","ztd.facis.io/service-token":"%s"}},"stringData":{"openbao-token":"%s","policy-sha256":"%s"}}' "$1" "$1" "$2" "$3" > "$W/req"
    code=$(kube POST "/api/v1/namespaces/$NS/secrets" application/json "$W/req" || true); rm -f "$W/req"
    [ "$code" = 201 ] && return 0
  fi
  cp "$W/btoken" "$W/btoken.keep"; use_token "$2"; bao POST auth/token/revoke-self >/dev/null || true; mv "$W/btoken.keep" "$W/btoken"
  die "storing Secret ztd-openbao-$1: HTTP $code (the token was revoked again)"
}
# service_token NAME MOUNT PERIOD (root token in use): the engine, the policy, the token when missing
# or expired. The policy covers that engine's keys, signing and verification, the engine's mount
# config and the mount table (the signer lists both), and a second engine beside it, MOUNT-storage
# (engines cannot nest), for keys, signing, verification, encryption and decryption: the W-Stack's
# storage service keeps its per-account keys there, out of the identity engine, and sets their
# per-key config when it creates them); key export stays denied in both and the identity engine's
# per-key config too, so the identity key can never be made exportable.
service_token() {
  mount "$2" transit '{}' '"type":"transit"'
  mount "$2-storage" transit '{}' '"type":"transit"'
  # The policy text is rendered by the chart (ztd.openbao.servicePolicy) and handed in as $4; its
  # hash ($5) is what the Secret records.
  printf '%s' "$4" > "$W/hcl"
  printf '{"policy":"%s"}' "$(sed 's/"/\\"/g' "$W/hcl" | tr '\n' ' ')" > "$W/req"
  phash=$5; rm -f "$W/hcl"
  code=$(bao PUT "sys/policies/acl/ztd-svc-$1" "$W/req"); rm -f "$W/req"
  [ "$code" = 204 ] || die "policy ztd-svc-$1: HTTP $code"
  v=0; svc_token_valid "$1" || v=$?
  case "$v" in
    0) svc_patch_hash "$1" "$phash"; say "service token $1 is valid"; return 0 ;;
    2) die "service token $1: OpenBao did not answer the lookup (HTTP $code); not replacing a token during an outage" ;;
  esac
  printf '{"policies":["ztd-svc-%s"],"period":"%s","display_name":"ztd-svc-%s","no_default_policy":true}' "$1" "$3" "$1" > "$W/req"
  code=$(bao POST auth/token/create-orphan "$W/req"); rm -f "$W/req"
  [ "$code" = 200 ] || die "service token $1: HTTP $code"
  t=$(jstr client_token "$W/bbody"); rm -f "$W/bbody"
  [ -n "$t" ] || die "service token $1: no token in the response"
  svc_store "$1" "$t" "$phash"
  say "service token $1 issued for $2/ and $2-storage/"
}
service_tokens() {
{{- range .Values.openbaoBootstrap.serviceTokens }}
  service_token {{ .name | quote }} {{ .transitMount | quote }} {{ .period | default "768h" | quote }} {{ include "ztd.openbao.servicePolicy" (dict "mount" .transitMount) | squote }} {{ include "ztd.openbao.servicePolicyHash" (dict "mount" .transitMount) | quote }}
{{- end }}
  :
}
# Every service token must exist and answer, and is renewed; otherwise the Job fails and names the
# recovery (docs/secrets.md). Runs with the service token itself, so it needs no root token.
service_tokens_check() {
{{- range .Values.openbaoBootstrap.serviceTokens }}
  v=0; svc_token_valid {{ .name | quote }} || v=$?
  [ "$v" != 2 ] || die "service token {{ .name }}: OpenBao did not answer the lookup (HTTP $code)"
  [ "$v" = 0 ] || die "service token {{ .name }} is missing, expired or not ours (HTTP $code) and the root token is gone: recovery in docs/secrets.md"
  [ "$(svc_field policy-sha256)" = {{ include "ztd.openbao.servicePolicyHash" (dict "mount" .transitMount) | quote }} ] || die "service token {{ .name }}: its policy changed in this chart version and cannot be rewritten without the root token: recovery in docs/secrets.md"
  use_token "$(svc_field openbao-token)"; code=$(bao POST auth/token/renew-self); [ "$code" = 200 ] || die "renewing service token {{ .name }}: HTTP $code"
  say "service token {{ .name }} renewed"
{{- end }}
  :
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
  use_token "$root"
  service_tokens; tokens_done=yes
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
      # A root token put back by the recovery (docs/secrets.md) issues the service tokens that are
      # missing, then goes the way of every root token.
      [ "${tokens_done:-no}" = yes ] || service_tokens
      use_token "$root"
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
service_tokens_check
rm -f "$W/bbody" "$W/btoken" "$W/secret" "$W/svcsecret"
say "done: initialised, unsealed, kv-v2 at secret/, transit at transit/, service tokens checked, root token revoked"
{{- end }}
