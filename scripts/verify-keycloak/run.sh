#!/usr/bin/env bash
# Isolated local-services proof; never uses kubectl or changes a kube context.
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
for tool in docker helm node go openssl python3; do command -v "$tool" >/dev/null; done
docker info >/dev/null 2>&1 || { echo 'Docker is unavailable; no proof ran' >&2; exit 1; }
work="$(mktemp -d)"
name="ztd-keycloak-$(date +%s)-$$"
cleanup() {
  docker rm -f "$name-keycloak" "$name-postgres" "$name-bao" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
export BDD_TARGET=local-services BDD_RUN_ID="$name" BDD_MODE=cluster
export FACIS_OIDC_ISSUER="https://127.0.0.1:${KEYCLOAK_LOCAL_PORT:-18443}/realms/facis-ztd"
export FACIS_UI_ORIGIN=https://127.0.0.1:18444
export NODE_EXTRA_CA_CERTS="$work/cert.pem"
export KEYCLOAK_GUARD_TOKEN_FILE="$work/viewer-token"
export BDD_OPERATOR_PASSWORD="$(openssl rand -hex 24)" BDD_OBSERVER_PASSWORD="$(openssl rand -hex 24)"
export TRANSIT_TEST_TOKEN="$(openssl rand -hex 24)" POSTGRES_PASSWORD="$(openssl rand -hex 24)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" \
  -days 1 -subj /CN=127.0.0.1 -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
helm template identity deployment/helm/facis-ztd-keycloak --show-only templates/configmap.yaml \
  --set "keycloak.publicUrl=${FACIS_OIDC_ISSUER%/realms/facis-ztd}" --set "ui.origin=$FACIS_UI_ORIGIN" > "$work/rendered.yaml"
node scripts/verify-keycloak/realm.cjs "$work/rendered.yaml" "$work/realm.json"
# Copy private files into this disposable container; do not make them world-readable for mounts.
keycloak_image="$(sed -n 's/^  image: \(quay.io\/keycloak\/keycloak:.*\)$/\1/p' deployment/helm/facis-ztd-keycloak/values.yaml)"
docker create --name "$name-keycloak" -p "127.0.0.1:${KEYCLOAK_LOCAL_PORT:-18443}:8443" \
  "$keycloak_image" start-dev --import-realm --http-enabled=false \
  "--hostname=${FACIS_OIDC_ISSUER%/realms/facis-ztd}" \
  --https-certificate-file=/tmp/cert.pem --https-certificate-key-file=/tmp/key.pem >/dev/null
python3 - "$work" <<'ARCHIVE'
import os, sys, tarfile
work = sys.argv[1]
with tarfile.open(os.path.join(work, 'files.tar'), 'w') as archive:
    for src, dst in [('cert.pem', 'tmp/cert.pem'), ('key.pem', 'tmp/key.pem'), ('realm.json', 'opt/keycloak/data/import/realm.json')]:
        info = archive.gettarinfo(os.path.join(work, src), dst)
        info.uid, info.gid, info.uname, info.gname = 1000, 0, '', ''
        with open(os.path.join(work, src), 'rb') as stream:
            archive.addfile(info, stream)
ARCHIVE
docker cp -a - "$name-keycloak:/" < "$work/files.tar"
docker start "$name-keycloak" >/dev/null
docker run -d --name "$name-postgres" -p 127.0.0.1::5432 -e POSTGRES_PASSWORD \
  postgres:16.10-alpine@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297 >/dev/null
docker run -d --name "$name-bao" -p 127.0.0.1::8200 -e "BAO_DEV_ROOT_TOKEN_ID=$TRANSIT_TEST_TOKEN" \
  openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315 server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null
pg_port="$(docker port "$name-postgres" 5432/tcp | sed 's/.*://')"
bao_port="$(docker port "$name-bao" 8200/tcp | sed 's/.*://')"
export TOKEN_STORE_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@127.0.0.1:$pg_port/postgres?sslmode=disable"
export TRANSIT_TEST_ADDR="http://127.0.0.1:$bao_port"
for ((i=0;i<120;i++)); do
  if docker exec "$name-postgres" pg_isready -U postgres >/dev/null 2>&1 && \
    docker exec "$name-bao" sh -c 'BAO_ADDR=http://127.0.0.1:8200 bao status' >/dev/null 2>&1 && \
    node -e 'require("https").get(process.env.FACIS_OIDC_ISSUER+"/.well-known/openid-configuration",r=>{r.resume();process.exitCode=r.statusCode===200?0:1}).on("error",()=>process.exitCode=1)' >/dev/null 2>&1; then break; fi
  [ "$(docker inspect -f '{{.State.Running}}' "$name-keycloak")" = true ] || break
  sleep 2
done
# A Keycloak that stopped or never answered is reported with its own last lines (no secrets there:
# the realm source is redacted by the server), instead of failing later in the scenario.
node -e 'require("https").get(process.env.FACIS_OIDC_ISSUER+"/.well-known/openid-configuration",r=>{r.resume();process.exitCode=r.statusCode===200?0:1}).on("error",()=>process.exitCode=1)' ||
  { docker logs --tail 5 "$name-keycloak" >&2 || true; echo 'Keycloak did not become ready; no proof ran' >&2; exit 1; }
# No credentials in process arguments or evidence: the container already has the dev token.
docker exec "$name-bao" sh -c 'export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$BAO_DEV_ROOT_TOKEN_ID"; bao secrets enable transit' >/dev/null
export GODOG_CUCUMBER_OUT="bundles/bdd/keycloak-$BDD_RUN_ID.json"
go test -count=1 -timeout 30m ./internal/bdd -godog.tags=@TDR-BDD-05
printf 'Proof passed: %s\n' "$GODOG_CUCUMBER_OUT"
