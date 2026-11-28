#!/usr/bin/env bash
# Local Docker proof only. Creates and removes its own PostgreSQL and OpenBao; never touches a zone.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
for tool in docker go openssl; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }; done
docker info >/dev/null 2>&1 || { echo 'Docker daemon unavailable' >&2; exit 1; }
run="application-feed-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 3)"
pg="$run-pg"
bao="$run-bao"
cleanup() { docker rm -f "$pg" "$bao" >/dev/null 2>&1 || true; }
trap cleanup EXIT
pg_password="$(openssl rand -hex 24)"
bao_token="$(openssl rand -hex 24)"
docker run -d --name "$pg" -e POSTGRES_PASSWORD="$pg_password" -p 127.0.0.1::5432 \
  postgres:16.10-alpine@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297 >/dev/null
docker run -d --name "$bao" -e BAO_DEV_ROOT_TOKEN_ID="$bao_token" -p 127.0.0.1::8200 \
  openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315 \
  server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null
ready=false
for ((i=0; i<60; i++)); do
  if docker exec "$pg" pg_isready -U postgres >/dev/null 2>&1 && \
     docker exec -e BAO_ADDR=http://127.0.0.1:8200 "$bao" bao status >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
$ready || { echo 'Local services did not become ready' >&2; exit 1; }
docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$bao_token" "$bao" bao secrets enable transit >/dev/null
pg_port="$(docker port "$pg" 5432/tcp)"
bao_port="$(docker port "$bao" 8200/tcp)"
export TOKEN_STORE_TEST_DATABASE_URL="postgres://postgres:$pg_password@127.0.0.1:${pg_port##*:}/postgres?sslmode=disable"
export TRANSIT_TEST_ADDR="http://127.0.0.1:${bao_port##*:}" TRANSIT_TEST_TOKEN="$bao_token"
export BDD_MODE=cluster BDD_TARGET=local-services BDD_RUN_ID="$run"
export GODOG_CUCUMBER_OUT="bundles/bdd/$run.json"
go test -count=1 -timeout 35m ./internal/bdd -godog.tags=@ZT-75
echo "Evidence: bundles/bdd/evidence/bdd-zt-075/local-services/$run"
echo "Cucumber report: $GODOG_CUCUMBER_OUT"
