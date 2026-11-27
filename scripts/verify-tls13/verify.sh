#!/usr/bin/env bash
# Proves the TLS 1.3 minimum of the public ingress (behind TDR-BDD-07) on a throwaway kind cluster
# with the ingress controller the IONOS cluster uses, Traefik, under the same ingress class name:
#
#   1. Traefik as its chart installs it, an application behind an Ingress with a TLS certificate.
#      The scenario must FAIL here, and on TLS 1.2 alone: Traefik accepts it by default.
#   2. deployment/ingress/traefik-tls-options.yaml applied. The same scenario must pass: TLS 1.3
#      completes a request; TLS 1.2, 1.1 and 1.0 are each refused with the protocol-version alert.
#
# The scenario is the one that runs against a target (features/go/tls-public-ingress.feature,
# BDD_MODE=cluster). It proves the manifest and the controller, not a target: a target is proven by
# running the scenario with that target's hosts in BDD_TLS_ENDPOINTS.
# Needs docker, kind, kubectl, helm, openssl and go. KEEP=1 leaves the cluster for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env

cluster=ztd-tls13
host=tls13.ztd.test
port="${TLS13_PORT:-18444}"
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
trap '[ -n "${KEEP:-}" ] || kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s --config - >/dev/null 2>&1 <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - {containerPort: 30443, hostPort: $port, listenAddress: "127.0.0.1", protocol: TCP}
KIND

helm pull traefik --repo "$TRAEFIK_CHART_REPO" --version "$TRAEFIK_CHART_VERSION" --destination "$work" >/dev/null
chart="$work/traefik-$TRAEFIK_CHART_VERSION.tgz"
[ "$(sha256 "$chart")" = "$TRAEFIK_CHART_SHA256" ] || { echo "the Traefik chart is not the pinned one" >&2; exit 1; }
# Nothing about TLS is set: the controller is as its chart ships it, only reachable from here.
helm install traefik "$chart" --namespace traefik --create-namespace --wait --timeout 300s \
  --set ingressClass.name=ztd-public --set service.spec.type=NodePort --set ports.websecure.nodePort=30443 >/dev/null

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -keyout "$work/tls.key" -out "$work/tls.crt" -subj "/CN=$host" -addext "subjectAltName=DNS:$host" 2>/dev/null
kubectl create namespace tls13 >/dev/null
kubectl -n tls13 create secret tls app-tls --cert="$work/tls.crt" --key="$work/tls.key" >/dev/null
kubectl apply -f - >/dev/null <<APP
apiVersion: apps/v1
kind: Deployment
metadata: {name: app, namespace: tls13}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
        - name: app
          image: $WHOAMI_IMAGE
          ports: [{containerPort: 80}]
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: tls13}
spec:
  selector: {app: app}
  ports: [{name: http, port: 80}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: app, namespace: tls13}
spec:
  ingressClassName: ztd-public
  tls: [{hosts: [$host], secretName: app-tls}]
  rules:
    - host: $host
      http:
        paths:
          - {path: /, pathType: Prefix, backend: {service: {name: app, port: {name: http}}}}
APP
kubectl -n tls13 rollout status deployment/app --timeout=180s >/dev/null

scenario() { # the scenario against the ingress; its output goes to $work/scenario.log
  BDD_MODE=cluster BDD_TLS_ENDPOINTS="$host:443@127.0.0.1:$port" BDD_TLS_CA_FILE="$work/tls.crt" \
    go test ./internal/bdd -count=1 -godog.tags=@tls-ingress >"$work/scenario.log" 2>&1
}

# The Ingress is served once Traefik has read it and its certificate; until then the handshake is
# answered with Traefik's own certificate, which the scenario refuses for either version.
served=0
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null --connect-timeout 5 --max-time 10 --resolve "$host:$port:127.0.0.1" --cacert "$work/tls.crt" "https://$host:$port/" 2>/dev/null; then served=1; break; fi
  sleep 2
done
[ "$served" = 1 ] || { echo "FAIL  the ingress never served the application with its certificate" >&2; exit 1; }

fail=0
if scenario; then
  echo "FAIL  before the TLS option the scenario passed: the rig does not show the default"; fail=1
elif grep -q "$host:443: TLS 1.2 was accepted" "$work/scenario.log" && ! grep -Eq "TLS 1.3 did not succeed|TLS 1.[01] was accepted|ended without" "$work/scenario.log"; then
  echo "ok    Traefik as installed accepts TLS 1.2 and refuses 1.1 and 1.0, and the scenario fails on exactly that"
else
  echo "FAIL  before the TLS option the scenario failed for another reason"; cat "$work/scenario.log"; fail=1
fi

kubectl -n traefik apply -f deployment/ingress/traefik-tls-options.yaml >/dev/null
passed=0
for _ in $(seq 1 15); do
  if scenario; then passed=1; break; fi
  sleep 2
done
if [ "$passed" = 1 ]; then
  echo "ok    with the TLS option, TLS 1.3 completes a request and TLS 1.2, 1.1 and 1.0 are each refused with the protocol-version alert"
else
  echo "FAIL  with the TLS option the scenario still fails"; cat "$work/scenario.log"; fail=1
fi
exit "$fail"
