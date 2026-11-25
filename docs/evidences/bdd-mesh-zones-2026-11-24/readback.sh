#!/usr/bin/env bash
# KUBECONFIG=<zone> readback.sh <a|b>: read-only (bash 4 or later, OpenSSL 3). Per node, the mesh daemons; per meshed pod of the plane namespaces, its
# node, whether the proxy is a native sidecar, the SPIFFE ID in the proxy's certificate and whether the
# certificate verifies against the SPIRE server's bundle.
set -uo pipefail
z=$1
: "${KUBECONFIG:?the zone kubeconfig}"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
echo "zone-$z, context $(kubectl config current-context), read $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "nodes: $(kubectl get nodes --no-headers | wc -l | tr -d ' ') ($(kubectl get nodes --no-headers | awk '$2=="Ready"' | wc -l | tr -d ' ') Ready)"
for ds in istio-system/istio-cni-node spire-system/spire-agent; do
  kubectl get ds -n "${ds%/*}" "${ds#*/}" -o json | jq -r --arg n "$ds" '"\($n): desired \(.status.desiredNumberScheduled), ready \(.status.numberReady)"'
done
echo "mesh mTLS mode: $(kubectl get peerauthentication -A -o json | jq -r '[.items[] | "\(.metadata.namespace)/\(.metadata.name)=\(.spec.mtls.mode)"] | join(" ")')"
kubectl -n spire-system get configmap spire-bundle -o jsonpath='{.data.bundle\.spiffe}' \
  | jq -r '.keys[] | select(.use == "x509-svid") | "-----BEGIN CERTIFICATE-----\n" + .x5c[0] + "\n-----END CERTIFICATE-----"' > "$t/bundle.pem"
echo "SPIRE bundle: $(openssl x509 -in "$t/bundle.pem" -noout -subject)"
printf '%s\n' "namespace/pod | node | native sidecar | certificate SPIFFE ID | expected | verifies against the SPIRE bundle"
ok=0 bad=0
for ns in $(kubectl get ns -l ztd.facis.io/plane -o jsonpath='{.items[*].metadata.name}'); do
  kubectl get pods -n "$ns" --field-selector=status.phase=Running -o json | jq -r '.items[] | select([(.spec.initContainers // [])[], .spec.containers[] | .name] | index("istio-proxy"))
    | [.metadata.name, (.spec.nodeName | split("-") | last), ([(.spec.initContainers // [])[] | select(.name == "istio-proxy" and .restartPolicy == "Always")] | length > 0 | if . then "yes" else "no" end), .spec.serviceAccountName] | @tsv' \
  | while IFS=$'\t' read -r pod node native sa; do
      kubectl exec -n "$ns" "$pod" -c istio-proxy -- pilot-agent request GET 'config_dump?resource=dynamic_active_secrets' 2>/dev/null \
        | jq -r '[.. | objects | select(.name? == "default") | .secret.tls_certificate.certificate_chain.inline_bytes] | first' | base64 -d > "$t/chain.pem" 2>/dev/null
      san=$(openssl x509 -in "$t/chain.pem" -noout -ext subjectAltName 2>/dev/null | grep -o 'spiffe://[^ ,]*')
      td=$(openssl x509 -in "$t/bundle.pem" -noout -subject | sed -E 's/.*CN ?= ?([^,]*).*/\1/')
      want="spiffe://$td/ns/$ns/sa/$sa"
      if openssl verify -CAfile "$t/bundle.pem" -untrusted "$t/chain.pem" "$t/chain.pem" >/dev/null 2>&1; then v=yes; else v=no; fi
      echo "$ns/$pod | $node | $native | ${san:-none} | $([ "$san" = "$want" ] && echo same || echo "$want") | $v"
    done
done | tee "$t/rows"
echo "meshed pods read: $(wc -l < "$t/rows" | tr -d ' '); own SPIFFE ID and verified: $(grep -c '| same | yes$' "$t/rows"); native sidecar: $(awk -F' [|] ' '$3=="yes"' "$t/rows" | wc -l | tr -d ' '); nodes with such a pod: $(awk -F' [|] ' '{print $2}' "$t/rows" | sort -u | wc -l | tr -d ' ')"
