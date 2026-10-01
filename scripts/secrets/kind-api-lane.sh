#!/usr/bin/env bash
# Print the networkPolicy.kubeApi values overlay for the cluster of the current kube context: the API
# server endpoints and port read off the cluster, not assumed. The OpenBao bootstrap needs this lane
# to store its Secret (docs/secrets.md); a zone file records the same facts for a real zone.
#
#   scripts/secrets/kind-api-lane.sh > api-lane.yaml
set -euo pipefail

slice=$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o jsonpath='{range .items[*]}{range .endpoints[*]}{.addresses[*]}{" "}{end}{"|"}{.ports[0].port}{"\n"}{end}')
addresses=$(printf '%s\n' "$slice" | cut -d'|' -f1 | xargs)
port=$(printf '%s\n' "$slice" | cut -d'|' -f2 | head -1)
[ -n "$addresses" ] && [ -n "$port" ] || { echo "cannot read the API server endpoint off the cluster" >&2; exit 1; }
cidrs=$(for a in $addresses; do printf '"%s/32", ' "$a"; done)
printf 'networkPolicy:\n  kubeApi:\n    enabled: true\n    cidrs: [%s]\n    ports: [%s]\n' "${cidrs%, }" "$port"
