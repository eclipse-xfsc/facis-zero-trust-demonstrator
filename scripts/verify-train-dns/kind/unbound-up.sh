#!/usr/bin/env bash
# Start the validating resolver pod with the given DS as its trust anchor. Prints the pod IP.
#   unbound-up.sh "<DS record as the zone manager printed it>"
#   KIND_CONTEXT (default kind-ztd), NAMESPACE (default train), ZONE (default trust.ztd.test), DNS_IP (default 10.96.0.53)
set -euo pipefail
cd "$(dirname "$0")"
DS=${1:?DS record}; CONTEXT=${KIND_CONTEXT:-kind-ztd}; NS=${NAMESPACE:-train}; ZONE=${ZONE:-trust.ztd.test}; DNS_IP=${DNS_IP:-10.96.0.53}
k() { kubectl --context "$CONTEXT" -n "$NS" "$@"; }
# the zone manager prints the DS with tabs and a trailing dot on the owner; unbound wants one line
ds=$(printf '%s' "$DS" | tr '\t' ' ' | sed 's/  */ /g')
sed -e "s|__DS__|$ds|" -e "s|__ZONE__|$ZONE|" -e "s|__DNS_IP__|$DNS_IP|" unbound.conf.tmpl > unbound.conf
k delete pod unbound --ignore-not-found --wait=true >/dev/null
k create configmap unbound-conf --from-file=unbound.conf --dry-run=client -o yaml | k apply -f - >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: unbound
spec:
  restartPolicy: Never
  containers:
    - name: unbound
      image: docker.io/library/alpine:3.20
      command: ["sh", "-c", "apk add -q unbound && unbound-anchor -a /tmp/root.key >/dev/null 2>&1; unbound -d -c /conf/unbound.conf"]
      volumeMounts: [{ name: conf, mountPath: /conf }]
  volumes:
    - name: conf
      configMap: { name: unbound-conf }
YAML
k wait --for=jsonpath='{.status.podIP}' pod/unbound --timeout=120s >/dev/null
k get pod unbound -o jsonpath='{.status.podIP}'; echo
