#!/usr/bin/env bash
# Proof that a hand-edited constraint is put back: changes the naming constraint's pattern on the
# cluster directly, as an operator with kubectl would, and waits for Argo CD to restore the value from
# Git. Prints the value from Git, the injected one and the seconds until the restore; fails when the
# value from Git is not back within the timeout. Safe on a zone: the injected pattern still admits the
# ztd- names, and it is live for seconds.
#
#   [TIMEOUT=180] [EVIDENCE=<json file>] scripts/argocd/drift-check.sh
set -euo pipefail

timeout="${TIMEOUT:-180}"
constraint=k8sztdnaming/ztd-naming
path='{.spec.parameters.pattern}'
injected='^(ztd|drift)-[a-z0-9-]+$'

before=$(kubectl get "$constraint" -o jsonpath="$path")
[ -n "$before" ] || { echo "constraint $constraint has no pattern" >&2; exit 1; }
[ "$before" != "$injected" ] || { echo "the injected pattern is already live; nothing to prove" >&2; exit 1; }
kubectl patch "$constraint" --type merge -p "{\"spec\":{\"parameters\":{\"pattern\":\"$injected\"}}}" >/dev/null
start=$(date +%s)
seconds=
for _ in $(seq "$timeout"); do
  if [ "$(kubectl get "$constraint" -o jsonpath="$path")" = "$before" ]; then
    seconds=$(( $(date +%s) - start ))
    break
  fi
  sleep 1
done
if [ -z "$seconds" ]; then
  echo "FAIL  $constraint still carries the injected pattern after ${timeout}s" >&2
  exit 1
fi
app=$(kubectl -n argocd get application admission-constraints -o jsonpath='{.status.sync.status}/{.status.health.status}')
echo "PASS  $constraint: '$injected' put back to '$before' after ${seconds}s (admission-constraints $app)"
if [ -n "${EVIDENCE:-}" ]; then
  printf '{"constraint":"%s","fromGit":"%s","injected":"%s","restoredAfterSeconds":%s,"application":"%s"}\n' \
    "$constraint" "$before" "$injected" "$seconds" "$app" > "$EVIDENCE"
fi
