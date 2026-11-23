#!/usr/bin/env bash
# The admission evidence pack of one cluster, re-runnable: the ZT-72 acceptance row with the namespaced
# tester identity (a signed image starts; unsigned, untrusted-key, mutable-tag, missing-SBOM and
# missing-mock-attestation images are refused with their reason codes), then the fault cases
# (fault-injection.sh). Both always run; the pack and an index land in bundles/admission/<target>/.
# Run by the cluster administrator after install.sh, with the inputs fault-injection.sh takes.
#
#   ADMIN_KUBECONFIG=... FIXTURES=<case ref list> BIN=... PROVIDER_IMAGE=... TRUST_REPOSITORY=... \
#   TRUST_KEY=... [OUTSIDE_NAMESPACES="ns ..."] [CLUSTER_KIND=target|non-target] \
#   scripts/admission/evidence-pack.sh <target>
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
[ $# -eq 1 ] || { echo "usage: $0 <target>" >&2; exit 2; }
target="$1"
[[ "$target" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "target must be a name like zone-a" >&2; exit 2; }
kind="${CLUSTER_KIND:-non-target}"
case "$kind" in target | non-target) ;; *) echo "CLUSTER_KIND must be target or non-target" >&2; exit 2 ;; esac
: "${ADMIN_KUBECONFIG:?}" "${FIXTURES:?}" "${BIN:?}" "${PROVIDER_IMAGE:?}" "${TRUST_REPOSITORY:?}" "${TRUST_KEY:?}"
FIXTURES="$(cd "$(dirname "$FIXTURES")" && pwd)/$(basename "$FIXTURES")"
run="${BDD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
out="bundles/admission/$target"
rm -rf "$out" "bundles/bdd/evidence/bdd-zt-072/$target"
mkdir -p "$out"
admin() { KUBECONFIG="$ADMIN_KUBECONFIG" kubectl "$@"; }
cluster_uid="$(admin get namespace kube-system -o jsonpath='{.metadata.uid}')"

# A short-lived kubeconfig for the namespaced tester (admission-pool chart); never the administrator.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# An interruption exits through the EXIT trap; bash runs it once the foreground child (the fault script,
# which restores the cluster on its own interruption) has finished.
trap 'exit 130' INT TERM
tester="$work/tester.kubeconfig"
(
  umask 077
  admin config view --minify --flatten -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$work/ca.crt"
  KUBECONFIG="$tester" kubectl config set-cluster "$target" --server="$(admin config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
    --certificate-authority="$work/ca.crt" --embed-certs >/dev/null
  KUBECONFIG="$tester" kubectl config set-credentials tester --token="$(admin -n ztd-adm-001 create token ztd-adm-tester --duration=2h)" >/dev/null
  KUBECONFIG="$tester" kubectl config set-context tester --cluster="$target" --user=tester >/dev/null
  KUBECONFIG="$tester" kubectl config use-context tester >/dev/null
)

zt72=FAIL faults=FAIL
if KUBECONFIG="$tester" BDD_MODE=cluster BDD_CLUSTER_KIND="$kind" BDD_TARGET="$target" BDD_RUN_ID="$run" BDD_ADM_FIXTURES="$FIXTURES" \
  GODOG_CUCUMBER_OUT="$out/zt-072.cucumber.json" go test ./internal/bdd -count=1 -args -godog.tags=@ZT-72 > "$out/zt-072.log" 2>&1; then
  zt72=PASS
fi
# A passed row must leave its record; a failed one is copied as far as it got.
if ! cp -R "bundles/bdd/evidence/bdd-zt-072/$target" "$out/zt-072" 2>/dev/null && [ "$zt72" = PASS ]; then
  zt72="FAIL (record missing)"
fi
if TESTER_KUBECONFIG="$tester" CLUSTER_KIND="$kind" EVIDENCE="$out/faults" scripts/admission/fault-injection.sh > "$out/faults.out" 2>&1; then
  faults=PASS
fi

{
  echo "# Admission evidence pack: $target"
  echo
  echo "| | |"
  echo "|---|---|"
  echo "| Run | \`$run\` |"
  echo "| Commit | \`$(git rev-parse HEAD)\` |"
  echo "| Cluster (\`kube-system\` UID) | \`$cluster_uid\` |"
  echo "| Cluster kind | $kind |"
  echo "| Provider image | \`$PROVIDER_IMAGE\` |"
  echo "| Trusted key | \`$TRUST_KEY\` (interim key, not the client trust chain) |"
  echo
  echo "| Part | Result | Record |"
  echo "|---|---|---|"
  echo "| ZT-72 secure pod startup | **$zt72** | \`zt-072/\`, \`zt-072.log\`, \`zt-072.cucumber.json\` |"
  echo "| Fault cases | **$faults** | \`faults/fault-injection.log\`, \`faults.out\` |"
  echo
  echo "## Fault cases"
  echo
  grep -E '^(PASS|FAIL)  ' "$out/faults/fault-injection.log" 2>/dev/null | sed 's/^/- /' || echo "- no fault-case record"
} > "$out/index.md"
cp "$FIXTURES" "$out/fixtures.txt"
echo "$out/index.md"
[ "$zt72" = PASS ] && [ "$faults" = PASS ]
