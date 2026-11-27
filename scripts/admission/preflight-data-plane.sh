#!/usr/bin/env bash
# Read-only preflight before a namespace is put under admission control (the umbrella's
# admission.enforceDataPlane labels the data-plane namespace facis.ztd/admission-proof=true). Lists
# every image of the namespace's Pods and of the pod templates of its Deployments, ReplicaSets,
# StatefulSets, DaemonSets, ReplicationControllers, Jobs and CronJobs - containers, init containers and ephemeral containers -
# and classifies each one as the image policy would see it:
#
#   trusted-repository  a digest reference from a repository both the provider and the
#                       ztd-allowed-repositories constraint allow (each with its own prefix rule):
#                       admitted if the provider then verifies its signature and attestations (not
#                       checked here)
#   allow-listed        an exact reference on both allow-lists: admitted without further checks
#   DENIED <code>       ADM-NOT-DIGEST (tag, no registry host) or ADM-REGISTRY-DENIED
#
#   scripts/admission/preflight-data-plane.sh <namespace>
#
# The allowed repositories and the allow-list are read from the provider's trust policy (ConfigMap
# ztd-admission-provider-trust in TRUST_NAMESPACE, default gatekeeper-system) and from the
# ztd-allowed-repositories constraint, and an image passes only if both would admit it; allow-lists
# that differ are reported as policy drift, a failure. Or both are given as REPOSITORIES and
# ALLOWED_DIGESTS (space-separated; both set, nothing is read from the cluster).
# kubectl get only. Exits 1 if any image would be denied or the allow-lists drift, 2 on a usage or
# read error.
set -euo pipefail

ns=${1:?usage: preflight-data-plane.sh <namespace>}
if [ -n "${REPOSITORIES:-}" ] && [ -n "${ALLOWED_DIGESTS+set}" ]; then
  p_repos=$REPOSITORIES p_allowed=$ALLOWED_DIGESTS c_repos=$REPOSITORIES c_allowed=$ALLOWED_DIGESTS
else
  policy=$(kubectl -n "${TRUST_NAMESPACE:-gatekeeper-system}" get configmap ztd-admission-provider-trust -o jsonpath='{.data.policy\.json}') ||
    { echo "cannot read the provider trust policy; set REPOSITORIES and ALLOWED_DIGESTS" >&2; exit 2; }
  constraint=$(kubectl get k8sztdallowedrepositories ztd-allowed-repositories -o json) ||
    { echo "cannot read the ztd-allowed-repositories constraint; set REPOSITORIES and ALLOWED_DIGESTS" >&2; exit 2; }
  p_repos=$(jq -r '.repositories[]?' <<<"$policy") p_allowed=$(jq -r '.allowedDigests[]?' <<<"$policy")
  c_repos=$(jq -r '.spec.parameters.repositories[]?' <<<"$constraint") c_allowed=$(jq -r '.spec.parameters.allowedDigests[]?' <<<"$constraint")
fi
[ -n "$p_repos" ] && [ -n "$c_repos" ] || { echo "no allowed repository" >&2; exit 2; }
norm() { tr ' ' '\n' <<<"$1" | sed '/^$/d' | sort -u | paste -sd' ' -; }
drift=0
if [ "$(norm "$p_allowed")" != "$(norm "$c_allowed")" ]; then
  drift=1
  echo "POLICY DRIFT  allowedDigests differ: provider [$(norm "$p_allowed")], constraint [$(norm "$c_allowed")]"
fi

# image <TAB> kind/name/container, one line per container of every pod spec in the namespace.
uses=$(kubectl -n "$ns" get pods,deployments,replicasets,statefulsets,daemonsets,replicationcontrollers,jobs,cronjobs -o json | jq -r '
  .items[] | . as $o
  | (if .kind == "Pod" then .spec elif .kind == "CronJob" then .spec.jobTemplate.spec.template.spec else .spec.template.spec end) as $s
  | ("containers", "initContainers", "ephemeralContainers") as $f
  | ($s[$f] // [])[] | [.image, "\($o.kind)/\($o.metadata.name)/\(.name)"] | @tsv') ||
  { echo "cannot list the workloads of namespace $ns" >&2; exit 2; }

# The same digest reference rule as the ztd-image-digest constraint.
digest_ref='^(localhost(:[0-9]+)?|[a-z0-9-]+(\.[a-z0-9-]+)+(:[0-9]+)?|[a-z0-9-]+:[0-9]+)/[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*@sha256:[a-f0-9]{64}$'
listed() { # image list...
  local x=$1 r
  shift
  for r in "$@"; do [ "$x" = "$r" ] && return 0; done
  return 1
}
# The provider's rule (internal/cosignverify): the name equals the prefix as written, or continues
# the prefix without its trailing "/" with "/".
provider_repo() { # name
  local r
  for r in $p_repos; do
    [ "$1" = "$r" ] && return 0
    case "$1" in "${r%/}"/*) return 0 ;; esac
  done
  return 1
}
# The constraint's rule (templates/allowed-repositories.yaml): the name equals the prefix without
# its trailing "/", or continues it with "/".
constraint_repo() { # name
  local r
  for r in $c_repos; do
    case "$1" in "${r%/}" | "${r%/}"/*) return 0 ;; esac
  done
  return 1
}
classify() { # image
  local a b
  [[ "$1" =~ $digest_ref ]] || { echo "DENIED ADM-NOT-DIGEST"; return; }
  # shellcheck disable=SC2086 # the lists are whitespace-separated references
  if listed "$1" $p_allowed; then a=1; else a=0; fi
  # shellcheck disable=SC2086
  if listed "$1" $c_allowed; then b=1; else b=0; fi
  [ "$a$b" = 11 ] && { echo allow-listed; return; }
  if [ "$a$b" = 00 ] && provider_repo "${1%@*}" && constraint_repo "${1%@*}"; then echo trusted-repository; return; fi
  echo "DENIED ADM-REGISTRY-DENIED"
}

denied=0 total=0
while IFS=$'\t' read -r image where; do
  [ -n "$image" ] || continue
  class=$(classify "$image")
  total=$((total + 1))
  case "$class" in DENIED*) denied=$((denied + 1)) ;; esac
  printf '%-30s %s  (%s)\n' "$class" "$image" "$where"
done < <(sort -u <<<"$uses")
echo "$total image use(s) in $ns, $denied would be denied"
[ "$denied" -eq 0 ] && [ "$drift" -eq 0 ]
