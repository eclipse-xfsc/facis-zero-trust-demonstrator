#!/usr/bin/env bash
# Exit 0 when a constraint is enforced by every serving Gatekeeper webhook replica: for each Ready pod
# of the webhook Deployment there is a status.byPod entry with that pod's id, the webhook operation,
# enforced true, no errors, the constraint's current UID and an observedGeneration equal to its
# metadata.generation. A missing, stale or erroring acknowledgement - or no Ready replica at all -
# fails. The audit pod is not a webhook replica and never counts.
#
#   scripts/admission/enforced.sh <constraint.json> <webhook-pods.json>
#   (kubectl get <kind> <name> -o json; kubectl -n gatekeeper-system get pods -l control-plane=controller-manager -o json)
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <constraint.json> <webhook-pods.json>" >&2; exit 2; }
jq -e --slurpfile pods "$2" '
  [$pods[0].items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.name] as $ready
  | .metadata.generation as $generation | .metadata.uid as $uid | (.status.byPod // []) as $acks
  | ($ready | length) > 0 and all($ready[]; . as $pod | any($acks[];
      .id == $pod and .enforced == true and .observedGeneration == $generation and .constraintUID == $uid
      and ((.errors // []) | length) == 0 and ((.operations // []) | index("webhook")) != null))
' "$1" >/dev/null
