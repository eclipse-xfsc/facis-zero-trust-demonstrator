#!/usr/bin/env bash
# Helm post-renderer for the Gatekeeper chart: restricts both of its validating webhooks to namespaces
# labelled facis.ztd/admission-proof=true - the policy webhook (validation.gatekeeper.sh) and the one
# guarding the admission.gatekeeper.sh/ignore label on namespaces (check-ignore-label.gatekeeper.sh) -
# so Gatekeeper decides nothing outside the admission namespaces. The chart's namespaceSelector values
# can only exclude namespaces; this adds the positive selector next to the chart's own expressions. It
# fails unless it changed exactly those two webhooks, so a chart change cannot silently widen the scope.
set -euo pipefail
awk '
  /^  name: (validation|check-ignore-label)\.gatekeeper\.sh$/ { webhook = 1 }
  /^- admissionReviewVersions:/ { webhook = 0 }
  { print }
  webhook && /^ *matchExpressions:$/ {
    match($0, /^ */); indent = substr($0, 1, RLENGTH)
    print indent "- key: facis.ztd/admission-proof"
    print indent "  operator: In"
    print indent "  values:"
    print indent "  - \"true\""
    webhook = 0; done++
  }
  END {
    if (done != 2) { print "ztd-webhook-scope: expected 2 webhook namespaceSelectors, scoped " done > "/dev/stderr"; exit 1 }
  }
'
