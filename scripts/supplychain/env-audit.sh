#!/usr/bin/env bash
# The audit of the release environment's allowlist (ZT-10): a run from a ref the environment must not
# admit is started, and its probe job - which names the release environment and holds no secret - must
# have been refused by the environment before any step ran. Run by the Environment audit job of
# signing-environment-audit.yml, by hand only.
#
#   1. the probe ref: PROBE_REF if given, else a branch this run owns, audit/env-probe-<run id>-<attempt>,
#      created at this commit and deleted at the end - the cleanup is armed before the branch is
#      created, retried, and a branch it cannot delete fails the audit; a ref the allowlist admits is
#      refused as a probe;
#   2. signing-environment-audit.yml dispatched on it with mode=probe, the run found and waited for;
#   3. the verdict from the probe job and the annotations of its check run (check_run_url): refused (no
#      step ran, the job failed and GitHub says the ref is not allowed to deploy), admitted (a step
#      ran), or inconclusive. Annotations that cannot be read fail the audit.
#
# Writes <out>/env-audit.json and exits 0 only for "refused".
#
#   GH_TOKEN=... GITHUB_REPOSITORY=... GITHUB_RUN_ID=... GITHUB_SHA=... [PROBE_REF=...] \
#     scripts/supplychain/env-audit.sh <out dir>
#
# The decision is a function, sourced by env-audit_test.sh.
set -euo pipefail

WORKFLOW=signing-environment-audit.yml
PROBE_JOB="Environment probe"

# verdict <probe job JSON> <annotation messages>  -> refused|admitted|inconclusive
verdict() {
  local job=$1 notes=$2
  if [ "$(jq -r '[.steps[]? | select(.conclusion != null and .conclusion != "skipped")] | length' <<<"$job")" != 0 ]; then
    echo admitted
  elif [ "$(jq -r '.status + "/" + (.conclusion // "")' <<<"$job")" = completed/failure ] \
    && grep -qiE 'not allowed to deploy to release|environment protection rules' <<<"$notes"; then
    echo refused
  else
    echo inconclusive
  fi
}

# probe_notes <repo> <probe job JSON>  -> the annotation messages of the job's check run; fails if they
# cannot be read. The check run is the one check_run_url names, not the job id.
probe_notes() {
  local url
  url="$(jq -r '.check_run_url // empty' <<<"$2")"
  [ -n "$url" ] || return 0
  gh api "repos/$1/check-runs/${url##*/}/annotations" --jq '.[].message'
}

# delete_ref <repo> <branch>  -> succeeds once the branch is gone (deleted now, or already absent);
# retried, since a branch left behind is a failure of the audit
delete_ref() {
  local attempt out
  for attempt in 1 2 3; do
    gh api -X DELETE "repos/$1/git/refs/heads/$2" >/dev/null 2>&1 && return 0
    if ! out="$(gh api "repos/$1/git/ref/heads/$2" 2>&1)" && grep -q 'HTTP 404' <<<"$out"; then return 0; fi
    [ "$attempt" = 3 ] || sleep "${RETRY_DELAY:-5}"
  done
  return 1
}

# allowlisted <ref>  -> succeeds for a ref the release environment is meant to admit
allowlisted() { case "$1" in main|candidate/*|v*) return 0 ;; *) return 1 ;; esac; }

main() {
  [ $# -eq 1 ] || { echo "usage: $0 <out dir>" >&2; exit 2; }
  local out=$1 repo=$GITHUB_REPOSITORY ref=${PROBE_REF:-} since run="" job="{}" notes="" result errors=()
  mkdir -p "$out"
  if [ -z "$ref" ]; then
    ref="audit/env-probe-$GITHUB_RUN_ID-${GITHUB_RUN_ATTEMPT:-1}"
    OWNED_REPO=$repo OWNED_REF=$ref
    # shellcheck disable=SC2154 # rc is set inside the trap
    trap 'rc=$?; if ! delete_ref "$OWNED_REPO" "$OWNED_REF"; then echo "::error::could not delete the probe branch $OWNED_REF - delete it by hand" >&2; rc=1; fi; exit "$rc"' EXIT
    gh api -X POST "repos/$repo/git/refs" -f ref="refs/heads/$ref" -f sha="$GITHUB_SHA" >/dev/null
  fi
  if allowlisted "$ref"; then
    echo "::error::$ref is on the release environment's allowlist; the probe needs a ref outside it" >&2
    exit 1
  fi

  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  gh workflow run "$WORKFLOW" --repo "$repo" --ref "$ref" -f mode=probe
  for _ in $(seq 60); do
    sleep "${POLL_DELAY:-10}"
    run="$(gh api -X GET "repos/$repo/actions/workflows/$WORKFLOW/runs" -f branch="$ref" -f event=workflow_dispatch \
      -f created=">=$since" --jq '.workflow_runs[0] | select(.status == "completed") | .id')"
    [ -z "$run" ] || break
  done
  if [ -n "$run" ]; then
    job="$(gh api "repos/$repo/actions/runs/$run/jobs" --jq "[.jobs[] | select(.name == \"$PROBE_JOB\")][0] // {}")"
    notes="$(probe_notes "$repo" "$job")" || errors+=("the probe job's annotations could not be read")
  else
    errors+=("no completed probe run found")
  fi
  result="$(verdict "$job" "$notes")"
  [ ${#errors[@]} -eq 0 ] || result=inconclusive
  jq -n --arg ref "$ref" --arg run "$run" --arg result "$result" --argjson job "$job" \
    --argjson errors "$(printf '%s\n' "${errors[@]}" | jq -R . | jq -sc 'map(select(. != ""))')" \
    --arg allowed "main, candidate/*, v*" \
    '{probeRef: $ref, probeRun: (if $run == "" then null else ($run | tonumber) end), allowlist: $allowed,
      probeJob: {conclusion: $job.conclusion, stepsRun: ([$job.steps[]? | select(.conclusion != null and .conclusion != "skipped")] | length)},
      errors: $errors, result: $result}' > "$out/env-audit.json"
  echo "environment audit: probe from $ref, run ${run:-none}: $result"
  [ ${#errors[@]} -eq 0 ] || printf '  error: %s\n' "${errors[@]}"
  [ "$result" = refused ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
