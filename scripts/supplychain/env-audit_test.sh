#!/usr/bin/env bash
# Cases for env-audit.sh's decision: a probe job refused by the environment before any step ran is
# "refused"; one that ran a step is "admitted"; anything else - waiting for a reviewer, failed for
# another reason, never found - is "inconclusive". And an allowlisted ref cannot be the probe.
#
#   scripts/supplychain/env-audit_test.sh
set -euo pipefail
# shellcheck source=scripts/supplychain/env-audit.sh disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env-audit.sh"
failures=0
want() { # name expected job notes
  local got; got="$(verdict "$3" "$4")"
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1 (got $got, want $2)"; failures=$((failures + 1)); fi
}
refusal='Branch "audit/env-probe-1" is not allowed to deploy to release due to environment protection rules.'
want "refused before any step" refused '{"status":"completed","conclusion":"failure","steps":[]}' "$refusal"
want "a step ran: admitted" admitted \
  '{"status":"completed","conclusion":"success","steps":[{"name":"Set up job","conclusion":"success"}]}' ""
want "failed without the environment's refusal: inconclusive" inconclusive '{"status":"completed","conclusion":"failure","steps":[]}' "runner lost"
want "waiting for a reviewer: inconclusive" inconclusive '{"status":"waiting","conclusion":null,"steps":[]}' ""
want "no probe job found: inconclusive" inconclusive '{}' ""
for ref in main candidate/x v1.2.3; do
  if allowlisted "$ref"; then echo "ok    $ref is allowlisted, so not a probe"; else echo "FAIL  $ref"; failures=$((failures + 1)); fi
done
if allowlisted audit/env-probe-1; then echo "FAIL  the disposable branch is allowlisted"; failures=$((failures + 1)); else echo "ok    the disposable branch is outside the allowlist"; fi
# probe_notes and delete_ref against a gh stub that answers by path and records each call.
calls="$(mktemp)"
trap 'rm -f "$calls"' EXIT
gh() {
  echo "$*" >> "$calls"
  case "$*" in
    "api repos/o/r/check-runs/555/annotations --jq .[].message") echo "$refusal" ;;
    *"/check-runs/"*) echo "gh: Not Found (HTTP 404)" >&2; return 1 ;;
    "api -X DELETE repos/o/r/git/refs/heads/"*)
      [ "${STUB_DELETE:-ok}" = ok ] && return 0
      [ "$STUB_DELETE" = second ] && [ "$(grep -c DELETE "$calls")" -ge 2 ] && return 0
      echo "gh: Server Error (HTTP 500)" >&2; return 1 ;;
    "api repos/o/r/git/ref/heads/"*)
      [ "${STUB_GET:-}" = gone ] && { echo "gh: Not Found (HTTP 404)" >&2; return 1; }
      echo '{"ref":"x"}' ;;
  esac
}
export RETRY_DELAY=0
job='{"id":111,"check_run_url":"https://api.github.com/repos/o/r/check-runs/555","status":"completed","conclusion":"failure","steps":[]}'
if [ "$(probe_notes o/r "$job")" = "$refusal" ] && ! grep -q check-runs/111 "$calls"; then echo "ok    the annotations come from check_run_url, not the job id"
else echo "FAIL  the annotations come from check_run_url, not the job id"; failures=$((failures + 1)); fi
if probe_notes o/r '{"id":111,"check_run_url":"https://api.github.com/repos/o/r/check-runs/999"}' >/dev/null 2>&1; then
  echo "FAIL  an annotation read that fails is not surfaced"; failures=$((failures + 1))
else echo "ok    an annotation read that fails is surfaced"; fi
cleanup() { # name expect(ok|fail) env...
  local name=$1 want=$2 got=fail; shift 2
  : > "$calls"
  # shellcheck disable=SC2163 # NAME=value pairs
  if (export "$@"; delete_ref o/r audit/env-probe-1-1) 2>/dev/null; then got=ok; fi
  if [ "$got" = "$want" ]; then echo "ok    $name"; else echo "FAIL  $name (got $got)"; failures=$((failures + 1)); fi
}
cleanup "the probe branch is deleted" ok STUB_DELETE=ok
cleanup "a delete that fails once is retried" ok STUB_DELETE=second
cleanup "a branch already gone counts as deleted" ok STUB_DELETE=fail STUB_GET=gone
cleanup "a branch that cannot be deleted fails" fail STUB_DELETE=fail

probe_job=$job
# main end to end, with the stub answering the run and the refused probe: the verdict passes only when
# the owned branch is also deleted.
gh() {
  echo "$*" >> "$calls"
  case "$*" in
    "api -X POST repos/o/r/git/refs "*|"workflow run "*) ;;
    *"/actions/workflows/"*) echo 4242 ;;
    "api repos/o/r/actions/runs/4242/jobs "*) echo "$probe_job" ;; # main has a local of its own named job
    "api repos/o/r/check-runs/555/annotations "*) echo "$refusal" ;;
    "api -X DELETE "*) [ "${STUB_DELETE:-ok}" = ok ] || { echo "gh: Server Error (HTTP 500)" >&2; return 1; } ;;
    "api repos/o/r/git/ref/heads/"*) echo '{"ref":"x"}' ;;
    *) echo "unexpected: $*" >&2; return 1 ;;
  esac
}
audit() { # expect(ok|fail) env...
  local want=$1 got=fail; shift
  : > "$calls"
  # shellcheck disable=SC2163 # NAME=value pairs
  if (export "$@" GITHUB_REPOSITORY=o/r GITHUB_RUN_ID=9 GITHUB_RUN_ATTEMPT=2 GITHUB_SHA=abc POLL_DELAY=0; main "$(mktemp -d)") >/dev/null 2>&1; then got=ok; fi
  [ "$got" = "$want" ]
}
if audit ok && grep -q "refs/heads/audit/env-probe-9-2" "$calls" && grep -q "DELETE repos/o/r/git/refs/heads/audit/env-probe-9-2" "$calls"; then
  echo "ok    a refused probe from an owned branch passes and the branch is deleted"
else echo "FAIL  a refused probe from an owned branch passes and the branch is deleted"; failures=$((failures + 1)); fi
if audit fail STUB_DELETE=fail; then echo "ok    a probe branch left behind fails the audit"
else echo "FAIL  a probe branch left behind fails the audit"; failures=$((failures + 1)); fi

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
