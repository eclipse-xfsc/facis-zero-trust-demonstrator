#!/usr/bin/env bash
# Proofs of the guard's policy hook on Envoy: ext_authz as the hook, ext_proc as the config-only
# alternative. Runs cmd/policy-hook-probe against Envoy from the image pinned in
# scripts/tools/pins.env — the echo upstream, the hook and the probe as plain processes, Envoy as
# one container — then checks the records it wrote and leaves verdict.txt and environment.json
# beside them. The five proofs: header mutation on allow, the deny response, filter parity,
# latency, and failing closed when the hook dies or stops answering. Nothing is committed: the
# records are a run's output, and the pull-request workflow uploads its own as an artefact.
#
# Usage: verify.sh [--out DIR] [--verify DIR]
#   --out DIR      write the records to DIR (default: .dev/policy-hook-evidence, which git ignores)
#   --verify DIR   run nothing: check the records already in DIR and print the verdict
#
# Environment:
#   POLICY_HOOK_HOST_KIND    what the run is recorded as: local (default) or ci (default on GitHub Actions)
#   POLICY_HOOK_ENVOY_IMAGE  use this image instead of ENVOY_IMAGE from scripts/tools/pins.env
#   POLICY_HOOK_PROBE_ARGS   extra arguments for the probe, for example "--requests 500"
#
# Needs go, git, jq, docker and bash 5.
set -euo pipefail

DEFAULT_OUT=.dev/policy-hook-evidence

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
out=$root/$DEFAULT_OUT
verify_only=
work=
image=
checks_failed=0
verdict_lines=()

say() { printf '%s\n' "$*"; }
die() {
	printf 'verify.sh: %s\n' "$*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case $1 in
	--out)
		[ $# -ge 2 ] || die "--out needs a directory"
		mkdir -p "$2"
		out=$(cd "$2" && pwd)
		shift 2
		;;
	--verify)
		[ $# -ge 2 ] || die "--verify needs a directory"
		[ -d "$2" ] || die "--verify: $2 is not a directory"
		verify_only=1
		out=$(cd "$2" && pwd)
		shift 2
		;;
	-h | --help)
		sed -n '2,/^set -euo/p' "$0" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown argument: $1 (try --help)" ;;
	esac
done

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	[ -z "$work" ] || rm -rf "$work"
	exit "$status"
}

# --- running --------------------------------------------------------------------------------

run_proofs() {
	local tool commit dirty kind digest
	for tool in go git jq docker; do
		command -v "$tool" >/dev/null || die "$tool is required"
	done
	[ "${BASH_VERSINFO[0]}" -ge 5 ] || die "bash 5 or newer is required"
	cd "$root"
	# shellcheck source=scripts/tools/pins.env
	source "$root/scripts/tools/pins.env"
	image=${POLICY_HOOK_ENVOY_IMAGE:-${ENVOY_IMAGE:?ENVOY_IMAGE is not pinned in scripts/tools/pins.env}}

	work=$(mktemp -d "${TMPDIR:-/tmp}/policy-hook.XXXXXX")
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	say "building the probe"
	go build -o "$work/policy-hook-probe" ./cmd/policy-hook-probe
	if ! docker image inspect "$image" >/dev/null 2>&1; then
		say "pulling $image"
		docker pull "$image" >/dev/null
	fi

	# The output folder is emptied except for its README; a folder holding anything else without an
	# environment.json is not evidence of an earlier run and is left alone, so a mistyped --out
	# cannot delete anything else.
	if [ -d "$out" ] && [ ! -f "$out/environment.json" ] && [ -n "$(find "$out" -mindepth 1 ! -name README.md -print -quit)" ]; then
		die "$out is not empty and holds no environment.json; refusing to replace it"
	fi
	mkdir -p "$out"
	find "$out" -mindepth 1 ! -name README.md -delete

	commit=$(git rev-parse HEAD)
	if [ -z "$(git status --porcelain)" ]; then dirty=false; else dirty=true; fi
	kind=${POLICY_HOOK_HOST_KIND:-}
	if [ -z "$kind" ]; then
		if [ "${GITHUB_ACTIONS:-}" = true ]; then kind=ci; else kind=local; fi
	fi
	digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "$image")
	jq -n \
		--arg commit "$commit" --argjson dirty "$dirty" --arg go "$(go env GOVERSION)" \
		--arg envoy_image "$image" --arg envoy_digest "$digest" \
		--arg envoy_api "$(go list -m -f '{{.Version}}' github.com/envoyproxy/go-control-plane/envoy)" \
		--arg grpc "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" \
		--arg docker "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)" \
		--arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg kind "$kind" --arg os "$(uname -sr)" --arg arch "$(uname -m)" \
		'{script: "scripts/verify-policy-hook/verify.sh", commit: $commit, dirty: $dirty, go_version: $go,
		  envoy_image: $envoy_image, envoy_digest: $envoy_digest, envoy_api_module: $envoy_api, grpc_module: $grpc,
		  docker_version: $docker, date: $date, host_kind: $kind, os: $os, arch: $arch}' \
		>"$out/environment.json"

	say "running the proofs against $image"
	# shellcheck disable=SC2086
	"$work/policy-hook-probe" prove all --out "$out" --envoy-image "$image" \
		--fixtures docs/contracts/fixtures --templates scripts/verify-policy-hook/envoy ${POLICY_HOOK_PROBE_ARGS:-}
}

# --- verdict --------------------------------------------------------------------------------

# check DESCRIPTION COMMAND...: run one check, record PASS or FAIL.
check() {
	local what=$1
	shift
	if "$@"; then
		verdict_lines+=("PASS  $what")
	else
		verdict_lines+=("FAIL  $what")
		checks_failed=$((checks_failed + 1))
	fi
}

# expect FILE JQ-CONDITION: true when the record satisfies the condition.
expect() { [ -f "$1" ] && jq -e "$2" "$1" >/dev/null 2>&1; }

# field FILE JQ-EXPRESSION: the value, or the empty string when the file or the value is missing.
field() {
	[ -f "$1" ] || return 0
	jq -r "($2) // empty" "$1" 2>/dev/null || true
}

section() { verdict_lines+=("" "## $1"); }

verdict() {
	local f mode

	section "On allow, header mutation substitutes the upstream credential"
	f=$out/upstream-seen.json
	check "the request was forwarded and answered by the upstream" \
		expect "$f" '.status == 200 and .upstream != null'
	check "the upstream received the token store's Authorization value and proof, not the caller's" \
		expect "$f" '.upstream.headers.Authorization[0] == .expected.authorization and .upstream.headers.Dpop[0] == .expected.dpop
			and .upstream.headers.Authorization[0] != .request_sent.Authorization[0] and .upstream.headers.Dpop[0] != .request_sent.DPoP[0]'
	check "no x-facis-* header and no forwarding header of the caller reached the upstream" \
		expect "$f" '([.upstream.headers | keys[] | ascii_downcase | select(startswith("x-facis-"))] | length) == 0
			and (.upstream.headers | (has("X-Forwarded-For") or has("X-Forwarded-Host") or has("X-Forwarded-Proto") or has("Forwarded")) | not)'
	check "the trace context was propagated unchanged" \
		expect "$f" '.upstream.headers.Traceparent[0] == .request_sent.Traceparent[0]'
	check "the caller's request id was replaced by one the guard generated, which the decision event carries as its correlation id" \
		expect "$f" '(.upstream.headers["X-Request-Id"][0] | length) > 0 and .upstream.headers["X-Request-Id"][0] != .request_sent["X-Request-Id"][0]
			and .decision_event.kind == "decision" and .decision_event.payload.state == "allowed"
			and .decision_event.correlation_id == .upstream.headers["X-Request-Id"][0]'
	check "the probe's own checks all passed" expect "$f" '.checks | all'

	section "On deny, the response carries status, headers and the OID4VP link in the body"
	f=$out/responses.json
	check "both refusal cases were sent and answered with the status the reason-code registry gives their code" \
		expect "$f" '(.cases | map(.case)) == ["rule-deny", "presentation-required"]
			and all(.cases[]; .status == .expected_status and .status == (if .decision.reason_code == "POL-RULE-DENY" then 403 else 401 end))'
	check "every answer is JSON, names its reason code in x-facis-reason-code and carries a request id" \
		expect "$f" 'all(.cases[]; .content_type == "application/json" and .reason_header == .decision.reason_code and (.request_id | length) > 0)'
	check "every body carries the fixture's error and reason code; the rule denial its rule, the presentation-required denial the OID4VP link" \
		expect "$f" 'all(.cases[]; .body.error == .decision.deny_body.error and .body.reason_code == .decision.reason_code)
			and (.cases[] | select(.case == "rule-deny") | (.body.rule_id | length) > 0 and (.body.oid4vp_link // "") == "")
			and (.cases[] | select(.case == "presentation-required") | .body.oid4vp_link == .decision.deny_body.oid4vp_link and (.body.oid4vp_link | startswith("https://")))'
	check "the probe's own checks all passed" expect "$f" 'all(.cases[]; .checks | all)'

	section "The same input set over ext_proc produces identical decisions; the switch is a config change"
	check "the three cases were sent through both filters and decided as the fixtures say: 200 with substitution, 403, 401" \
		expect "$out/parity.json" '.cases == 3' &&
		expect "$out/decisions-ext-authz.json" '[.[] | .status] == [200, 403, 401] and .[0].upstream_headers.authorization == "DPoP fx-upstream-token"
			and .[1].body.reason_code == "POL-RULE-DENY" and .[2].body.reason_code == "POL-PRESENTATION-REQUIRED"' &&
		expect "$out/decisions-ext-proc.json" 'length == 3'
	check "status, headers, body and what the upstream received are identical under both filters" \
		expect "$out/parity.json" '.decisions_identical and .decisions_diff == ""'
	check "the two bootstraps are identical outside the filter block, and the diff records the block" \
		expect "$out/parity.json" '.configs_identical_outside_filter' &&
		grep -q 'envoy.filters.http.ext_authz' "$out/envoy-ext-authz.yaml" &&
		grep -q 'envoy.filters.http.ext_proc' "$out/envoy-ext-proc.yaml" && [ -s "$out/filter-switch.diff" ]

	section "The hook's added latency, measured"
	f=$out/latency.json
	check "all three bootstraps were measured at every concurrency, with no error and only 200 answers" \
		expect "$f" '([.runs[].filter] | unique) == ["baseline", "ext-authz", "ext-proc"]
			and ([.runs[] | select(.filter == "baseline")] | length) * 3 == (.runs | length)
			and .all_ok and all(.runs[]; .errors == 0 and (.statuses | keys) == ["200"] and .statuses["200"] == .requests)'
	check "the added latency of both hooks is recorded per concurrency" \
		expect "$f" '(.added | length) == ([.runs[] | select(.filter != "baseline")] | length) and all(.added[]; has("p99_ms"))'

	section "The hook fails closed and never hangs"
	for mode in killed frozen; do
		f=$out/$mode.json
		check "$mode: every request in the window ended; every one started after the strike was refused with 503 and POL-PDP-UNAVAILABLE; none outlived the timeout plus the margin" \
			expect "$f" '.all_completed and .errors == 0 and .sent == .completed and .sent > 0 and .after_strike > 0
				and .all_after_strike_refused and .after_strike_unavailable == .after_strike and (.anomalies | length) == 0
				and .all_within_bound and .max_duration_ms <= .timeout_ms + .margin_ms'
	done
	check "killed: a reset hook is refused at once, well inside the timeout" \
		expect "$out/killed.json" '.after_strike_median_ms < .timeout_ms'
	check "frozen: a hook that stops answering is refused by the timeout, not before it" \
		expect "$out/frozen.json" '.after_strike_median_ms >= .timeout_ms * 0.8 and .after_strike_median_ms <= .timeout_ms + .margin_ms'
	check "the hook recovers once restarted, with no manual step, after both strikes, and stays recovered" \
		expect "$out/recovery.json" '.after_kill.recovered and .after_freeze.recovered
			and .after_kill.first_success_after_ms < 5000 and .after_freeze.first_success_after_ms < 5000
			and ([.after_kill.after_recovery_statuses, .after_freeze.after_recovery_statuses | to_entries[] | select(.key != "200")] | length) == 0'
}

notes() {
	jq -r '.runs[] | "\(.filter), concurrency \(.concurrency): p50 \(.p50_ms) ms, p95 \(.p95_ms) ms, p99 \(.p99_ms) ms, max \(.max_ms) ms (\(.requests) requests)"' "$out/latency.json" 2>/dev/null || true
	jq -r '.added[] | "added by \(.filter), concurrency \(.concurrency): p50 \(.p50_ms) ms, p95 \(.p95_ms) ms, p99 \(.p99_ms) ms"' "$out/latency.json" 2>/dev/null || true
	say "killed: $(field "$out/killed.json" '"\(.after_strike) requests after the strike, all 503; median \(.after_strike_median_ms) ms, longest \(.max_duration_ms) ms; timeout \(.timeout_ms) ms"')"
	say "frozen: $(field "$out/frozen.json" '"\(.after_strike) requests after the strike, all 503; shortest \(.after_strike_min_ms) ms, median \(.after_strike_median_ms) ms, longest \(.max_duration_ms) ms"')"
	say "recovery: $(field "$out/recovery.json" '"first success \(.after_kill.first_success_after_ms) ms after the restart that followed the kill, \(.after_freeze.first_success_after_ms) ms after the one that followed the freeze"')"
}

[ -n "$verify_only" ] || run_proofs
verdict
result=PASS
[ "$checks_failed" -eq 0 ] || result=FAIL
text=$(
	say "Guard policy hook on Envoy: ext_authz as the hook, ext_proc as the config-only alternative"
	for line in "${verdict_lines[@]}"; do say "$line"; done
	say
	say "## Numbers"
	notes | sed 's/^/NOTE  /'
	say
	say "verdict: $result"
)
say "$text"
if [ -z "$verify_only" ]; then
	say "$text" >"$out/verdict.txt"
	say "records written to $out"
fi
[ "$result" = PASS ]
