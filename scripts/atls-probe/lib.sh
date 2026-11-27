# shellcheck shell=bash
# Shared by prove-mutual-handshake.sh, prove-tampered-binding.sh and prove-session-loss.sh. Source it; do not run it.
#
# It builds cmcd (the CMC version pinned in go.mod) and the probe, generates the two zones'
# fixtures, runs one cmcd per zone as a plain process, and collects records, logs, the verdict
# and the environment into the output folder. Everything it starts is stopped again on exit.
#
# A run writes its full output (records, logs, cmcd configurations, verdict, environment) to
# --out DIR, by default the git-ignored .dev/atls-evidence/. The repository keeps only the summary
# of a run under docs/evidences/cmc-atls-channel-binding/: verdict.txt and environment.json per
# proof, plus reconnect-findings.md for the session-loss proof. --summary writes those files.
#
# Environment:
#   ATLS_HOST_KIND   what the run is recorded as: local (default), ci (default on GitHub
#                    Actions) or target-cluster
#   ATLS_CMCD_BIN    use this cmcd binary instead of building one
#   ATLS_KEEP_WORK   when set, keep the temporary work directory (keys included) for inspection

set -euo pipefail

CMC_MODULE=github.com/Fraunhofer-AISEC/cmc
EVIDENCE_ROOT=docs/evidences/cmc-atls-channel-binding
DEFAULT_OUT=.dev/atls-evidence
# What the repository keeps of a run; everything else is the run's full output.
SUMMARY_FILES=(verdict.txt environment.json reconnect-findings.md)
ZONE_A_ID=spiffe://a/gateway
ZONE_B_ID=spiffe://b/gateway

lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(git -C "$lib_dir" rev-parse --show-toplevel)
script=$(basename "$0")

work=
out=
verify_only=
summary_dir=
summary_only=
declare -A pids=()
checks_failed=0

say() { printf '%s\n' "$*"; }
die() {
	printf '%s: %s\n' "$script" "$*" >&2
	exit 1
}

# now_ms: Unix time in milliseconds. EPOCHREALTIME (bash 5) is used because not every date(1)
# prints fractions of a second.
now_ms() {
	local t=${EPOCHREALTIME/[.,]/}
	echo $((t / 1000))
}

# --- arguments ----------------------------------------------------------------------------

# parse_args DEFAULT_FOLDER "$@"
#   --out DIR      write the full output to DIR/DEFAULT_FOLDER (default: .dev/atls-evidence/)
#   --summary      after a passing run, also write the summary files to the proof's folder in
#                  the repository
#   --verify DIR   run no process: check what is already in DIR and print the verdict. A folder
#                  with the records of a run is checked on those records; a folder that holds
#                  only summary files (the committed one) is checked on the recorded verdict.
parse_args() {
	local default=$1
	shift
	out=$root/$DEFAULT_OUT/$default
	local base='' summary=''
	while [ $# -gt 0 ]; do
		case $1 in
		--out)
			[ $# -ge 2 ] || die "--out needs a directory"
			base=$2
			shift 2
			;;
		--summary)
			summary=yes
			shift
			;;
		--verify)
			[ $# -ge 2 ] || die "--verify needs a directory"
			verify_only=$2
			shift 2
			;;
		-h | --help)
			sed -n '2,/^set -euo/p' "$0" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//'
			exit 0
			;;
		*) die "unknown argument: $1 (try --help)" ;;
		esac
	done
	if [ -n "$base" ]; then
		mkdir -p "$base"
		out=$(cd "$base" && pwd)/$default
	fi
	if [ -n "$verify_only" ]; then
		[ -z "$summary" ] || die "--summary writes the summary of a run; it cannot be combined with --verify"
		[ -d "$verify_only" ] || die "--verify: $verify_only is not a directory"
		out=$(cd "$verify_only" && pwd)
		if holds_only_summary "$out"; then summary_only=yes; fi
		return 0
	fi
	# The folder in the repository holds summary files only; a run never writes its records there.
	case $out/ in
	"$root/$EVIDENCE_ROOT"/*) die "--out: $out is the committed evidence folder; use --summary to write the summary files there" ;;
	esac
	if [ -n "$summary" ]; then summary_dir=$root/$EVIDENCE_ROOT/$default; fi
}

# holds_only_summary DIR: true when DIR holds summary files and nothing else.
holds_only_summary() {
	local entry name known f found=
	for entry in "$1"/* "$1"/.[!.]*; do
		[ -e "$entry" ] || continue
		name=$(basename "$entry")
		known=
		for f in "${SUMMARY_FILES[@]}"; do [ "$name" = "$f" ] && known=yes; done
		[ -n "$known" ] && [ -f "$entry" ] || return 1
		found=yes
	done
	[ -n "$found" ]
}

# --- lifecycle ------------------------------------------------------------------------------

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	local name
	for name in "${!pids[@]}"; do
		# A frozen process does not act on SIGTERM; wake it, then kill it outright.
		kill -CONT "${pids[$name]}" 2>/dev/null || true
		kill -KILL "${pids[$name]}" 2>/dev/null || true
	done
	wait 2>/dev/null || true
	if [ -n "$work" ] && [ -z "${ATLS_KEEP_WORK:-}" ]; then
		rm -rf "$work"
	elif [ -n "$work" ]; then
		say "work directory kept: $work"
	fi
	exit "$status"
}

# setup: requirements, temporary directory, clean output folder, binaries, fixtures.
setup() {
	local tool
	for tool in go git jq; do
		command -v "$tool" >/dev/null || die "$tool is required"
	done
	[ -n "${EPOCHREALTIME:-}" ] || die "bash 5 or newer is required"
	cd "$root"

	work=$(mktemp -d "${TMPDIR:-/tmp}/atls-probe.XXXXXX")
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	mkdir -p "$work/bin" "$work/logs" "$work/records"

	prepare_out

	commit=$(git rev-parse HEAD)
	# The evidence folder is what --summary writes; changes there do not make the tree dirty.
	if [ -z "$(git status --porcelain -- . ":!$EVIDENCE_ROOT")" ]; then dirty=false; else dirty=true; fi
	cmc_version=$(go list -m -f '{{.Version}}' "$CMC_MODULE")

	say "building cmcd $cmc_version and the probe"
	if [ -n "${ATLS_CMCD_BIN:-}" ]; then
		cp "$ATLS_CMCD_BIN" "$work/bin/cmcd"
	else
		GOBIN=$work/bin go install "$CMC_MODULE/cmcd@$cmc_version"
	fi
	go build -ldflags "-X main.commit=$commit -X main.dirty=$dirty" -o "$work/bin/atls-probe" ./cmd/atls-probe
	probe=$work/bin/atls-probe

	cmcd_a=127.0.0.1:$(free_port)
	cmcd_b=127.0.0.1:$(free_port)
	fixtures=$work/fixtures
	say "generating fixtures for zones a and b"
	ATLS_FIXTURE_DIR=$fixtures ATLS_FIXTURE_CMCD_A=$cmcd_a ATLS_FIXTURE_CMCD_B=$cmcd_b \
		go test -count=1 -run '^TestWriteFixtures$' ./internal/atls/atlstest/ >"$work/logs/fixtures.log" 2>&1 ||
		{
			cat "$work/logs/fixtures.log" >&2
			die "fixture generation failed"
		}
	[ -f "$fixtures/fixtures.json" ] || die "fixture generation wrote nothing"
	trust=(--ca "$fixtures/zone-a/ca.pem" --ca "$fixtures/zone-b/ca.pem")
	zone_a=(--cmcd "$cmcd_a" --cert "$fixtures/zone-a/cert.pem" --key "$fixtures/zone-a/key.pem" "${trust[@]}" --peer-id "$ZONE_B_ID")
	zone_b=(--cmcd "$cmcd_b" --cert "$fixtures/zone-b/cert.pem" --key "$fixtures/zone-b/key.pem" "${trust[@]}" --peer-id "$ZONE_A_ID")

	write_environment
}

# prepare_out empties the output folder. It refuses a non-empty folder that does not look like
# evidence of an earlier run, so a mistyped --out cannot delete anything else.
prepare_out() {
	if [ -d "$out" ] && [ -n "$(ls -A "$out")" ] && [ ! -f "$out/environment.json" ]; then
		die "$out is not empty and holds no environment.json; refusing to replace it"
	fi
	rm -rf "$out"
	mkdir -p "$out"
}

write_environment() {
	local kind=${ATLS_HOST_KIND:-}
	if [ -z "$kind" ]; then
		if [ "${GITHUB_ACTIONS:-}" = true ]; then kind=ci; else kind=local; fi
	fi
	jq -n \
		--arg script "scripts/atls-probe/$script" \
		--arg commit "$commit" \
		--argjson dirty "$dirty" \
		--arg go "$(go env GOVERSION)" \
		--arg cmc "$cmc_version" \
		--arg cmcd "$(go version -m "$work/bin/cmcd" | awk '$1 == "mod" {print $2 "@" $3}')" \
		--arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		--arg kind "$kind" \
		--arg os "$(uname -sr)" \
		--arg arch "$(uname -m)" \
		'{script: $script, commit: $commit, dirty: $dirty, go_version: $go, cmc_version: $cmc,
		  cmcd_binary: $cmcd, date: $date, host_kind: $kind, os: $os, arch: $arch}' \
		>"$out/environment.json"
}

# --- processes ------------------------------------------------------------------------------

# free_port prints a TCP port on 127.0.0.1 nothing listens on.
free_port() {
	local port
	for _ in $(seq 1 200); do
		port=$((20000 + (RANDOM * 32768 + RANDOM) % 40000))
		if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
			echo "$port"
			return 0
		fi
	done
	die "no free port found"
}

# wait_port ADDR SECONDS: until something accepts connections on ADDR.
wait_port() {
	local host=${1%:*} port=${1##*:} deadline=$(($(date +%s) + $2))
	until (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 0.1
	done
}

# start_cmcd ZONE: run the zone's cmcd from its generated configuration.
start_cmcd() {
	local zone=$1 addr
	addr=$(jq -r .cmcAddr "$fixtures/zone-$zone/cmcd.json")
	(cd "$work" && exec "$work/bin/cmcd" --config "$fixtures/zone-$zone/cmcd.json") >>"$work/logs/cmcd-$zone.log" 2>&1 &
	pids[cmcd-$zone]=$!
	wait_port "$addr" 30 || {
		cat "$work/logs/cmcd-$zone.log" >&2
		die "cmcd of zone $zone did not start"
	}
}

# start_cmcds: both zones, then check that each produces reports with metadata which both verify.
start_cmcds() {
	say "starting cmcd for zone a ($cmcd_a) and zone b ($cmcd_b)"
	start_cmcd a
	start_cmcd b
	if ! ATLS_FIXTURE_CMCD_CHECK=$cmcd_a,$cmcd_b \
		go test -count=1 -v -run '^TestCmcdReports$' ./internal/atls/atlstest/ >"$work/logs/cmcd-check.log" 2>&1; then
		cat "$work/logs/cmcd-check.log" >&2
		die "the cmcd processes do not produce verifiable reports"
	fi
}

# spawn NAME COMMAND...: run COMMAND in the background with its output in logs/NAME.log.
spawn() {
	local name=$1
	shift
	"$@" >>"$work/logs/$name.log" 2>&1 &
	pids[$name]=$!
}

# signal NAME SIGNAL
signal() { kill "-$2" "${pids[$1]}" 2>/dev/null || true; }

# reap NAME [SECONDS]: wait for NAME to end and leave its exit status in $reaped; after SECONDS
# (default 30) it is killed and $reaped is "killed". Call it directly, not in $(...).
reap() {
	local name=$1 limit=${2:-30} pid=${pids[$1]}
	local deadline=$(($(date +%s) + limit))
	reaped=0
	while kill -0 "$pid" 2>/dev/null; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			kill -CONT "$pid" 2>/dev/null || true
			kill -KILL "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
			unset "pids[$name]"
			reaped=killed
			return 0
		fi
		sleep 0.1
	done
	wait "$pid" 2>/dev/null || reaped=$?
	unset "pids[$name]"
}

# kill_now NAME: SIGKILL, as a crash would end the process, and wait until it is gone. A frozen
# process is killed as it is, without letting it run again first.
kill_now() {
	local pid=${pids[$1]}
	kill -KILL "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	unset "pids[$1]"
}

# field FILE JQ-EXPRESSION: the value, or the empty string when the file or the value is missing.
field() {
	[ -f "$1" ] || return 0
	jq -r "($2) // empty" "$1" 2>/dev/null || true
}

# wait_record FILE JQ-CONDITION SECONDS: until the record satisfies the condition.
wait_record() {
	local deadline=$(($(date +%s) + $3))
	until [ -f "$1" ] && jq -e "$2" "$1" >/dev/null 2>&1; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 0.1
	done
}

# wait_listening RECORD SECONDS: until a probe server or relay has written its record, which it
# does once it listens. Its port is not probed: the server would count that as a handshake.
wait_listening() { wait_record "$1" '(.listen_addr // "") != ""' "$2"; }

# --- evidence -------------------------------------------------------------------------------

# scrub: replace what is particular to this machine and run — the temporary directory and the
# host name — so the evidence carries no local path.
scrub() {
	local host fqdn
	host=$(hostname 2>/dev/null || true)
	fqdn=$(hostname -f 2>/dev/null || true)
	# A very short host name would match ordinary words; leave it.
	[ "${#host}" -ge 4 ] || host=
	[ "${#fqdn}" -ge 4 ] || fqdn=
	sed -e "s|$work|<work>|g" ${fqdn:+-e "s|$fqdn|<host>|g"} ${host:+-e "s|$host|<host>|g"}
}

# collect [SUBFOLDER]: copy the records and logs written so far into the evidence folder.
collect() {
	local dest=$out${1:+/$1} f
	mkdir -p "$dest"
	for f in "$work/records${1:+/$1}"/*.json; do
		[ -f "$f" ] && scrub <"$f" >"$dest/$(basename "$f")"
	done
	for f in "$work/logs${1:+/$1}"/*.log; do
		[ -f "$f" ] && scrub <"$f" >"$dest/$(basename "$f")"
	done
	return 0
}

# collect_configs: the cmcd configuration each zone ran with (paths only, no secret).
collect_configs() {
	local zone
	for zone in a b; do
		scrub <"$fixtures/zone-$zone/cmcd.json" >"$out/cmcd-$zone.config.json"
	done
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

# expect FILE [JQ-OPTION...] JQ-CONDITION: true when the record satisfies the condition.
expect() { [ -f "$1" ] && jq -e "${@:2}" "$1" >/dev/null 2>&1; }

# verify_summary TITLE SCRIPT-NAME: the checks --verify makes on a folder that holds only the
# summary of a run. The records are not there, so the recorded verdict is checked, not re-derived.
verify_summary() {
	local e=$out/environment.json
	check "verdict.txt is the verdict of this proof" summary_line head "$1"
	check "verdict.txt records at least one check and none that failed" summary_checks
	check "verdict.txt ends with verdict: PASS" summary_line tail "verdict: PASS"
	check "environment.json names this script, the commit, the versions, the date and the host kind of the run" \
		expect "$e" --arg script "scripts/atls-probe/$script" \
		'.script == $script and (.commit | test("^[0-9a-f]{40}$")) and (.dirty | type) == "boolean"
		 and (.go_version // "") != "" and (.cmc_version // "") != "" and (.date // "") != ""
		 and (.host_kind | IN("local", "ci", "target-cluster"))'
}
summary_line() { [ -f "$out/verdict.txt" ] && [ "$("$1" -n 1 "$out/verdict.txt")" = "$2" ]; }
summary_checks() { grep -q '^PASS  ' "$out/verdict.txt" 2>/dev/null && ! grep -q '^FAIL' "$out/verdict.txt"; }

# run_verify TITLE: what --verify does. On the records of a run it makes the proof's own checks
# (verdict); on a summary-only folder it checks the recorded verdict, and the proof's
# verdict_summary when the script defines one. It does not return.
run_verify() {
	if [ -n "$summary_only" ]; then
		verify_summary "$1"
		if declare -F verdict_summary >/dev/null; then verdict_summary "$out"; fi
		conclude "$1" "summary only: this folder holds the summary of a run, so the recorded verdict is checked; the records it was derived from are in the run's full output"
	fi
	verdict "$out"
	conclude "$1"
}

# write_summary: copy the summary files of this run to the proof's folder in the repository.
write_summary() {
	local f
	rm -rf "$summary_dir"
	mkdir -p "$summary_dir"
	for f in "${SUMMARY_FILES[@]}"; do
		[ -f "$out/$f" ] && cp "$out/$f" "$summary_dir/$f"
	done
	say "summary written to $summary_dir"
}

# conclude TITLE [NOTE...]: print the verdict, write verdict.txt unless verifying, and exit
# with status 0 only when every check passed.
conclude() {
	local title=$1 result=PASS line text
	shift
	[ "$checks_failed" -eq 0 ] || result=FAIL
	text=$(
		say "$title"
		say
		for line in "${verdict_lines[@]}"; do say "$line"; done
		for line in "$@"; do say "NOTE  $line"; done
		say
		say "verdict: $result"
	)
	say "$text"
	if [ -z "$verify_only" ]; then
		say "$text" >"$out/verdict.txt"
		say "full output written to $out"
		if [ -n "$summary_dir" ] && [ "$result" = PASS ]; then
			write_summary
		elif [ -n "$summary_dir" ]; then
			say "the run failed: the summary in $summary_dir is left as it was"
		fi
	fi
	[ "$result" = PASS ] || exit 1
	exit 0
}

verdict_lines=()
