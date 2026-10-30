#!/usr/bin/env bash
# Proof — session loss: what each surviving end observes, how long it takes, and whether
# a new channel can be opened afterwards.
#
# Every scenario starts from an established channel between a probe server (zone a) and client
# (zone b) that both keep open and send a heartbeat over every second. Then one thing is taken
# away:
#
#   server-killed                              SIGKILL to the server
#   client-killed                              SIGKILL to the client
#   cmcd-killed-channel-open                   SIGKILL to zone a's cmcd; the channel stays in use,
#                                              then a second client dials
#   cmcd-killed-during-handshake               zone a's cmcd is frozen, a second client dials, the
#                                              cmcd is killed while that handshake waits for it
#   cmcd-killed-during-handshake-dialer-zone   the same with zone b's cmcd, the dialing side
#   server-frozen                              SIGSTOP to the server: a half-open peer
#
# Each scenario ends with one reconnect attempt after what was taken away is back. The script
# records; it does not judge timings. It fails when a scenario could not be run or left no
# finding, or when a handshake without the zone's cmcd is not refused with
# ErrAttesterUnavailable. A surviving end that sees nothing is recorded as
# "no error observed within <limit>".
#
# Usage: prove-session-loss.sh [--out DIR] [--verify DIR]
#   --out DIR      write the evidence to DIR/session-loss
#                  (default: docs/evidences/cmc-atls-channel-binding/)
#   --verify DIR   run nothing; check the findings already in DIR
#
# Environment: ATLS_SESSION_LOSS_LIMIT  seconds a surviving end is given to observe an error (default 15)
#
# Needs go, git and jq. Evidence: reconnect-findings.md, findings.json, one folder of records
# and logs per scenario, environment.json, verdict.txt.
set -euo pipefail
# shellcheck source=scripts/atls-probe/lib.sh
source "$(dirname "$0")/lib.sh"

limit=${ATLS_SESSION_LOSS_LIMIT:-15}
scenarios=(server-killed client-killed cmcd-killed-channel-open cmcd-killed-during-handshake
	cmcd-killed-during-handshake-dialer-zone server-frozen)

# verdict DIR: the checks of this proof over the findings in DIR.
verdict() {
	local findings=$1/findings.json md=$1/reconnect-findings.md sc
	check "findings.json and reconnect-findings.md were written" test -s "$findings" -a -s "$md"
	for sc in "${scenarios[@]}"; do
		check "$sc: ran from an established channel and left findings with a reconnect outcome" \
			expect "$findings" --arg sc "$sc" \
			'[.[] | select(.scenario == $sc)] | length > 0 and all(.from_established_channel == true
			 and (.error // "") != "" and (.reconnect // "") != "")'
		check "$sc: listed in reconnect-findings.md" grep -q "| $sc |" "$md"
	done
	check "cmcd-killed-channel-open: states whether the open channel kept working" \
		expect "$findings" \
		'any(.[]; .scenario == "cmcd-killed-channel-open" and (.surviving_end | test("open channel")))'
	check "cmcd-killed-channel-open: the new handshake is refused with ErrAttesterUnavailable by the end without cmcd" \
		expect "$findings" \
		'any(.[]; .scenario == "cmcd-killed-channel-open" and (.surviving_end | test("new handshake"))
		 and (.classification | test("ErrAttesterUnavailable")))'
	check "cmcd-killed-during-handshake: the end whose cmcd died refuses with ErrAttesterUnavailable" \
		expect "$findings" \
		'any(.[]; .scenario == "cmcd-killed-during-handshake" and (.classification | test("ErrAttesterUnavailable")))'
	check "server-frozen: states how long, if at all, the client took to observe an error" \
		expect "$findings" \
		'any(.[]; .scenario == "server-frozen" and (.surviving_end | test("^client"))
		 and ((.time_to_detect | test("ms$")) or (.error | test("^no error observed within"))))'
}

parse_args session-loss "$@"
title="Session loss is recorded per scenario"
if [ -n "$verify_only" ]; then
	verdict "$out"
	conclude "$title"
fi

# --- helpers ------------------------------------------------------------------------------

sc= # the scenario being run
server_addr=

rec() { echo "$work/records/$sc/$1.json"; }

# start_server NAME: a server of zone a that takes handshakes until stopped and holds each
# channel open.
start_server() {
	spawn "$sc/$1" "$probe" server --listen "$server_addr" "${zone_a[@]}" --record "$(rec "$1")" \
		--sessions 0 --hold 10m --interval 1s --accept-timeout 0
	wait_listening "$(rec "$1")" 30 || die "$sc: the probe server did not start"
}

# establish: the channel every scenario starts from, with heartbeats flowing both ways.
establish() {
	mkdir -p "$work/records/$sc" "$work/logs/$sc"
	server_addr=127.0.0.1:$(free_port)
	start_server server
	spawn "$sc/client" "$probe" client --connect "$server_addr" "${zone_b[@]}" --record "$(rec client)" \
		--hold 10m --interval 1s
	local flowing='.outcome == "established" and .heartbeats.received >= 2 and (.ended // "") == ""'
	wait_record "$(rec server)" "$flowing" 30 && wait_record "$(rec client)" "$flowing" 30 ||
		die "$sc: no established channel to start from"
	say "$sc: channel established, binding $(field "$(rec client)" .binding)"
}

# attempt NAME [FLAG...]: one more client of zone b dials the server, exchanges a heartbeat and
# leaves. Its record tells how it went.
attempt() {
	local name=$1
	shift
	spawn "$sc/$name" "$probe" client --connect "$server_addr" "${zone_b[@]}" --record "$(rec "$name")" "$@"
	reap "$sc/$name" 60
}

# outcome FILE [JQ-PATH]: one line on how a handshake went.
outcome() {
	jq -r "${2:-.}"' |
		if .outcome == "established" then "established in \(.handshake_ms // "?") ms, verdict \(.verdict)"
		elif .outcome == "refused" then "refused, " + (if (.refusal.sentinel // "") != "" then .refusal.sentinel else "no sentinel" end)
		else "no handshake seen (" + (.outcome // "no record") + ")" end' "$1" 2>/dev/null || echo "no record"
}

# observe FILE T0 [JQ-PATH]: what the session at JQ-PATH of the record observed after T0 (Unix
# ms). Sets obs_error, obs_class and obs_detect.
observe() {
	local file=$1 t0=$2 path=${3:-.} at
	obs_error=$(jq -r "$path"' |
		if .error then "\(.error.op): \(.error.message)"
		elif .refusal then .refusal.message
		else "session ended: \(.ended)" end' "$file")
	obs_class=$(jq -r "$path"' |
		if .error and .error.kind == "sentinel" then "sentinel " + .error.sentinel
		elif .error then "transport (" + .error.transport + "), no sentinel"
		elif .refusal and .refusal.sentinel != "" then "sentinel " + .refusal.sentinel
		elif .refusal then "no sentinel"
		else "none" end' "$file")
	at=$(jq -r "$path"' | .error.detected_at_unix_ms // .refused_at_unix_ms // .ended_at_unix_ms // empty' "$file")
	obs_detect=unknown
	[ -z "$at" ] || obs_detect="$((at - t0)) ms"
}

# finding END ERROR CLASSIFICATION TIME-TO-DETECT RECONNECT: one row of the findings.
finding() {
	jq -n --arg scenario "$sc" --arg end "$1" --arg error "$2" --arg class "$3" --arg detect "$4" --arg reconnect "$5" \
		'{scenario: $scenario, from_established_channel: true, surviving_end: $end, error: $error,
		  classification: $class, time_to_detect: $detect, reconnect: $reconnect}' >>"$work/findings.jsonl"
	say "$sc: $1: $2 [$3, $4]"
}

# stop NAME...: end probe processes in an orderly way, so they write their final record.
stop() {
	local name
	for name in "$@"; do
		[ -n "${pids[$sc/$name]:-}" ] || continue
		signal "$sc/$name" TERM
		reap "$sc/$name" 15
	done
}

# silent_or_observed FILE T0 SECONDS [JQ-PATH]: wait for the session to end; when it does not,
# the observation is that nothing was observed.
silent_or_observed() {
	local file=$1 t0=$2 seconds=$3 path=${4:-.}
	if wait_record "$file" "$path | (.ended // \"\") != \"\"" "$seconds"; then
		observe "$file" "$t0" "$path"
	else
		obs_error="no error observed within $seconds s"
		obs_class="none"
		obs_detect="not detected"
	fi
}

heartbeats() { field "$1" "${2:-.} | .heartbeats.received"; }

# --- scenarios ----------------------------------------------------------------------------

server_killed() {
	sc=server-killed
	establish
	local t0 down up
	t0=$(now_ms)
	kill_now "$sc/server"
	silent_or_observed "$(rec client)" "$t0" "$limit"
	stop client
	attempt reconnect-while-down
	down=$(outcome "$(rec reconnect-while-down)")
	start_server server-restarted
	attempt reconnect
	up=$(outcome "$(rec reconnect)")
	finding "client" "$obs_error" "$obs_class" "$obs_detect" "while the server is down: $down; after restarting it: $up"
	stop server-restarted
}

client_killed() {
	sc=client-killed
	establish
	local t0 again
	t0=$(now_ms)
	kill_now "$sc/client"
	silent_or_observed "$(rec server)" "$t0" "$limit"
	attempt reconnect
	again=$(outcome "$(rec reconnect)")
	finding "server" "$obs_error" "$obs_class" "$obs_detect" "a new client against the surviving server: $again"
	stop server
}

cmcd_killed_channel_open() {
	sc=cmcd-killed-channel-open
	establish
	local t0 s0 c0 s1 c1 watch=$((limit < 8 ? limit : 8)) open restored t1
	s0=$(heartbeats "$(rec server)")
	c0=$(heartbeats "$(rec client)")
	t0=$(now_ms)
	kill_now cmcd-a
	sleep "$watch"
	s1=$(heartbeats "$(rec server)")
	c1=$(heartbeats "$(rec client)")
	if expect "$(rec server)" '(.ended // "") == ""' && expect "$(rec client)" '(.ended // "") == ""' &&
		[ "$s1" -gt "$s0" ] && [ "$c1" -gt "$c0" ]; then
		open="no error observed within $watch s; the open channel keeps working (heartbeats received: server $s0 to $s1, client $c0 to $c1)"
	else
		observe "$(rec server)" "$t0"
		open="the open channel did not keep working: $obs_error"
	fi

	# A new handshake while zone a has no cmcd.
	t1=$(now_ms)
	attempt handshake-without-cmcd
	start_cmcd a
	attempt reconnect
	restored=$(outcome "$(rec reconnect)")
	stop client server

	finding "server and client (open channel)" "$open" "none" "not detected" \
		"not needed for the open channel; a new one after restarting cmcd: $restored"
	observe "$(rec server)" "$t1" '.further_sessions[0]'
	finding "server, zone without cmcd (new handshake)" "$obs_error" "$obs_class" "$obs_detect" \
		"after restarting cmcd: $restored"
	observe "$(rec handshake-without-cmcd)" "$t1"
	finding "client, zone with cmcd (new handshake)" "$obs_error" "$obs_class" "$obs_detect" \
		"after restarting cmcd: $restored"
}

# cmcd_killed_during_handshake ZONE SCENARIO: ZONE's cmcd is frozen so that the next handshake
# waits for it, then killed while that handshake is in flight.
cmcd_killed_during_handshake() {
	local zone=$1 t0 restored own other before s0 c0
	sc=$2
	establish
	signal "cmcd-$zone" STOP
	spawn "$sc/handshake" "$probe" client --connect "$server_addr" "${zone_b[@]}" --record "$(rec handshake)"
	wait_record "$(rec handshake)" '.outcome == "pending" and (.handshake_started_at // "") != ""' 10 ||
		die "$sc: the second client did not start"
	sleep 2
	expect "$(rec handshake)" '.outcome == "pending"' || die "$sc: the handshake did not wait for the frozen cmcd"
	t0=$(now_ms)
	kill_now "cmcd-$zone"
	reap "$sc/handshake" 60
	# The server notes the refusal once its own side of the handshake has ended.
	wait_record "$(rec server)" '(.further_sessions[0].outcome // "pending") != "pending"' 30 || true
	start_cmcd "$zone"
	attempt reconnect
	restored=$(outcome "$(rec reconnect)")
	# The channel opened before the cmcd was frozen: still open and in use?
	s0=$(heartbeats "$(rec server)")
	c0=$(heartbeats "$(rec client)")
	sleep 2
	if expect "$(rec server)" '(.ended // "") == ""' && expect "$(rec client)" '(.ended // "") == ""' &&
		[ "$(heartbeats "$(rec server)")" -gt "$s0" ] && [ "$(heartbeats "$(rec client)")" -gt "$c0" ]; then
		before="no error observed; the channel stayed open and in use throughout"
	else
		before="the channel did not stay open: server $(field "$(rec server)" '.ended // "open"'), client $(field "$(rec client)" '.ended // "open"')"
	fi
	stop client server

	if [ "$zone" = a ]; then own="server, its cmcd died" other="client, its cmcd is up"; else own="client, its cmcd died" other="server, its cmcd is up"; fi
	if [ "$zone" = a ]; then observe "$(rec server)" "$t0" '.further_sessions[0]'; else observe "$(rec handshake)" "$t0"; fi
	finding "$own (handshake in flight)" "$obs_error" "$obs_class" "$obs_detect" "after restarting cmcd: $restored"
	if expect "$(rec server)" '.further_sessions[0]'; then
		if [ "$zone" = a ]; then observe "$(rec handshake)" "$t0"; else observe "$(rec server)" "$t0" '.further_sessions[0]'; fi
	else
		obs_error="no handshake reached the server" obs_class="none" obs_detect="not detected"
	fi
	finding "$other (handshake in flight)" "$obs_error" "$obs_class" "$obs_detect" "after restarting cmcd: $restored"
	finding "server and client (channel opened before)" "$before" "none" "not detected" "not needed for the open channel"
}

server_frozen() {
	sc=server-frozen
	establish
	local t0 frozen c0 c1 resumed again note
	t0=$(now_ms)
	signal "$sc/server" STOP
	silent_or_observed "$(rec client)" "$t0" "$limit"
	note=$(jq -r '"its writes still succeed (\(.heartbeats.sent) heartbeats sent); the last heartbeat from the peer is \(.heartbeats.max_gap_ms) ms old"' "$(rec client)")
	attempt reconnect-while-frozen --handshake-timeout 5s
	frozen=$(outcome "$(rec reconnect-while-frozen)")
	c0=$(heartbeats "$(rec client)")
	signal "$sc/server" CONT
	sleep 3
	c1=$(heartbeats "$(rec client)")
	if [ "${c1:-0}" -gt "${c0:-0}" ] && expect "$(rec client)" '(.ended // "") == ""'; then
		resumed="the frozen channel resumes once the server runs again"
	else
		resumed="the frozen channel does not resume: client $(field "$(rec client)" '.ended // "still open, no heartbeat"')"
	fi
	attempt reconnect
	again=$(outcome "$(rec reconnect)")
	finding "client" "$obs_error; $note" "$obs_class" "$obs_detect" \
		"while the server is frozen: $frozen; after it runs again: $again; $resumed"
	stop client server
}

# --- findings -----------------------------------------------------------------------------

write_findings() {
	jq -s . "$work/findings.jsonl" | scrub >"$out/findings.json"
	{
		say "# Session loss — reconnect findings"
		say
		say "Generated by \`scripts/atls-probe/prove-session-loss.sh\`; not edited by hand."
		say
		jq -r '"Run: commit `\(.commit)`\(if .dirty then " with uncommitted changes" else "" end), \(.go_version), CMC \(.cmc_version), \(.date), host kind `\(.host_kind)`."' "$out/environment.json"
		say
		say "Every scenario starts from an established channel between a probe server (zone a) and a"
		say "probe client (zone b), each attesting through the \`cmcd\` of its zone, with a heartbeat"
		say "every second in both directions. A surviving end is given $limit s to observe an error."
		say "\"Sentinel\" is a refusal sentinel of \`internal/atls\`; \"transport\" is an error of the"
		say "connection that matches none. Time to detect counts from the moment the process was"
		say "killed or frozen. The records and logs of each scenario are in the folder of its name."
		say
		say "| Scenario | Surviving end | Error observed | Sentinel or transport | Time to detect | Reconnect |"
		say "|---|---|---|---|---|---|"
		jq -r '.[] | [.scenario, .surviving_end, .error, .classification, .time_to_detect, .reconnect]
			| map(gsub("\\|"; "\\|") | gsub("\n"; " ") | if length > 260 then .[0:260] + "…" else . end)
			| "| " + join(" | ") + " |"' "$out/findings.json"
		say
		say "Long error texts are cut in the table; \`findings.json\` has them in full."
	} >"$out/reconnect-findings.md"
}

# --- run ----------------------------------------------------------------------------------

setup
start_cmcds
: >"$work/findings.jsonl"

server_killed
client_killed
cmcd_killed_channel_open
cmcd_killed_during_handshake a cmcd-killed-during-handshake
cmcd_killed_during_handshake b cmcd-killed-during-handshake-dialer-zone
server_frozen

collect
for sc in "${scenarios[@]}"; do collect "$sc"; done
collect_configs
write_findings
verdict "$out"
conclude "$title" "timings are recorded, not judged"
