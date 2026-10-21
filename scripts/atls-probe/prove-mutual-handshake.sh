#!/usr/bin/env bash
# Proof — two processes complete a mutually attested handshake and derive the same
# channel binding.
#
# Runs one cmcd per zone and a probe server (zone a) and client (zone b) as separate processes.
# Passes only when both records show an established channel with verdict "success", each end saw
# the certificate of the expected peer, and both hold the same 32-byte RFC 9266 binding.
#
# Usage: prove-mutual-handshake.sh [--out DIR] [--verify DIR]
#   --out DIR      write the evidence to DIR/mutual-handshake
#                  (default: docs/evidences/cmc-atls-channel-binding/)
#   --verify DIR   run nothing; check the records already in DIR
#
# Needs go, git and jq. Evidence: server.json, client.json, logs, environment.json, verdict.txt.
set -euo pipefail
# shellcheck source=scripts/atls-probe/lib.sh
source "$(dirname "$0")/lib.sh"

# verdict DIR: the checks of this proof over the records in DIR.
verdict() {
	local dir=$1 server=$1/server.json client=$1/client.json
	check "the server returned an established channel with verdict success" \
		expect "$server" '.outcome == "established" and .verdict == "success" and .exit_code == 0'
	check "the client returned an established channel with verdict success" \
		expect "$client" '.outcome == "established" and .verdict == "success" and .exit_code == 0'
	check "the server required $ZONE_B_ID and the client's certificate carries it" \
		expect "$server" --arg id "$ZONE_B_ID" --slurpfile peer "$client" \
		'.expected_peer_identity == $id and ($peer[0].identities | index($id)) != null
		 and .peer_fingerprint == $peer[0].cert_fingerprint'
	check "the client required $ZONE_A_ID and the server's certificate carries it" \
		expect "$client" --arg id "$ZONE_A_ID" --slurpfile peer "$server" \
		'.expected_peer_identity == $id and ($peer[0].identities | index($id)) != null
		 and .peer_fingerprint == $peer[0].cert_fingerprint'
	check "both ends state until when the channel is valid" \
		expect "$server" --slurpfile peer "$client" '(.valid_until // "") != "" and ($peer[0].valid_until // "") != ""'
	check "each binding is 32 bytes" \
		expect "$server" --slurpfile peer "$client" \
		'[., $peer[0]] | all(.binding_bytes == 32 and ((.binding // "") | test("^[0-9a-f]{64}$")))'

	local sb cb
	sb=$(field "$server" .binding)
	cb=$(field "$client" .binding)
	if [ -n "$sb" ] && [ "$sb" = "$cb" ]; then
		verdict_lines+=("PASS  both ends hold the same binding: $sb")
	else
		verdict_lines+=("FAIL  the bindings differ: server ${sb:-none}, client ${cb:-none}")
		checks_failed=$((checks_failed + 1))
	fi
	check "application data crossed the channel in both directions" \
		expect "$server" --slurpfile peer "$client" \
		'[., $peer[0]] | all(.application_bytes_sent > 0 and .application_bytes_received > 0)'
}

parse_args mutual-handshake "$@"
title="Mutual attested handshake, identical binding"
if [ -n "$verify_only" ]; then
	verdict "$out"
	conclude "$title"
fi

setup
start_cmcds

listen=127.0.0.1:$(free_port)
say "server (zone a) on $listen, client (zone b)"
spawn server "$probe" server --listen "$listen" "${zone_a[@]}" --record "$work/records/server.json" --accept-timeout 60s
wait_listening "$work/records/server.json" 30 || die "the probe server did not start"
spawn client "$probe" client --connect "$listen" "${zone_b[@]}" --record "$work/records/client.json"
reap client 60
say "client exit status: $reaped"
reap server 60
say "server exit status: $reaped"

collect
collect_configs
verdict "$out"
conclude "$title"
