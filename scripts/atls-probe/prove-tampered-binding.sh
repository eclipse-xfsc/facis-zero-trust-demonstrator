#!/usr/bin/env bash
# Proof — a tampered binding aborts the handshake.
#
# Puts the probe's relay between the client (zone b) and the server (zone a). The relay is an
# insider: it holds certificates the zone CAs issued for the two gateway identities, so both TLS
# handshakes succeed and the identity checks pass. It forwards the attestation exchange between
# its two TLS sessions unchanged, so each end receives a report bound to a TLS session it is not
# part of. Passes only when the relay was in the path and forwarded bytes both ways, both ends
# refuse the channel with ErrBindingMismatch, and no application data crossed.
#
# Usage: prove-tampered-binding.sh [--out DIR] [--verify DIR]
#   --out DIR      write the evidence to DIR/tampered-binding
#                  (default: docs/evidences/cmc-atls-channel-binding/)
#   --verify DIR   run nothing; check the records already in DIR
#
# A control run shows why the relay needs those identities: with a certificate of another
# identity it is stopped by the identity check (ErrIdentityMismatch) before any attestation.
#
# Needs go, git and jq. Evidence: server.json, client.json, relay.json, control-other-identity/,
# logs, environment.json, verdict.txt.
set -euo pipefail
# shellcheck source=scripts/atls-probe/lib.sh
source "$(dirname "$0")/lib.sh"

# verdict DIR: the checks of this proof over the records in DIR.
verdict() {
	local server=$1/server.json client=$1/client.json relay=$1/relay.json end

	# The relay must have been in the path; a handshake that succeeds end to end proves nothing.
	for end in server client; do
		if expect "$1/$end.json" '.outcome == "established"'; then
			verdict_lines+=("FAIL  the $end established a channel: the relay did not exercise the binding")
			checks_failed=$((checks_failed + 1))
		fi
	done
	check "the relay held a TLS 1.3 session with each end and forwarded bytes both ways" \
		expect "$relay" '.outcome == "forwarded" and .relay.bytes_dialer_to_listener > 0 and .relay.bytes_listener_to_dialer > 0
		 and .relay.downstream.tls_version == "TLS 1.3" and .relay.upstream.tls_version == "TLS 1.3"'
	check "the relay's two TLS sessions have different channel bindings" \
		expect "$relay" '.relay.bindings_differ == true'
	check "the relay's sessions were with this client and this server" \
		expect "$relay" --slurpfile s "$server" --slurpfile c "$client" \
		'.relay.downstream.peer_fingerprint == $c[0].cert_fingerprint and .relay.upstream.peer_fingerprint == $s[0].cert_fingerprint'
	check "the relay showed each end a certificate with the identity that end expects" \
		expect "$relay" --slurpfile s "$server" --slurpfile c "$client" \
		'(.relay.downstream.presented_identities | index($c[0].expected_peer_identity)) != null
		 and (.relay.upstream.presented_identities | index($s[0].expected_peer_identity)) != null'
	check "the server refused the channel with ErrBindingMismatch" \
		expect "$server" '.outcome == "refused" and .refusal.sentinel == "ErrBindingMismatch" and (.refusal.message // "") != ""'
	check "the client refused the channel with ErrBindingMismatch" \
		expect "$client" '.outcome == "refused" and .refusal.sentinel == "ErrBindingMismatch" and (.refusal.message // "") != ""'
	check "neither end holds a binding" \
		expect "$server" --slurpfile c "$client" '[., $c[0]] | all(has("binding") | not)'
	check "no application data crossed" \
		expect "$server" --slurpfile c "$client" \
		'[., $c[0]] | all(.application_bytes_sent == 0 and .application_bytes_received == 0 and .heartbeats.received == 0)'

	# Control: why the relay needs the peers' identities to reach the binding check at all.
	local control=$1/control-other-identity
	check "control: a relay showing another identity is stopped by the identity check (ErrIdentityMismatch)" \
		expect "$control/client.json" '.outcome == "refused" and .refusal.sentinel == "ErrIdentityMismatch"'
	check "control: that relay forwarded nothing" \
		expect "$control/relay.json" '.outcome == "not-relayed" and .relay.bytes_dialer_to_listener == 0 and .relay.bytes_listener_to_dialer == 0'
}

parse_args tampered-binding "$@"
title="A report bound to another TLS session is refused"
if [ -n "$verify_only" ]; then
	verdict "$out"
	conclude "$title"
fi

setup
start_cmcds

listen=127.0.0.1:$(free_port)
relay_addr=127.0.0.1:$(free_port)
say "server (zone a) on $listen, relay on $relay_addr, client (zone b) dials the relay"
spawn server "$probe" server --listen "$listen" "${zone_a[@]}" --record "$work/records/server.json" --accept-timeout 60s
wait_listening "$work/records/server.json" 30 || die "the probe server did not start"
# To the client the relay shows zone a's gateway identity, to the server zone b's.
spawn relay "$probe" relay --listen "$relay_addr" --upstream "$listen" \
	--cert "$fixtures/relay/as-zone-a.cert.pem" --key "$fixtures/relay/as-zone-a.key.pem" \
	--upstream-cert "$fixtures/relay/as-zone-b.cert.pem" --upstream-key "$fixtures/relay/as-zone-b.key.pem" \
	"${trust[@]}" --record "$work/records/relay.json" --accept-timeout 60s
wait_listening "$work/records/relay.json" 30 || die "the relay did not start"
spawn client "$probe" client --connect "$relay_addr" "${zone_b[@]}" --record "$work/records/client.json"
reap client 60
say "client exit status: $reaped (2 = no channel)"
reap server 60
say "server exit status: $reaped (2 = no channel)"
reap relay 60
say "relay exit status: $reaped (0 = forwarded)"

# Control: the same relay showing the client a certificate of zone b's identity instead of the
# expected zone a. The client refuses during the TLS handshake; nothing reaches the server.
mkdir -p "$work/records/control-other-identity" "$work/logs/control-other-identity"
control_addr=127.0.0.1:$(free_port)
spawn control-other-identity/relay "$probe" relay --listen "$control_addr" --upstream "$listen" \
	--cert "$fixtures/relay/as-zone-b.cert.pem" --key "$fixtures/relay/as-zone-b.key.pem" \
	"${trust[@]}" --record "$work/records/control-other-identity/relay.json" --accept-timeout 60s
wait_listening "$work/records/control-other-identity/relay.json" 30 || die "the control relay did not start"
spawn control-other-identity/client "$probe" client --connect "$control_addr" "${zone_b[@]}" \
	--record "$work/records/control-other-identity/client.json"
reap control-other-identity/client 60
say "control client exit status: $reaped (2 = no channel)"
reap control-other-identity/relay 60
say "control relay exit status: $reaped (2 = nothing forwarded)"

collect
collect control-other-identity
collect_configs
verdict "$out"
conclude "$title" \
	"the relay forwards the attestation messages unread; the bytes it counts are that exchange, not application data"
