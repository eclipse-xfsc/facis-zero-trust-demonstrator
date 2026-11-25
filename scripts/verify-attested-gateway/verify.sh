#!/usr/bin/env bash
# ZT-19: two real local cmcd processes; no Docker, Kubernetes or zone writes.
# Usage: verify.sh --out ABSOLUTE_DIRECTORY
# Optional GATEWAY_CONTROL_DIR: BDD pauses after establishing the channel until
# the caller creates its forward file. Records are emitted only after all tests pass.
set -euo pipefail
source "$(dirname "$0")/../atls-probe/lib.sh"
parse_args attested-gateway "$@"
[ -z "$verify_only" ] || die "this proof always runs; replay is not acceptance"
setup
start_cmcds
status=0
GATEWAY_FIXTURES="$fixtures" GATEWAY_RECORD="$out/record.json" \
  go test -count=1 -timeout=180s -v -run '^TestGatewayProof$' ./internal/connectorgateway \
  >"$out/gateway-test.log" 2>&1 || status=$?
collect_configs
cp "$work/logs/cmcd-a.log" "$work/logs/cmcd-b.log" "$work/logs/cmcd-check.log" "$out/"
if [ "$status" -ne 0 ]; then
  cat "$out/gateway-test.log" >&2
  die "gateway forwarding proof failed"
fi
jq -e '.passed == true and .proof == "http-grpc-two-cmcd" and .interConnectorTLSBytes > 0 and
  ([.events[] | select(.decision == "established" and .tlsVersion == 772)] | length >= 4) and
  ([.events[] | select(.decision == "refused" and .role == "ingress" and .reason == "atls: peer does not speak attested TLS 1.3")] | length == 1) and
  ([.events[] | select(.decision == "refused" and .role == "ingress" and .reason == "atls: handshake timed out")] | length == 1) and
  ([.events[] | select(.decision == "refused" and .role == "egress" and .reason == "atls: handshake timed out")] | length == 1)' \
  "$out/record.json" >/dev/null || die "the record does not hold the channel, the protected hop and the three refusals"
printf 'PASS ZT-19: HTTP and gRPC preserved over the attested channel; plaintext and unattested TLS refused; no fallback\n' >"$out/verdict.txt"
cat "$out/verdict.txt"
