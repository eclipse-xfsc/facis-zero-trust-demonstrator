#!/usr/bin/env bash
# Proof — each zone's mock attestation evidence is provisioned from its configuration in Git,
# from zero, through the zone's own estserver and cmcd (ADR-0011 class 3, ZT-31 and ZT-63).
#
# From an empty directory it builds the pinned CMC tools (cmcd, estserver, metatool), creates a
# throwaway PKI, and for each zone in deployment/attestation:
#   1. renders the reference values and the measurement log from the zone's file in Git;
#   2. signs the reference values with metatool, as the pipeline does;
#   3. serves them from the zone's estserver, over TLS;
#   4. starts the zone's cmcd, which fetches them from that estserver and signs evidence over the
#      measurement log;
#   5. runs the gateway's startup check: a fresh report from the zone's cmcd, verified against the
#      metadata CA, whose measured values must be those of the file in Git.
# Then it changes the first zone's measurement as a commit would, provisions again, and shows that
# the evidence differs, that it verifies against the changed file and not against the original,
# and that reference values signed by a key outside the metadata CA are refused.
#
# Usage: prove.sh [--out DIR]   (records and logs are copied to DIR; by default they are removed)
# Needs go, jq and openssl. Prints each check; exits non-zero when one fails.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
out=""
while [ $# -gt 0 ]; do
	case $1 in
	--out) out=$2; shift 2 ;;
	*) echo "usage: $0 [--out DIR]" >&2; exit 1 ;;
	esac
done
for tool in go jq openssl; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }; done

work=$(mktemp -d "${TMPDIR:-/tmp}/attestation-provision.XXXXXX")
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [ -n "$out" ]; then mkdir -p "$out" && cp -R "$work/logs" "$work/records" "$out/" 2>/dev/null || true; fi
	rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/logs" "$work/records" "$work/pki"
failures=0
say() { printf '== %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }
# now: the signing time, RFC 3339, one second after the previous one so each signing is a newer
# metadata version (CMC keeps the newest of two).
now() { sleep 1; date -u +%Y-%m-%dT%H:%M:%SZ; }

# --- tools --------------------------------------------------------------------------------
cmc=github.com/Fraunhofer-AISEC/cmc
cmc_version=$(go list -m -f '{{.Version}}' "$cmc")
say "building cmcd, estserver and metatool $cmc_version, and attestation-provision"
GOBIN=$work/bin go install "$cmc/cmcd@$cmc_version" "$cmc/tools/estserver@$cmc_version" "$cmc/tools/metatool@$cmc_version"
go build -o "$work/bin/attestation-provision" ./cmd/attestation-provision
provision=$work/bin/attestation-provision

# --- PKI (throwaway; ECDSA P-256, SHA-256) --------------------------------------------------
pki=$work/pki
# cert NAME SUBJECT ISSUER EXTENSIONS: a key and certificate for NAME, signed by ISSUER ("self"
# for a self-signed certificate).
cert() {
	local name=$1 subject=$2 issuer=$3
	printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s\n' "$4" >"$pki/$name.cnf"
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
		-out "$pki/$name.key" 2>/dev/null
	if [ "$issuer" = self ]; then
		openssl req -new -x509 -sha256 -days 2 -key "$pki/$name.key" -subj "$subject" \
			-config "$pki/$name.cnf" -extensions v3 -out "$pki/$name.pem" 2>/dev/null
	else
		openssl req -new -sha256 -key "$pki/$name.key" -subj "$subject" -config "$pki/$name.cnf" \
			-out "$pki/$name.csr" 2>/dev/null
		openssl x509 -req -sha256 -days 2 -in "$pki/$name.csr" -CA "$pki/$issuer.pem" -CAkey "$pki/$issuer.key" \
			-CAcreateserial -extfile "$pki/$name.cnf" -extensions v3 -out "$pki/$name.pem" 2>/dev/null
	fi
}
ca_ext=$'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign'
leaf_ext=$'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature'
say "creating the PKI: metadata CA and pipeline signer, EST CA and estserver TLS, and an untrusted signer"
cert ca "/CN=ztd attestation metadata CA" self "$ca_ext"
cert signer "/CN=ztd pipeline metadata signer" ca "$leaf_ext"
cert est-ca "/CN=ztd EST CA" ca "$ca_ext"
cert est-tls "/CN=127.0.0.1" ca "$leaf_ext"$'\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1'
cert rogue-ca "/CN=not the metadata CA" self "$ca_ext"
cert rogue "/CN=rogue signer" rogue-ca "$leaf_ext"

free_port() {
	local port
	for _ in $(seq 1 200); do
		port=$((20000 + (RANDOM * 32768 + RANDOM) % 40000))
		if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "$port"; return 0; fi
	done
	echo "no free port" >&2
	exit 1
}
wait_port() {
	local deadline=$(($(date +%s) + 30))
	until (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 0.2
	done
}

# provision_zone ZONE CONFIG SIGNER CA SIGNED_AT: render CONFIG, sign its reference values with
# SIGNER (chain SIGNER, CA) into the zone's estserver folder, and put the measurement log where
# the zone's cmcd reads it.
provision_zone() {
	local zone=$1 config=$2 signer=$3 ca=$4 signed_at=$5 dir=$work/$1
	rm -rf "$dir/render" "$dir/metadata-signed"
	mkdir -p "$dir/metadata-signed"
	"$provision" render --zone "$config" --out "$dir/render" --signed-at "$signed_at"
	for f in manifest.json image-description.json; do
		"$work/bin/metatool" sign --in "$dir/render/unsigned/$f" --out "$dir/metadata-signed/$f" \
			--keys "$pki/$signer.key" --x5cs "$pki/$signer.pem,$pki/$ca.pem" >>"$work/logs/metatool-$zone.log" 2>&1
	done
	cp "$dir/render/measurements.json" "$dir/measurements.json"
}

# start_estserver ZONE: the zone's estserver, serving its signed metadata over TLS. Enrolment needs
# a token and the token store is empty, so nothing can enrol.
start_estserver() {
	local zone=$1 dir=$work/$1 port
	port=$(free_port)
	mkdir -p "$dir/tokens"
	jq -n --arg addr "127.0.0.1:$port" --arg pki "$pki" --arg dir "$dir" '{
		estAddr: $addr, estCaKey: ($pki + "/est-ca.key"), estCaChain: [($pki + "/est-ca.pem"), ($pki + "/ca.pem")],
		tlsKey: ($pki + "/est-tls.key"), tlsCaChain: [($pki + "/est-tls.pem"), ($pki + "/ca.pem")],
		rootCas: [($pki + "/ca.pem")], httpFolder: ($dir + "/metadata-signed"), verifyEkCert: false,
		authMethods: ["token"], tokenPath: ($dir + "/tokens"), logLevel: "debug"}' >"$dir/estserver.json"
	"$work/bin/estserver" --config "$dir/estserver.json" >>"$work/logs/estserver-$zone.log" 2>&1 &
	pids+=($!)
	wait_port "$port" || { cat "$work/logs/estserver-$zone.log" >&2; echo "estserver of $zone did not start" >&2; exit 1; }
	echo "$port" >"$dir/est-port"
}

# start_cmcd ZONE: the zone's cmcd, with no cached metadata, fetching it from the zone's estserver.
start_cmcd() {
	local zone=$1 dir=$work/$1 port est
	port=$(free_port)
	est=https://127.0.0.1:$(cat "$dir/est-port")
	rm -rf "$dir/cache"
	jq -n --arg addr "127.0.0.1:$port" --arg est "$est" --arg dir "$dir" --arg ca "$pki/ca.pem" '{
		cmcAddr: $addr, api: "grpc", drivers: ["sw"], hashAlg: "SHA-256",
		ctr: true, ctrDriver: "sw", ctrLog: ($dir + "/measurements.json"),
		metadata: [($est + "/metadata-signed")], rootCas: [$ca], allowSystemCerts: false,
		storage: ($dir + "/storage"), cache: ($dir + "/cache"), peerCache: ($dir + "/peer-cache"),
		endorsementMode: "direct", vendorCache: ($dir + "/vendor-cache"),
		enrollmentMode: "est", enrollmentAddr: ($est + "/"), logLevel: "info"}' >"$dir/cmcd.json"
	"$work/bin/cmcd" --config "$dir/cmcd.json" >>"$work/logs/cmcd-$zone.log" 2>&1 &
	pids+=($!)
	echo $! >"$dir/cmcd-pid"
	wait_port "$port" || { cat "$work/logs/cmcd-$zone.log" >&2; echo "cmcd of $zone did not start" >&2; exit 1; }
	echo "127.0.0.1:$port" >"$dir/cmcd-addr"
}
stop_cmcd() {
	local pid
	pid=$(cat "$work/$1/cmcd-pid")
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

# startup_check ZONE CONFIG RECORD [CA]: the gateway's startup check against the zone's cmcd,
# trusting CA (default the metadata CA); its output goes to records/RECORD.json, its errors to
# logs/check-RECORD.log.
startup_check() {
	"$provision" check --zone "$2" --cmcd "$(cat "$work/$1/cmcd-addr")" --ca "$pki/${4:-ca}.pem" \
		>"$work/records/$3.json" 2>>"$work/logs/check-$3.log"
}

# rejected ZONE CONFIG RECORD PATTERN [CA]: the startup check obtained a report (exit status 2, not
# 3 for no report) and rejected it with an error matching PATTERN.
rejected() {
	local status=0
	startup_check "$1" "$2" "$3" "${5:-ca}" || status=$?
	[ "$status" -eq 2 ] && grep -Eq "$4" "$work/logs/check-$3.log"
}

# --- 1. every zone, from zero ---------------------------------------------------------------
t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
zones=()
for config in deployment/attestation/*.json; do
	zone=$(jq -r .zone "$config")
	zones+=("$zone")
	say "provisioning $zone from $config"
	mkdir -p "$work/$zone"
	provision_zone "$zone" "$config" signer ca "$t0"
	start_estserver "$zone"
	start_cmcd "$zone"
	if startup_check "$zone" "$config" "$zone-startup" &&
		jq -e --slurpfile want "$work/$zone/render/expected.json" '. == $want[0]' "$work/records/$zone-startup.json" >/dev/null; then
		pass "$zone: the startup check obtained evidence from the zone's cmcd and verified it; its measured values are those in Git"
	else
		fail "$zone: startup check"
		cat "$work/logs/check-$zone-startup.log" >&2 || true
	fi
	if grep -q "/metadata-signed/manifest.json" "$work/logs/estserver-$zone.log"; then
		pass "$zone: cmcd fetched the signed metadata from the zone's estserver"
	else
		fail "$zone: the estserver logged no fetch of the signed metadata"
	fi
done

# --- 2. a measurement change, as a commit makes it --------------------------------------------
zone=${zones[0]}
original=deployment/attestation/$zone.json
changed=$work/$zone-changed.json
digest=$(printf 'facis-ztd %s atls-gateway rootfs 2' "$zone" | openssl dgst -sha256 -r | cut -d' ' -f1)
jq --arg d "$digest" '.components[0].rootfs_sha256 = $d' "$original" >"$changed"
say "changing $zone's first component digest and provisioning again"
stop_cmcd "$zone"
provision_zone "$zone" "$changed" signer ca "$(now)"
start_cmcd "$zone"
if startup_check "$zone" "$changed" "$zone-changed"; then
	pass "$zone: after the change the evidence verifies against the changed configuration"
else
	fail "$zone: the changed evidence does not verify"
	cat "$work/logs/check-$zone-changed.log" >&2 || true
fi
before=$(jq -r .aggregate "$work/records/$zone-startup.json" 2>/dev/null || echo)
after=$(jq -r .aggregate "$work/records/$zone-changed.json" 2>/dev/null || echo)
if [ -n "$before" ] && [ -n "$after" ] && [ "$after" != "$before" ]; then
	pass "$zone: the signed evidence differs ($before -> $after)"
else
	fail "$zone: the signed evidence did not change"
fi
if rejected "$zone" "$original" "$zone-changed-vs-original" "component atls-gateway: verified [0-9a-f]+, configured [0-9a-f]+"; then
	pass "$zone: the changed evidence is refused against the original configuration (its verified template hash is not the configured one)"
else
	fail "$zone: the changed evidence was not refused for its measurement against the original configuration"
	cat "$work/logs/check-$zone-changed-vs-original.log" >&2 || true
fi

# --- 3. reference values from outside the pipeline's CA -------------------------------------
say "signing $zone's reference values with a key outside the metadata CA"
stop_cmcd "$zone"
provision_zone "$zone" "$original" rogue rogue-ca "$(now)"
start_cmcd "$zone"
if rejected "$zone" "$original" "$zone-rogue" 'verified as "fail"'; then
	pass "$zone: metadata signed outside the metadata CA is refused"
else
	fail "$zone: metadata from an untrusted signer was not refused as a failed verification"
	cat "$work/logs/check-$zone-rogue.log" >&2 || true
fi
# The control: the same report passes when its signer's CA is the one trusted, so the refusal
# above is the CA's doing and nothing else.
if startup_check "$zone" "$original" "$zone-rogue-own-ca" rogue-ca; then
	pass "$zone: the same metadata passes against its own signer's CA (control)"
else
	fail "$zone: the rogue-signed metadata fails even against its own CA; the refusal above proves nothing"
	cat "$work/logs/check-$zone-rogue-own-ca.log" >&2 || true
fi

jq -n --arg date "$t0" --arg cmc "$cmc_version" --arg commit "$(git rev-parse HEAD)" \
	--argjson failures "$failures" '{date: $date, cmc_version: $cmc, commit: $commit, failures: $failures}' \
	>"$work/records/summary.json"
if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed" >&2
	exit 1
fi
say "all checks passed"
