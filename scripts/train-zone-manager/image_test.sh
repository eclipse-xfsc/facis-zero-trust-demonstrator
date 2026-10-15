#!/usr/bin/env bash
# The TRAIN DNS zone manager image (deployment/docker/train-zone-manager), exercised in Docker
# without a cluster. Five cases, each with its positive and its negative half, one per defect the
# upstream image ships with (docs/train-dns.md, "Operating the zone manager"):
#
#   1 pin and patches   built from the pinned upstream commit; a patch that no longer applies fails the build
#   2 first start       creates the zone, prints the DS once, answers over UDP and TCP; the upstream base
#                       cannot import ldns (issue #39)
#   3 restart           serves the same zone and keys again; the readiness command refuses a server
#                       with no zone (issue #40)
#   4 resign            moves the signature dates and the serial; a wrong database path fails loudly
#                       (issue #41)
#   5 gates             the image is linux/amd64 (ZT-13); the scan and signing gates are the pipeline's
#
# A FAIL fails the script. Lines of evidence go to stdout and, when EVIDENCE is set, to that file.
#
#   scripts/train-zone-manager/image_test.sh              builds the image, runs every case
#   IMAGE=<ref>   use an image already built       PORT=<n>  host port for the queries (default 15353)
#   EVIDENCE=<f>  also write the evidence there    KEEP=1    leave the container and volume behind
#
# Needs docker and dig. Builds pull from Docker Hub and GitHub.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
ctx=deployment/docker/train-zone-manager
dockerfile="$ctx/Dockerfile"
IMAGE=${IMAGE:-}
PORT=${PORT:-15353}
zone=trust.ztd.test
name="zm-image-test-$$"
volume="$name-data"
# The upstream base tag as it resolves today (Debian 13), for the negative half of case 2. Pinned so
# the case stays what it was observed to be; when Debian 13 gets an ldns binding for Python 3.11 the
# case fails, which is the signal that the base-image reason for this build has gone.
upstream_base="python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
work="$(mktemp -d)"
failed=0

say() { printf '%s\n' "$*"; [ -n "${EVIDENCE:-}" ] && printf '%s\n' "$*" >> "$EVIDENCE" || true; }
pass() { say "PASS  $*"; }
fail() { say "FAIL  $*"; failed=1; }
note() { say "      $*"; }

cleanup() {
  if [ -n "${KEEP:-}" ]; then
    echo "kept: container $name, volume $volume, work dir $work"
    return
  fi
  docker rm -f "$name" "$name-nozone" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

for tool in docker dig; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
[ -n "${EVIDENCE:-}" ] && : > "$EVIDENCE"
say "# TRAIN DNS zone manager image: $(date -u +%FT%TZ)"

# ---------------------------------------------------------------- 1 pin and patches
pinned=$(sed -n 's/^ARG UPSTREAM_COMMIT=//p' "$dockerfile")
if [ -z "$IMAGE" ]; then
  IMAGE="ztd/train-zone-manager:test"
  say "building $IMAGE from $dockerfile"
  docker build --platform linux/amd64 -q -f "$dockerfile" -t "$IMAGE" . >/dev/null
fi
revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")
if [ "$revision" = "$pinned" ] && [ -n "$pinned" ]; then
  pass "1a the image records the pinned upstream commit $pinned"
else
  fail "1a image revision label '$revision' is not the pinned commit '$pinned'"
fi
# Negative: a context whose first patch no longer matches the upstream source must fail at `git apply`.
mkdir -p "$work/badctx/$ctx"
cp -r "$ctx"/. "$work/badctx/$ctx/"
first_patch=$(ls "$work/badctx/$ctx"/patches/*.patch | head -1)
sed -i 's|^ mv /tmp/zonemgr.conf /etc/nsd/nsd.conf.d/zonemgr.conf$| mv /tmp/some-other-file.conf /etc/nsd/nsd.conf.d/zonemgr.conf|' "$first_patch"
if docker build --platform linux/amd64 --target source --progress=plain -f "$work/badctx/$dockerfile" "$work/badctx" >"$work/badbuild.log" 2>&1; then
  fail "1b a build with a patch that does not apply succeeded"
else
  if grep -q -E "error: patch failed|does not apply" "$work/badbuild.log"; then
    pass "1b a patch that no longer applies fails the build at git apply"
  else
    fail "1b the build failed, but not at git apply:"; tail -5 "$work/badbuild.log" | sed 's/^/      /'
  fi
fi

# ---------------------------------------------------------------- 2 first start
printf 'ISSUER_URL = "https://issuer.invalid"\nCLIENT_ID = "none"\nALLOW_UNSAFE_SSL = "false"\n' > "$work/auth.conf"
docker volume create "$volume" >/dev/null
start_container() {
  docker run -d --name "$name" \
    -v "$volume:/var/lib/zonemgr" -v "$work/auth.conf:/usr/lib/zonemgr/auth.conf:ro" \
    -p "127.0.0.1:$PORT:53/udp" -p "127.0.0.1:$PORT:53/tcp" \
    -e TF_DOMAIN_NAME="$zone" -e TF_DOMAIN_IP=192.0.2.53 \
    -e PRIMARY_SERVER_NSD="ns1.$zone" -e PRIMARY_SERVER_IP=192.0.2.53 \
    -e SECONDARY_SERVER_1_NSD="ns2.$zone" -e SECONDARY_SERVER_1_IP=192.0.2.53 \
    -e SECONDARY_SERVER_2_NSD="ns3.$zone" -e SECONDARY_SERVER_2_IP=192.0.2.53 \
    "$IMAGE" >/dev/null
}
# waits for zone-ready inside the container; prints the seconds it took, or fails
wait_ready() {
  local t0 now
  t0=$(date +%s)
  while :; do
    if docker exec "$name" zone-ready >/dev/null 2>&1; then
      now=$(date +%s); echo $((now - t0)); return 0
    fi
    now=$(date +%s)
    if [ "$(docker inspect --format '{{.State.Status}}' "$name")" != running ] || [ $((now - t0)) -ge 60 ]; then
      return 1
    fi
    sleep 1
  done
}
q() { dig @127.0.0.1 -p "$PORT" +norecurse +time=3 +tries=1 +noall +comments +answer "$@"; }
status_of() { grep -o 'status: [A-Z]*' | head -1 | cut -d' ' -f2; }
aa_of() { grep -q '^;; flags: qr aa' && echo aa || echo noaa; }

start_container
if secs=$(wait_ready); then
  pass "2a the container is ready $secs s after its first start"
else
  fail "2a the container did not become ready (state $(docker inspect --format '{{.State.Status}}' "$name"))"
  docker logs "$name" 2>&1 | tail -15 | sed 's/^/      /'
fi
ds_lines=$(docker logs "$name" 2>&1 | awk '$4=="DS"' || true)
ds_count=$(printf '%s' "$ds_lines" | grep -c . || true)
if [ "$ds_count" = 1 ]; then pass "2b the DS is printed once at first start: $ds_lines"; else fail "2b expected one DS line in the log, found $ds_count"; fi
udp=$(q "$zone" SOA); tcp=$(q +tcp "$zone" SOA)
if [ "$(printf '%s' "$udp" | status_of)" = NOERROR ] && [ "$(printf '%s' "$udp" | aa_of)" = aa ]; then
  pass "2c the SOA is answered authoritatively over UDP"
else fail "2c no authoritative SOA over UDP: $(printf '%s' "$udp" | grep -E 'status|flags' | tr '\n' ' ')"; fi
if [ "$(printf '%s' "$tcp" | status_of)" = NOERROR ] && [ "$(printf '%s' "$tcp" | aa_of)" = aa ]; then
  pass "2d the SOA is answered authoritatively over TCP"
else fail "2d no authoritative SOA over TCP: $(printf '%s' "$tcp" | grep -E 'status|flags' | tr '\n' ' ')"; fi
serial_first=$(printf '%s' "$udp" | awk '$4=="SOA"{print $7}')
note "SOA serial at first start: $serial_first"
# Negative: the upstream base cannot import the ldns binding (issue #39).
if docker run --rm --platform linux/amd64 "$upstream_base" bash -c \
  'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends python3-ldns >/dev/null 2>&1 && PYTHONPATH=/usr/lib/python3/dist-packages python3 -c "import ldns"' >"$work/upstream.log" 2>&1; then
  fail "2e the upstream base imports ldns now; the base-image reason for this build may be gone"
else
  if grep -q "_ldns" "$work/upstream.log"; then
    pass "2e the upstream base (python:3.11, Debian 13) fails at import ldns: $(grep -o "No module named '_ldns'" "$work/upstream.log" | head -1)"
  else
    fail "2e the upstream base failed, but not at import ldns:"; tail -3 "$work/upstream.log" | sed 's/^/      /'
  fi
fi

# ---------------------------------------------------------------- 3 restart
keys_before=$(dig @127.0.0.1 -p "$PORT" +norecurse +time=3 +tries=1 +short "$zone" DNSKEY | sort)
docker restart "$name" >/dev/null
if secs=$(wait_ready); then
  pass "3a the container is ready $secs s after a restart with the volume kept"
else
  fail "3a the container did not become ready after a restart"
  docker logs "$name" 2>&1 | tail -15 | sed 's/^/      /'
fi
after=$(q "$zone" SOA)
keys_after=$(dig @127.0.0.1 -p "$PORT" +norecurse +time=3 +tries=1 +short "$zone" DNSKEY | sort)
if [ "$(printf '%s' "$after" | status_of)" = NOERROR ] && [ "$(printf '%s' "$after" | aa_of)" = aa ]; then
  pass "3b the zone is served again after the restart"
else fail "3b the zone is not served after the restart"; fi
if [ -n "$keys_before" ] && [ "$keys_before" = "$keys_after" ]; then
  pass "3c the DNSKEY set is unchanged across the restart ($(printf '%s\n' "$keys_after" | grep -c .) keys)"
else fail "3c the DNSKEY set changed across the restart"; fi
# Negative: NSD running with no zone configured is not ready (what every start of the unpatched upstream looks like).
docker run -d --name "$name-nozone" -e TF_DOMAIN_NAME="$zone" "$IMAGE" bash -c 'service nsd start >/dev/null && sleep infinity' >/dev/null
sleep 3
if docker exec "$name-nozone" zone-ready >"$work/nozone.log" 2>&1; then
  fail "3d zone-ready reported ready on a server with no zone"
else
  pass "3d zone-ready refuses a server with no zone: $(cat "$work/nozone.log")"
fi
docker rm -f "$name-nozone" >/dev/null

# ---------------------------------------------------------------- 4 resign
rrsig() { dig @127.0.0.1 -p "$PORT" +norecurse +dnssec +time=3 +tries=1 +noall +answer "$zone" SOA | awk '$4=="RRSIG" && $5=="SOA"{print $9, $10}' | head -1; }
read -r exp_before inc_before <<<"$(rrsig)"
serial_before=$(q "$zone" SOA | awk '$4=="SOA"{print $7}')
sleep 1
if docker exec "$name" dns-zone-manager-server --database sqlite:////var/lib/zonemgr/zones.db resign >"$work/resign.log" 2>&1; then
  pass "4a the resign command exits 0"
else
  fail "4a the resign command failed:"; tail -5 "$work/resign.log" | sed 's/^/      /'
fi
sleep 2
read -r exp_after inc_after <<<"$(rrsig)"
serial_after=$(q "$zone" SOA | awk '$4=="SOA"{print $7}')
if [ -n "$exp_before" ] && [ -n "$exp_after" ] && [ "$exp_after" -gt "$exp_before" ] && [ "$inc_after" -gt "$inc_before" ]; then
  pass "4b the SOA signature moved: expiration $exp_before -> $exp_after, inception $inc_before -> $inc_after"
else fail "4b the SOA signature did not move (before $exp_before/$inc_before, after $exp_after/$inc_after)"; fi
if [ -n "$serial_before" ] && [ "$serial_after" -gt "$serial_before" ]; then
  pass "4c the SOA serial increased: $serial_before -> $serial_after"
else fail "4c the SOA serial did not increase ($serial_before -> $serial_after)"; fi
# Negative: a resign pointed at a database that does not exist must fail, not quietly do nothing.
if docker exec "$name" dns-zone-manager-server --database sqlite:////tmp/missing.db resign >"$work/missing.log" 2>&1; then
  fail "4d a resign against a missing database exited 0"
else
  pass "4d a resign against a missing database fails (exit $(docker exec "$name" sh -c 'dns-zone-manager-server --database sqlite:////tmp/missing.db resign >/dev/null 2>&1; echo $?'))"
fi

# ---------------------------------------------------------------- 5 gates
platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")
if [ "$platform" = linux/amd64 ]; then pass "5a the image is $platform (ZT-13)"; else fail "5a the image is $platform, ZT-13 requires linux/amd64"; fi
note "5b the vulnerability scan and the signing are the pipeline's gates (ci.yml 'Image build and scan', release.yml)"

say "# result: $([ $failed = 0 ] && echo 'all cases passed' || echo 'at least one case FAILED')"
exit $failed
