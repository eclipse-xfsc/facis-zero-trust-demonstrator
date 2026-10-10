#!/usr/bin/env bash
# Cases for verify.sh against local NSD servers, each serving a variant of one zone that breaks one
# thing the inspector must catch: a DS with the right key tag and a wrong digest, owner or algorithm; a
# DS recorded for a zone a server answers unsigned; a secondary with the same serial and another NS
# set; a resolver that answers the pointer but not the URI at its target. Then the delegation path: a
# signed parent zone that delegates the zone with the right DS, a DS with the right key tag and a
# wrong digest, a stale DS next to the right one, no DS, and a DS above an unsigned server, resolved
# through a validating resolver anchored on the parent. The DS records the cases start from are
# ldns-key2ds's, so the inspector's own DS computation is checked against another one.
#
# Linux, as root: the servers listen on 127.0.53.1-7 port 53, the port verify.sh queries, and the
# parent's server name goes into /etc/hosts for the run (restored on exit). Needs nsd, ldnsutils,
# unbound, dig and python3; the README runs it in a throwaway container.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for tool in nsd ldns-keygen ldns-signzone ldns-key2ds unbound dig python3; do
  command -v "$tool" >/dev/null || { echo "missing $tool: run it as the README shows" >&2; exit 2; }
done
[ "$(id -u)" = 0 ] || { echo "needs root: the servers listen on port 53" >&2; exit 2; }
work="$(mktemp -d)"
cleanup() {
  for p in "$work"/s*/nsd.pid "$work/r/unbound.pid"; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
  [ -f "$work/hosts" ] && cat "$work/hosts" > /etc/hosts
  rm -rf "$work"
}
trap cleanup EXIT
zone=trust.ztd.test
cd "$work"

# the zone as the zone manager lays it out: in-zone name servers, the pointer, the URI at its target
cat > base <<EOF
\$ORIGIN $zone.
\$TTL 3600
@                  SOA  ns1 hostmaster 1791417600 28800 7200 604800 3600
@                  NS   ns1
@                  NS   ns2
ns1                A    127.0.53.1
ns2                A    127.0.53.2
ns3                A    127.0.53.3
_scheme._trust     0 PTR _scheme._trust.fw.$zone.
_scheme._trust.fw  0 URI 10 1 "did:web:$zone:fw"
EOF
ksk=$(ldns-keygen -a ECDSAP256SHA256 -k "$zone"); zsk=$(ldns-keygen -a ECDSAP256SHA256 "$zone")
sign() { ldns-signzone -f "$2" "$1" "$ksk" "$zsk"; }   # NSEC, as the zone manager signs
sign base signed
sed 's/^@ *NS *ns2$/@ NS ns3/' base > other-ns && sign other-ns signed-other-ns
grep -v ' URI ' base > no-uri && sign no-uri signed-no-uri
sed 's/127\.0\.53\.[12]$/127.0.53.4/' base > unsigned   # its own name servers point at it

stop() { # stop <pid file>: the daemon is gone and its port free when this returns
  local pid
  pid=$(cat "$1" 2>/dev/null) || return 0
  kill "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
  rm -f "$1"
}
serve() { # serve <last octet of 127.0.53.x> <zone file> [zone name]
  local dir="$work/s$1" name=${3:-$zone}
  stop "$dir/nsd.pid"
  mkdir -p "$dir" && cp "$2" "$dir/zone"
  cat > "$dir/nsd.conf" <<EOF
server:
  ip-address: 127.0.53.$1
  port: 53
  do-ip6: no
  username: ""
  chroot: ""
  zonesdir: "$dir"
  database: ""
  zonelistfile: "$dir/zone.list"
  xfrdfile: "$dir/xfrd.state"
  pidfile: "$dir/nsd.pid"
  logfile: "$dir/nsd.log"
  server-count: 1
remote-control:
  control-enable: no
zone:
  name: $name
  zonefile: "$dir/zone"
EOF
  nsd -c "$dir/nsd.conf"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -n "$(dig +short +norec +time=1 +tries=1 SOA "$name" "@127.0.53.$1")" ] && return 0
    sleep 0.5
  done
  echo "the server on 127.0.53.$1 did not come up" >&2; cat "$dir/nsd.log" >&2; exit 1
}
serve 1 signed            # ns1
serve 2 signed            # ns2, a healthy secondary
serve 3 signed-other-ns   # a secondary with the same serial and another NS set
serve 4 unsigned          # an unsigned replacement server
serve 5 signed-no-uri     # stands in for a resolver that answers the pointer but not the URI

ds1=$(ldns-key2ds -n -1 "$ksk.key"); ds2=$(ldns-key2ds -n -2 "$ksk.key"); ds4=$(ldns-key2ds -n -4 "$ksk.key")
tag=$(echo "$ds2" | awk '{print $5}'); digest=$(echo "$ds2" | awk '{print $NF}')
[ "${digest: -1}" = 0 ] && flip=1 || flip=0
bad_digest=$(echo "$ds2" | awk -v d="${digest%?}$flip" '{$NF=d; print}')
bad_owner=$(echo "$ds2" | awk -v o="other.$zone." '{$1=o; print}')
bad_alg=$(echo "$ds2" | awk '{$6=8; print}')
# as dig prints a DS: uppercase, the digest in two pieces
as_dig=$(echo "$ds2" | awk '{print toupper($1), $2, $3, $4, $5, $6, $7, toupper(substr($8,1,32)), toupper(substr($8,33))}')
healthy="SERVERS=ns1.$zone=127.0.53.1 ns2.$zone=127.0.53.2"
unsigned="SERVERS=ns1.$zone=127.0.53.4 ns2.$zone=127.0.53.4"
ds_pass="PASS: the DS recorded for publication (EXPECT_DS) is the DS of a KSK every server serves"
ds_fail="**FAIL**: the DS recorded for publication (EXPECT_DS) is the DS of a KSK every server serves"

failures=0
run() { # run <case> <want exit 0|1> <lines the evidence must hold, one per line> [VAR=value ...]
  local name=$1 want=$2 lines=$3 got=0 missing=""
  shift 3
  env ZONE="$zone" RESOLVERS=127.0.53.1 OUT="$work/evidence.md" "$@" bash "$here/verify.sh" >/dev/null || got=1
  while IFS= read -r l; do grep -qF -- "$l" "$work/evidence.md" || missing="$missing
      missing: $l"; done <<<"$lines"
  if [ "$got" = "$want" ] && [ -z "$missing" ]; then echo "ok    $name"; else
    echo "FAIL  $name (exit $got, want $want)$missing"; sed 's/^/      | /' "$work/evidence.md"; failures=$((failures + 1))
  fi
}

run "healthy zone, the DS as ldns-key2ds writes it" 0 "$ds_pass
PASS: ns2.$zone. serves the URI record at pointer target _scheme._trust.fw.$zone.
PASS: resolver 127.0.53.1 resolves the URI record at pointer target _scheme._trust.fw.$zone." "$healthy" "EXPECT_DS=$ds2"
run "SHA-1, SHA-256 and SHA-384 records together" 0 "$ds_pass" "$healthy" "EXPECT_DS=$ds1,$ds2,$ds4"
run "the DS as dig prints it" 0 "$ds_pass" "$healthy" "EXPECT_DS=$as_dig"
run "right key tag, wrong digest" 1 "$ds_fail" "$healthy" "EXPECT_DS=$bad_digest"
run "right key tag and digest, another owner" 1 "$ds_fail" "$healthy" "EXPECT_DS=$bad_owner"
run "right key tag and digest, another algorithm" 1 "$ds_fail" "$healthy" "EXPECT_DS=$bad_alg"
run "one good record and one with a wrong digest" 1 "$ds_pass
$ds_fail" "$healthy" "EXPECT_DS=$ds2
$bad_digest"
run "a bare key tag passes, as the weaker check it is" 0 "PASS: key tag $tag recorded for publication (EXPECT_DS) is a KSK every server serves — the tag only" "$healthy" "EXPECT_DS=$tag"
run "a bare key tag of another key" 1 "**FAIL**: key tag $((tag ^ 1)) recorded" "$healthy" "EXPECT_DS=$((tag ^ 1))"
run "EXPECT_DS that is neither" 1 "**FAIL**: EXPECT_DS holds DS records or key tags" "$healthy" "EXPECT_DS=see the zone manager log"
run "unsigned zone, no DS recorded" 0 "INFO: the zone is not signed
INFO: the parent was not asked (SERVERS)" "$unsigned" RESOLVERS=127.0.53.4
run "unsigned replacement server, DS recorded" 1 "INFO: the zone is not signed
$ds_fail" "$unsigned" RESOLVERS=127.0.53.4 "EXPECT_DS=$ds2"
run "one signed and one unsigned server, DS recorded" 1 "**FAIL**: every authoritative server serves the same key-signing keys
$ds_fail" "SERVERS=ns1.$zone=127.0.53.1 ns2.$zone=127.0.53.4" "EXPECT_DS=$ds2"
run "a secondary with the same serial and another NS set" 1 "PASS: every authoritative server serves the same SOA serial
PASS: ns1.$zone. (127.0.53.1) serves inside the zone the NS set SERVERS names
**FAIL**: ns2.$zone. (127.0.53.3) serves inside the zone the NS set SERVERS names" "SERVERS=ns1.$zone=127.0.53.1 ns2.$zone=127.0.53.3"
run "a resolver that answers the pointer but not the URI" 1 "PASS: resolver 127.0.53.5 resolves the pointer
**FAIL**: resolver 127.0.53.5 resolves the URI record at pointer target _scheme._trust.fw.$zone." "$healthy" "RESOLVERS=127.0.53.1 127.0.53.5"
run "the same with REQUIRE_POINTER=0: recorded, not failed" 0 "INFO: resolver 127.0.53.5 resolves the URI record" "$healthy" "RESOLVERS=127.0.53.1 127.0.53.5" REQUIRE_POINTER=0

# The delegation path. A signed parent zone on 127.0.53.6 delegates the zone, and a validating resolver
# on 127.0.53.7 is anchored on the parent's key, as the internet's resolvers are anchored on the root.
# verify.sh finds the parent's server by the name the parent's NS record gives, hence /etc/hosts.
parent=${zone#*.}
pksk=$(ldns-keygen -a ECDSAP256SHA256 -k "$parent"); pzsk=$(ldns-keygen -a ECDSAP256SHA256 "$parent")
cp /etc/hosts "$work/hosts" && printf '127.0.53.6 ns.%s ns.%s.\n' "$parent" "$parent" >> /etc/hosts
stale=$(ldns-key2ds -n -2 "$(ldns-keygen -a ECDSAP256SHA256 -k "$zone").key")   # a key the zone does not serve
resolver() { # (re)start the validating resolver, cache empty
  local dir="$work/r"
  stop "$dir/unbound.pid"
  mkdir -p "$dir"
  cat > "$dir/unbound.conf" <<EOF
server:
  interface: 127.0.53.7
  port: 53
  do-ip6: no
  username: ""
  chroot: ""
  directory: "$dir"
  pidfile: "$dir/unbound.pid"
  use-syslog: no
  logfile: "$dir/unbound.log"
  do-not-query-localhost: no
  local-zone: "test." nodefault
  trust-anchor: "$(ldns-key2ds -n -2 "$pksk.key" | awk '{print $1, "DS", $5, $6, $7, $8}')"
stub-zone:
  name: "$parent"
  stub-addr: 127.0.53.6
stub-zone:
  name: "."
  stub-addr: 127.0.53.6
EOF
  unbound -c "$dir/unbound.conf"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -n "$(dig +short +time=1 +tries=1 SOA "$parent" @127.0.53.7)" ] && return 0
    sleep 0.5
  done
  echo "the resolver did not come up" >&2; cat "$dir/unbound.log" >&2; exit 1
}
parent_up() { # parent_up <ns1 address> <ns2 address> [DS records at the parent, one per line]
  { cat <<EOF
\$ORIGIN $parent.
\$TTL 3600
@          SOA  ns hostmaster 1791417600 28800 7200 604800 3600
@          NS   ns
ns         A    127.0.53.6
${zone%%.*}      NS   ns1.${zone%%.*}
${zone%%.*}      NS   ns2.${zone%%.*}
ns1.${zone%%.*}  A    $1
ns2.${zone%%.*}  A    $2
EOF
    printf '%s\n' "${3:-}"; } > parent.zone
  ldns-signzone -f parent.signed parent.zone "$pksk" "$pzsk"
  serve 6 parent.signed "$parent"
  resolver
}
via="RESOLVERS=127.0.53.7"
parent_up 127.0.53.1 127.0.53.2 "$ds2"
run "delegated and signed, the DS at the parent is the key's" 0 "PASS: the parent's server ns.$parent. delegates $zone
PASS: the delegation names exactly the expected servers
PASS: glue address for in-zone server ns2.$zone. is in the referral
PASS: a DS at the parent is the DS of a KSK every server serves
status NOERROR, flags: qr rd ra ad
PASS: resolver 127.0.53.7 resolves the URI record at pointer target _scheme._trust.fw.$zone.
PASS: resolver 127.0.53.7 does not reject the zone as bogus" "$via" "EXPECT_NS=ns1.$zone ns2.$zone" "EXPECT_DS=$ds2"
run "the delegation names other servers than expected" 1 "**FAIL**: the delegation names exactly the expected servers" "$via" "EXPECT_NS=ns1.$zone ns3.$zone"
parent_up 127.0.53.1 127.0.53.2 "$bad_digest"
run "the DS at the parent: right key tag, wrong digest" 1 "**FAIL**: a DS at the parent is the DS of a KSK every server serves
**FAIL**: resolver 127.0.53.7 does not reject the zone as bogus" "$via"
parent_up 127.0.53.1 127.0.53.2 "$ds2
$stale"
run "a DS of another key next to the right one, as in a key rollover" 0 "PASS: a DS at the parent is the DS of a KSK every server serves
INFO: DS at the parent that matches no served KSK" "$via"
parent_up 127.0.53.1 127.0.53.2
run "delegated without a DS" 0 "INFO: DS at the parent: none
INFO: no DS at the parent" "$via"
parent_up 127.0.53.4 127.0.53.4 "$ds2"
run "a DS at the parent above an unsigned server" 1 "**FAIL**: no DS at the parent for an unsigned zone" "$via"
[ "$failures" -eq 0 ]
