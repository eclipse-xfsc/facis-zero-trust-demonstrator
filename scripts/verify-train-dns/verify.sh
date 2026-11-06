#!/usr/bin/env bash
# Evidence that the trust-framework DNS zone is delegated, answers from every authoritative server,
# carries the TRAIN pointer records, resolves through recursive resolvers and has a coherent DNSSEC
# state. Every step appends to evidence.md next to this script; the exit status is non-zero if any
# check failed. Run it from outside the clusters as it is; run it inside a cluster with RESOLVERS set
# to the cluster resolver to prove resolution from that cluster (README).
#
#   ZONE             the trust-framework zone, e.g. trust.example.org   (required)
#   RESOLVERS        recursive resolvers to resolve through, space-separated
#                    (default: the system resolver plus 1.1.1.1 and 9.9.9.9, which validate DNSSEC)
#   WHERE            where this run happens, for the evidence header (default: outside the clusters)
#   EXPECT_NS        name servers the delegation must name, space-separated (default: not checked)
#   SERVERS          "name=ip ..." — query these authoritative servers directly instead of the ones a
#                    delegation names; for a server that exists before the delegation does
#   EXPECT_DS        the DS to be published at the parent, as the zone manager printed it (several
#                    records comma- or newline-separated). Each record is compared in full — owner,
#                    algorithm, digest type, digest — with the DS computed from the key-signing key
#                    every server serves, signed zone or not, so a key change shows before the DS is
#                    live. A bare key tag is accepted as a weaker check that compares the tag only.
#   REQUIRE_POINTER  1: the _scheme._trust pointer and its URI must exist; 0: record what is there
#                    (default: 1; use 0 for a zone that is live but has no framework registered yet)
#   MIN_SIG_DAYS     days of signature validity still required when the zone is signed (default: 7)
#   OUT              evidence file (default: evidence.md next to this script)
#
# Every check is "<test>; check $? <title>": the status of the test is what the check records.
# Needs dig and python3; uses delv for a validation verdict when it is installed with crypto.
# Unquoted expansions of record lists are deliberate: they collapse dig's one-per-line output.
# shellcheck disable=SC2319,SC2086,SC2116,SC2016
set -uo pipefail
cd "$(dirname "$0")" || exit 1
ZONE=${ZONE:?set ZONE to the trust-framework zone}
ZONE=${ZONE%.}
RESOLVERS=${RESOLVERS:-"system 1.1.1.1 9.9.9.9"}
WHERE=${WHERE:-outside the clusters}
EXPECT_NS=${EXPECT_NS:-}
SERVERS=${SERVERS:-}
EXPECT_DS=${EXPECT_DS:-}
REQUIRE_POINTER=${REQUIRE_POINTER:-1}
MIN_SIG_DAYS=${MIN_SIG_DAYS:-7}
OUT=${OUT:-evidence.md}
POINTER="_scheme._trust.$ZONE"
first=${RESOLVERS%% *}
failures=0

say() { printf '%s\n' "$@" >> "$OUT"; }
code() { [ -n "$*" ] || return 0; say '' '```'; say "$@"; say '```' ''; }
check() { # check <PASS-condition exit status> <title> <detail...>
  local status=$1; shift; local title=$1; shift
  if [ "$status" -eq 0 ]; then say "- PASS: $title"; else say "- **FAIL**: $title"; failures=$((failures+1)); fi
  [ $# -gt 0 ] && say "  $*"
  return 0
}
# a check that only records when REQUIRE_POINTER=0
check_pointer() { if [ "$REQUIRE_POINTER" = 1 ]; then check "$@"; else shift; say "- INFO: $1" "  $2"; fi; }
# dig with short timeouts; "system" means the resolver of the host the script runs on
d() { # d <server|system> <dig args...>
  local at=$1; shift
  if [ "$at" = system ]; then dig +time=3 +tries=1 "$@"; else dig +time=3 +tries=1 "$@" "@$at"; fi
}
status_of() { grep -o 'status: [A-Z]*' | head -1 | cut -d' ' -f2; }
flags_of() { grep -o '^;; flags:[^;]*' | head -1 | sed 's/^;; flags://'; }
lower() { tr '[:upper:]' '[:lower:]'; }
zone_lc=$(printf '%s' "$ZONE" | lower)
in_zone() { case "$(printf '%s' "$1" | lower | sed 's/\.$//')" in "$zone_lc"|*".$zone_lc") return 0;; esac; return 1; }
# the URI records in a dig answer, as "<priority> <weight> <target>", on one line
uri_of() { awk '$4=="URI" {$1=$2=$3=$4=""; sub(/^ +/, ""); print}' | tr '\n' ' ' | sed 's/ *$//'; }
days_until() { # days_until <YYYYMMDDHHMMSS>
  python3 -c "import sys,datetime as d;e=d.datetime.strptime(sys.argv[1],'%Y%m%d%H%M%S').replace(tzinfo=d.timezone.utc);print(int((e-d.datetime.now(d.timezone.utc)).total_seconds()//86400))" "$1"
}
norm_set() { printf '%s\n' $1 | lower | sed 's/\.$//' | sort -u | tr '\n' ' '; }
# The DS of every key-signing key in a DNSKEY answer (dig output on stdin), computed as RFC 4034
# §5.1.4 defines it: the digest of the owner name in canonical wire form followed by the DNSKEY RDATA,
# with the key tag of Appendix B. One line per key and digest type (1 SHA-1, 2 SHA-256, 4 SHA-384),
# in the form ds_norm writes, so a recorded DS and a computed one compare as strings.
ds_of_keys() {
  python3 -c '
import base64, hashlib, sys
for f in (l.split(";")[0].split() for l in sys.stdin):
    if len(f) < 8 or f[3] != "DNSKEY" or int(f[4]) & 0x101 != 0x101:
        continue
    rdata = int(f[4]).to_bytes(2, "big") + bytes([int(f[5]), int(f[6])]) + base64.b64decode("".join(f[7:]))
    tag = sum(b if i % 2 else b << 8 for i, b in enumerate(rdata))
    owner = f[0].lower().rstrip(".")
    wire = b"".join(bytes([len(x)]) + x.encode() for x in owner.split(".") if x) + b"\0"
    for dt, h in ((1, hashlib.sha1), (2, hashlib.sha256), (4, hashlib.sha384)):
        print(owner, (tag + (tag >> 16)) & 0xFFFF, int(f[6]), dt, h(wire + rdata).hexdigest())'
}
# DS records as text (dig output, the zone manager's print-out, or bare key tags), one per line or
# comma-separated, as "<owner> <tag> <algorithm> <digest type> <digest>" — lowercase, the digest in one
# piece, the zone as owner when none is given — or "<tag>" for a bare key tag, or "? <text>".
ds_norm() {
  tr ',' '\n' | python3 -c '
import sys
zone = sys.argv[1].lower().rstrip(".")
for line in sys.stdin:
    f = [x for x in line.split(";")[0].split() if x not in ("(", ")")]
    if not f:
        continue
    up = [x.upper() for x in f]
    owner, rd = zone, f
    if "DS" in up:
        i = up.index("DS")
        rd = f[i + 1:]
        if i > 0 and not f[0].isdigit() and up[0] not in ("IN", "CH", "HS"):
            owner = f[0].lower().rstrip(".")
    if len(rd) == 1 and rd[0].isdigit():
        print(int(rd[0]))
    elif len(rd) >= 4 and all(x.isdigit() for x in rd[:3]):
        print(owner, int(rd[0]), int(rd[1]), int(rd[2]), "".join(rd[3:]).lower())
    else:
        print("?", line.strip())' "$ZONE"
}
# IPv4 of a name server: the glue the parent handed out, else what the first resolver says
addr_of() { # addr_of <ns name>
  local ip
  ip=$(printf '%s\n' "$glue" | grep -i "^$1 " | awk '{print $2}' | grep -E '^[0-9.]+$' | head -1)
  [ -n "$ip" ] || ip=$(d "$first" +short A "$1" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
  printf '%s' "$ip"
}
# the first comment line of a delv run: "fully validated", "unsigned answer", "resolution failed: ..."
delv_verdict() { # delv_verdict <server|system> <type> <name>
  command -v delv >/dev/null || return 0
  local v
  if [ "$1" = system ]; then v=$(delv "$2" "$3" 2>&1); else v=$(delv "@$1" "$2" "$3" 2>&1); fi
  v=$(printf '%s\n' "$v" | grep '^;' | head -1 | sed 's/^;* *//')
  case "$v" in *"no crypto support"*|"") ;; *) say "  delv: $v";; esac
}

: > "$OUT"
say "# Trust-framework DNS evidence for \`$ZONE\` ($(date -u +%Y-%m-%dT%H:%M:%SZ))" ''
say "Run from $WHERE; resolvers: \`$RESOLVERS\`; dig $(dig -v 2>&1 | head -1 | sed 's/^DiG //')." ''
say 'Authoritative queries are sent without recursion (`+norec`) straight to the servers the delegation names, so an answer there proves the server itself, not a cache.' ''

say '' '## 1. Delegation at the parent' ''
pns=""; deleg=""; ns_names=""; glue=""; parent_ds=""; ns_src="the delegation"
if [ -n "$SERVERS" ]; then
  say "- INFO: servers given directly (SERVERS); the delegation at the parent is not looked up"
  for pair in $SERVERS; do ns_names="$ns_names ${pair%%=*}."; glue="$glue
${pair%%=*}. ${pair#*=}"; done
  say "  $(echo $ns_names)"
  parent=""; ns_src="SERVERS"
else
parent=${ZONE#*.}; [ "$parent" = "$ZONE" ] && parent=""
while [ -n "$parent" ]; do
  [ -n "$(d "$first" +short NS "$parent" 2>/dev/null)" ] && break
  [ "$parent" = "${parent#*.}" ] && parent=""
  parent=${parent#*.}
done
[ -n "$parent" ]; check $? "a parent zone with name servers exists above $ZONE" "parent: ${parent:-none found}"
fi
if [ -n "$parent" ]; then
  # the first parent server that returns a referral; the parent servers should agree, so the one used is recorded
  for cand in $(d "$first" +short NS "$parent"); do
    out=$(d "$cand" +norec +noall +answer +authority +additional NS "$ZONE" 2>/dev/null)
    [ -n "$pns" ] || pns=$cand
    if [ -n "$(printf '%s\n' "$out" | awk -v z="$ZONE." 'tolower($1)==tolower(z) && $4=="NS"')" ]; then pns=$cand; deleg=$out; break; fi
  done
  ns_names=$(printf '%s\n' "$deleg" | awk -v z="$ZONE." 'tolower($1)==tolower(z) && $4=="NS" {print $5}')
  [ -n "$ns_names" ]; check $? "the parent's server ${pns:-?} delegates $ZONE (NS records in its referral)" "NS: $(echo $ns_names)"
  code "$deleg"
  if [ -n "$EXPECT_NS" ]; then
    [ "$(norm_set "$ns_names")" = "$(norm_set "$EXPECT_NS")" ]; check $? "the delegation names exactly the expected servers" "expected: $EXPECT_NS"
  fi
  glue=$(printf '%s\n' "$deleg" | awk '$4=="A"||$4=="AAAA" {print $1" "$5}')
  for n in $ns_names; do
    case "$(printf '%s' "$n" | lower)" in
      *".$ZONE.") g=$(printf '%s\n' "$glue" | grep -i "^$n " | tr '\n' ' ')
                  [ -n "$g" ]; check $? "glue address for in-zone server $n is in the referral" "${g:-none}";;
    esac
  done
  parent_ds=$(d "$pns" +norec +noall +answer DS "$ZONE" 2>/dev/null | awk '$4=="DS"' | ds_norm)
  say "- INFO: DS at the parent: $( [ -n "$parent_ds" ] && echo "key tag(s) $(printf '%s\n' "$parent_ds" | awk '{print $2}' | sort -u | tr '\n' ' ')" || echo "none (insecure delegation: answers are accepted unsigned)")"
fi

say '' '## 2. Authoritative servers' ''
serials=""
for n in $ns_names; do
  ip=$(addr_of "$n")
  [ -n "$ip" ]; check $? "$n has an address" "${ip:-none from the referral or the resolver}"
  [ -n "$ip" ] || continue
  for proto in udp tcp; do
    [ "$proto" = tcp ] && t=+tcp || t=+notcp
    out=$(d "$ip" +norec "$t" +noall +comments +answer SOA "$ZONE" 2>&1)
    st=$(printf '%s\n' "$out" | status_of); fl=$(printf '%s\n' "$out" | flags_of)
    serial=$(printf '%s\n' "$out" | awk '$4=="SOA" {print $7}')
    [ "$st" = NOERROR ] && case " $fl " in *" aa "*) true;; *) false;; esac
    check $? "$n ($ip) answers the SOA authoritatively over $proto" "status ${st:-timeout}, flags:${fl:- none}, serial ${serial:-?}"
    [ "$proto" = udp ] && [ -n "$serial" ] && serials="$serials $serial"
  done
  # every server, not just the first: a secondary with the same serial can still carry another NS set
  apex_ns=$(d "$ip" +norec +noall +answer NS "$ZONE" 2>/dev/null | awk '$4=="NS" {print $5}')
  [ "$(norm_set "$apex_ns")" = "$(norm_set "$ns_names")" ]
  check $? "$n ($ip) serves inside the zone the NS set $ns_src names" "zone: $(echo ${apex_ns:-none}); $ns_src: $(echo $ns_names)"
done
if [ -n "$serials" ]; then
  [ "$(echo $serials | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')" -eq 1 ]
  check $? "every authoritative server serves the same SOA serial" "serials:$serials"
fi

say '' '## 3. TRAIN pointer records' ''
say "The content resolver starts at \`$POINTER\` (PTR), then reads the URI record at each target, which names the DID of the trust list." ''
targets=""
for n in $ns_names; do
  ip=$(addr_of "$n"); [ -n "$ip" ] || continue
  out=$(d "$ip" +norec +noall +comments +answer PTR "$POINTER" 2>&1)
  st=$(printf '%s\n' "$out" | status_of)
  t=$(printf '%s\n' "$out" | awk '$4=="PTR" {print $5}')
  [ -n "$t" ]; check_pointer $? "$n serves the pointer $POINTER" "status ${st:-timeout}; targets: ${t:-none}"
  targets="$targets $t"
  # a target inside the zone is this server's to answer, so its URI record must be here too
  for tg in $t; do
    in_zone "$tg" || continue
    u=$(d "$ip" +norec +noall +answer URI "$tg" 2>/dev/null | uri_of)
    [ -n "$u" ]; check_pointer $? "$n serves the URI record at pointer target $tg" "${u:-none}"
  done
done
# a target outside the zone is another zone's to answer: read it through the first resolver
for tg in $(echo $targets | tr ' ' '\n' | sort -u); do
  in_zone "$tg" && continue
  u=$(d "$first" +noall +answer URI "$tg" 2>/dev/null | uri_of)
  [ -n "$u" ]; check_pointer $? "pointer target $tg, outside the zone, has a URI record (through resolver $first)" "${u:-none}"
done

say '' '## 4. Resolution through recursive resolvers' ''
say 'What a client where this script runs sees: the SOA, the pointer and the URI record at every target the resolver returns. `ad` in the flags means the resolver validated the answer with DNSSEC.' ''
for r in $RESOLVERS; do
  out=$(d "$r" +dnssec +noall +comments +answer SOA "$ZONE" 2>&1)
  st=$(printf '%s\n' "$out" | status_of); fl=$(printf '%s\n' "$out" | flags_of)
  [ "$st" = NOERROR ] && [ -n "$(printf '%s\n' "$out" | awk '$4=="SOA"')" ]
  check $? "resolver $r resolves the SOA of $ZONE" "status ${st:-timeout}, flags:${fl:- none}"
  delv_verdict "$r" SOA "$ZONE"
  out=$(d "$r" +noall +comments +answer PTR "$POINTER" 2>&1)
  st=$(printf '%s\n' "$out" | status_of)
  t=$(printf '%s\n' "$out" | awk '$4=="PTR" {print $5}')
  [ -n "$t" ]; check_pointer $? "resolver $r resolves the pointer $POINTER" "status ${st:-timeout}; targets: ${t:-none}"
  # the targets this resolver returned, through this resolver: a negative answer it still caches for
  # a URI breaks discovery for its clients even when the servers and the other resolvers are right
  for tg in $t; do
    out=$(d "$r" +noall +comments +answer URI "$tg" 2>&1)
    st=$(printf '%s\n' "$out" | status_of); u=$(printf '%s\n' "$out" | uri_of)
    [ -n "$u" ]; check_pointer $? "resolver $r resolves the URI record at pointer target $tg" "status ${st:-timeout}; ${u:-no URI record}"
  done
done

say '' '## 5. DNSSEC state' ''
say 'The zone manager signs the zone with keys it generated at first start; the DS at the parent must be the DS of its key-signing key (KSK) on every server, and the signatures must not expire before the next re-sign. A DS is compared in full — owner, algorithm, digest type and digest, computed from the DNSKEY each server serves (RFC 4034 §5.1.4) — because a DS with the right key tag and a wrong digest makes every validating resolver refuse the zone just the same.' ''
answered=""; keysets=""; served=""; first_ds=""; same=0; signed_any=0; sig_exp=""; src=""
for n in $ns_names; do
  ip=$(addr_of "$n"); [ -n "$ip" ] || continue
  out=$(d "$ip" +norec +noall +comments +answer DNSKEY "$ZONE" 2>/dev/null)
  [ "$(printf '%s\n' "$out" | status_of)" = NOERROR ] || continue
  ds=$(printf '%s\n' "$out" | ds_of_keys | sort)
  tags=$(printf '%s\n' "$ds" | awk 'NF {print $2}' | sort -u | tr '\n' ' ' | sed 's/ *$//')
  keysets="$keysets${keysets:+; }$n ${tags:-none}"
  if [ -z "$answered" ]; then
    served=$ds; first_ds=$ds; same=1
  else
    [ "$ds" = "$first_ds" ] || same=0
    # only what every server serves can stand behind a DS: a resolver may ask any of them
    served=$(printf '%s\n' "$served" | grep -xF -f <(printf '%s\n' "$ds"))
  fi
  answered="$answered $n"
  if [ -n "$ds" ]; then
    signed_any=1
    if [ -z "$src" ]; then
      src=$n
      sig_exp=$(d "$ip" +norec +dnssec +noall +answer SOA "$ZONE" 2>/dev/null | awk '$4=="RRSIG" && $5=="SOA" {print $9}' | head -1)
    fi
  fi
done
ksk_tags=$(printf '%s\n' "$served" | awk 'NF {print $2}' | sort -u | tr '\n' ' ' | sed 's/ *$//')
if [ -z "$answered" ] && [ -n "$ns_names" ]; then
  check 1 "an authoritative server answers the DNSKEY query (the DNSSEC state cannot be read)" "no answer from: $(echo $ns_names)"
else
  if [ "$signed_any" = 1 ]; then
    say "- INFO: the zone is signed; KSK key tag(s) by server: $keysets"
  else
    say "- INFO: the zone is not signed ($( [ -n "$answered" ] && echo "no DNSKEY at:$answered" || echo "no authoritative server to ask"))"
  fi
  if [ "$(echo $answered | wc -w | tr -d ' ')" -gt 1 ]; then
    [ "$same" = 1 ]; check $? "every authoritative server serves the same key-signing keys" "$keysets"
  fi
  if [ -n "$EXPECT_DS" ]; then
    while IFS= read -r e; do
      [ -n "$e" ] || continue
      case "$e" in
        '? '*)
          check 1 "EXPECT_DS holds DS records or key tags" "could not read \"${e#? }\": give the DS record as the zone manager printed it (<zone>. 3600 IN DS <tag> 13 2 <digest>), or its key tag";;
        *' '*)
          dt=$(echo "$e" | awk '{print $4}')
          printf '%s\n' "$served" | grep -qxF "$e"
          check $? "the DS recorded for publication (EXPECT_DS) is the DS of a KSK every server serves (owner, algorithm, digest type and digest)" \
            "recorded: $e; served, digest type $dt: $(printf '%s\n' "$served" | awk -v dt="$dt" '$4==dt' | tr '\n' ' ' | sed 's/ *$//' | grep . || echo none)";;
        *)
          [ -n "$(printf '%s\n' "$served" | awk -v t="$e" '$2==t')" ]
          check $? "key tag $e recorded for publication (EXPECT_DS) is a KSK every server serves — the tag only, the digest is not compared: give the whole DS record for the full check" \
            "KSK key tag(s) every server serves: ${ksk_tags:-none}";;
      esac
    done <<EOF
$(printf '%s\n' "$EXPECT_DS" | ds_norm)
EOF
  fi
  if [ -n "$SERVERS" ]; then
    say "- INFO: the parent was not asked (SERVERS): whether it holds a DS, and which, is not checked"
  elif [ "$signed_any" = 0 ]; then
    [ -z "$parent_ds" ]; check $? "no DS at the parent for an unsigned zone (a DS would make every validating resolver refuse the zone)" "DS at the parent: $(echo ${parent_ds:-none})"
  elif [ -n "$parent_ds" ]; then
    matching=$(printf '%s\n' "$parent_ds" | grep -xF -f <(printf '%s\n' "$served"))
    [ -n "$matching" ]
    check $? "a DS at the parent is the DS of a KSK every server serves (owner, algorithm, digest type and digest)" \
      "at the parent: $(printf '%s\n' "$parent_ds" | tr '\n' ';' | sed 's/;$//; s/;/; /g'); matching: $(echo ${matching:-none})"
    stale=$(printf '%s\n' "$parent_ds" | grep -vxF -f <(printf '%s\n' "$served"))
    [ -z "$stale" ] || [ -z "$matching" ] || say "- INFO: DS at the parent that matches no served KSK (a key rollover in progress, or a leftover): $(echo $stale)"
  else
    say "- INFO: no DS at the parent: the signatures are not validated by resolvers (insecure delegation). Publish the DS of the KSK above once key persistence and re-signing are proven."
  fi
  if [ "$signed_any" = 1 ]; then
    if [ -n "$sig_exp" ]; then
      left=$(days_until "$sig_exp")
      [ "${left:-0}" -ge "$MIN_SIG_DAYS" ]; check $? "the SOA signature is valid for at least $MIN_SIG_DAYS more days" "expires $sig_exp UTC, ${left:-?} day(s) left"
    else
      check 1 "an RRSIG covers the SOA" "none returned by $src"
    fi
    for r in $RESOLVERS; do
      plain=$(d "$r" +noall +comments SOA "$ZONE" 2>&1 | status_of); cd_=$(d "$r" +cd +noall +comments SOA "$ZONE" 2>&1 | status_of)
      ! { [ "$plain" = SERVFAIL ] && [ "$cd_" = NOERROR ]; }
      check $? "resolver $r does not reject the zone as bogus (SERVFAIL that disappears with checking disabled)" "validated: ${plain:-timeout}, checking disabled: ${cd_:-timeout}"
    done
  fi
fi

say '' '## Summary' ''
state="unsigned"
if [ "$signed_any" = 1 ]; then
  if [ "$same" = 0 ]; then state="signed, but the servers serve different keys"
  elif [ -n "$SERVERS" ]; then state="signed (parent not asked)"
  elif [ -n "$parent_ds" ]; then state="signed, DS published"
  else state="signed, no DS (insecure delegation)"; fi
fi
# shellcheck disable=SC2015  # display-only "test && echo a || echo b": echo cannot fail
say "| Item | State |" "|---|---|" \
    "| Run from | $WHERE |" \
    "| Delegation | $( [ -n "$SERVERS" ] && echo "not looked up; servers given directly" || { [ -n "$ns_names" ] && echo "NS: $(echo $ns_names)" || echo "not delegated"; }) |" \
    "| Pointer | $( [ -n "$(echo $targets)" ] && echo "$POINTER → $(echo $targets | tr ' ' '\n' | sort -u | tr '\n' ' ')" || echo "not published") |" \
    "| DNSSEC | $state$( [ -n "$sig_exp" ] && echo ", signatures expire $sig_exp") |" \
    "| Checks failed | $failures |"
printf 'wrote %s: %d check(s) failed\n' "$OUT" "$failures"
[ "$failures" -eq 0 ]
