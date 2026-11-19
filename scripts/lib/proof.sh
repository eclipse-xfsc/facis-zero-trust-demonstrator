# Shared machinery of the cluster proofs (scripts/verify-mesh-identity/verify.sh,
# scripts/verify-plane-separation/verify.sh): the CI refusal, the context guard, the run directory
# and its refusal inside the repository, the check/say/exit accounting of the record and the
# redaction of addresses. Sourced, never run; it defines functions only and runs nothing when
# sourced. The sourcing script sets PROOF_NAME (the prefix of its messages) before calling any of
# them, and the globals each function names (CONTEXT, REPO, OUT, failures, ...).
# shellcheck shell=bash disable=SC2016,SC2034,SC2154

# proof_refuse_ci: exits 125 under CI: the evidence is the record of a run on a cluster.
proof_refuse_ci() {
  if [ -n "${CI:-}" ]; then
    echo "$PROOF_NAME: refusing to run under CI; the evidence is written from a run on a cluster" >&2
    exit 125
  fi
}
# yaml_get <file> <key>... : one value out of a YAML file; the path travels as an argument, never inside the source
yaml_get() { python3 -c 'import sys,yaml
v=yaml.safe_load(open(sys.argv[1]))
for k in sys.argv[2:]: v=v[k]
print(v)' "$@"; }
# A refusal exits 125, outside the range of the failure count (1-124), so a caller tells them apart.
refuse() { echo "$PROOF_NAME: refusing context '$CONTEXT': $*" >&2; exit 125; }
# proof_guard_context: refuses (exit 125) any context that is neither a local kind cluster nor a
# confirmed participant cluster, before anything is read from it or written to it, and sets
# CLUSTER_KIND (kind | provider), ZONE_VALUES (its default per cluster) and KEEP. The keep opt-in
# (ZTD_KEEP_ZONE) is read only when PROOF_KEEP_OPT_IN=1; PROOF_OTHER_CONTEXT is the reason a context
# of any other kind is refused for.
proof_guard_context() {
  case $CONTEXT in
    kind-?*)
      [ "${PROOF_KEEP_OPT_IN:-0}" != 1 ] || [ -z "${ZTD_KEEP_ZONE:-}" ] || refuse "ZTD_KEEP_ZONE is set ('$ZTD_KEEP_ZONE'), expected unset: the keep opt-in applies to a participant cluster only (kind-cilium-up.sh recreates a kind zone)"
      CLUSTER_KIND=kind
      ZONE_VALUES=${ZONE_VALUES:-$CHART/ci/values.yaml}
      providers=$(kubectl --context "$CONTEXT" get nodes -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' 2>/dev/null)
      if [ -z "$providers" ] || grep -qv '^kind://' <<<"$providers"; then
        refuse "unreachable, or a node whose provider ID is not kind://"
      fi
      ;;
    zerotrust-a|zerotrust-b)
      [ "${ZTD_CONFIRM_CLUSTER:-}" = "$CONTEXT" ] \
        || refuse "a participant cluster: expected ZTD_CONFIRM_CLUSTER=$CONTEXT, found ${ZTD_CONFIRM_CLUSTER:+ZTD_CONFIRM_CLUSTER=}${ZTD_CONFIRM_CLUSTER:-it unset}"
      [ "${PROOF_KEEP_OPT_IN:-0}" = 1 ] && case ${ZTD_KEEP_ZONE:-} in
        '') ;;
        "$CONTEXT") KEEP=1;;
        *) refuse "expected ZTD_KEEP_ZONE unset or ZTD_KEEP_ZONE=$CONTEXT, found ZTD_KEEP_ZONE=$ZTD_KEEP_ZONE";;
      esac
      CLUSTER_KIND=provider
      zone_name=zone-${CONTEXT#zerotrust-}
      ZONE_VALUES=${ZONE_VALUES:-$CHART/zones/$zone_name.yaml}
      [ "$(yaml_get "$ZONE_VALUES" zone name 2>/dev/null)" = "$zone_name" ] \
        || refuse "expected a zone file whose zone.name is $zone_name, found '$(yaml_get "$ZONE_VALUES" zone name 2>/dev/null)' in $ZONE_VALUES"
      # The binding of the local context name to the cluster it points at: the API host's prefix, the
      # nodes' provider and the nodes' names (no address or domain is kept in the repository).
      api=$(kubectl config view --minify --context "$CONTEXT" -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
      api_host=${api#*://}; api_host=${api_host%%[:/]*}
      [[ $api_host == "api.$CONTEXT."* ]] || refuse "expected the context's API server host to begin with api.$CONTEXT., found '${api_host:-none}'"
      nodes=$(kubectl --context "$CONTEXT" get nodes -o jsonpath='{range .items[*]}{.metadata.name} {.spec.providerID}{"\n"}{end}' 2>/dev/null)
      [ -n "$nodes" ] || refuse "unreachable, or no node listed"
      bad=$(awk '$2 !~ /^onmetal:\/\// {print $1 " (provider ID " ($2 == "" ? "none" : $2) ")"}' <<<"$nodes")
      [ -z "$bad" ] || refuse "expected every node's provider ID to begin with onmetal://, found $(paste -sd, - <<<"$bad")"
      bad=$(awk -v c="--$CONTEXT-" '!index($1, c) {print $1}' <<<"$nodes")
      [ -z "$bad" ] || refuse "expected every node name to contain --$CONTEXT-, found $(paste -sd, - <<<"$bad")"
      ;;
    *) refuse "neither a kind cluster (kind-<name>) nor a participant cluster (zerotrust-a, zerotrust-b); $PROOF_OTHER_CONTEXT";;
  esac
}
# proof_run_dir <tool>: sets EVID to the run directory: ZTD_EVIDENCE_DIR as given, or the base of a
# new one per run under ${XDG_STATE_HOME:-$HOME/.local/state}/ztd/<tool>/<context> (proof_run_dir_new
# names it by the run's UTC start). A run never writes into the repository, so a directory inside it is
# refused (exit 125) before the cluster is touched; with PROOF_ALLOW_IGNORED_RUN_DIR=1 a directory that
# git ignores (the BDD harness's bundles/) is outside the tracked tree and accepted.
proof_run_dir() {
  if [ -n "${ZTD_EVIDENCE_DIR:-}" ]; then EVID=$ZTD_EVIDENCE_DIR
  else EVID=$(realpath -m -- "${XDG_STATE_HOME:-$HOME/.local/state}")/ztd/$1/$CONTEXT; fi
  case $EVID/ in
    "$REPO"/*) [ "${PROOF_ALLOW_IGNORED_RUN_DIR:-0}" = 1 ] && [ "$EVID" != "$REPO" ] && git -C "$REPO" check-ignore -q -- "$EVID" && return 0
      echo "$PROOF_NAME: refusing run directory '$EVID': it is inside the repository, which holds no record of a run" >&2; exit 125;;
  esac
}
# proof_run_dir_new: the default run directory is named by the run's UTC start ($started); an
# existing one is never reused.
proof_run_dir_new() {
  if [ -z "${ZTD_EVIDENCE_DIR:-}" ]; then
    base=$EVID/$(date -u -d "$started" +%Y%m%dT%H%M%SZ); EVID=$base; n=1
    while [ -e "$EVID" ]; do EVID=$base-$n; n=$((n+1)); done
  fi
}
k() { kubectl --context "$CONTEXT" "$@"; }
h() { helm --kube-context "$CONTEXT" "$@"; }
say() { printf '%s\n' "$@" >> "$OUT"; }
code() { say '' '```'; say "$@"; say '```' ''; }
check() { # check <PASS-condition exit status> <title> <detail...>
  local status=$1; shift; local title=$1; shift
  if [ "$status" -eq 0 ]; then say "- PASS: $title"; else say "- **FAIL**: $title"; failures=$((failures+1)); fi
  [ $# -gt 0 ] && say "  $*"
  return 0
}
section() { say '' "## $1" ''; echo "== $1"; }
# proof_mask <file>: the file with every IPv4 and IPv6 address replaced by <address> (the record of a
# participant cluster keeps no address of a client cluster: a dual-stack cluster's pod and node
# addresses included). The loopbacks 127.0.0.1 and ::1, and the unspecified ::, are no address of the
# cluster and stay, so a record still shows where a node-local endpoint answers. An IPv6 candidate is a
# run of hex digits, colons and dots with at least two colons that Python's ipaddress reads as an IPv6
# address (a zone index %<name> included; a sentence's full stop or colon after it stays): a clock time (20:01:26), a MAC address or a digest
# (sha256:...) is no such address and stays. IPv6 goes first, so an IPv4-mapped ::ffff:10.0.0.1 is one
# address; IPv4 then as before. A candidate may follow a colon, so the address of `hostIP:fd00::5` goes as
# that of `hostIP:10.0.0.5` does. The file is read and written byte for byte: a byte that is no UTF-8 (an
# HTTP body cut by bytes at a multibyte character) passes unchanged and never stops the mask.
proof_mask() {
  python3 -c 'import ipaddress, re, sys
KEEP = {ipaddress.IPv6Address("::1"), ipaddress.IPv6Address("::")}
def sub(m):
    t, tail = m.group(0), ""
    while t:
        try: a = ipaddress.IPv6Address(t.split("%")[0])
        except ValueError: a = None
        if a is not None: return m.group(0) if a in KEEP else "<address>" + tail
        if t[-1] not in ".:": return m.group(0)
        t, tail = t[:-1], t[-1] + tail
    return m.group(0)
pat = re.compile(r"(?<![0-9A-Za-z_.])[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z_-]+(?:\.[0-9A-Za-z_-]+)*)?(?![0-9A-Za-z_:])")
text = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read()
sys.stdout.buffer.write(pat.sub(sub, text).encode("utf-8", "surrogateescape"))' "$1" \
  | LC_ALL=C sed -E 's/(^|[^0-9.])127\.0\.0\.1([^0-9.]|$)/\1@LOOPBACK@\2/g; s/(^|[^0-9.])127\.0\.0\.1([^0-9.]|$)/\1@LOOPBACK@\2/g
  s/(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)/\1<address>\3/g; s/(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)/\1<address>\3/g
  s/@LOOPBACK@/127.0.0.1/g'
}
# proof_exit: exits with the number of failed checks, capped at 124 (125 is a refusal).
proof_exit() { exit $(( failures > 124 ? 124 : failures )); }
