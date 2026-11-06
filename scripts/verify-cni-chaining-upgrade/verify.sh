#!/usr/bin/env bash
# Evidence that the CNI chain the mesh relies on survives a Cilium upgrade (ADR-0001 and ADR-0009: the
# chaining order is checked again after every Cilium upgrade). On a disposable kind cluster of its own,
# created with scripts/dev/kind-cilium-up.sh at the zones' Cilium version (Cilium chained with
# cni.exclusive=false), the proof installs the zone with scripts/install-zone/install.sh and the CI zone
# file, applies three stand-ins from scripts/verify-mesh-identity/fixtures/stand-ins.yaml (pdp-adapter
# and data-plain in the data plane, tsa-policy-engine in the management plane), and checks, before and
# after `helm upgrade cilium --reset-then-reuse-values` to the repository's pinned Cilium version (the
# release's own settings, cni.exclusive=false among them, over the new chart's defaults; plain
# --reuse-values keeps the old chart's defaults too and does not render a newer Cilium chart):
#   - every node's CNI configuration lists the Istio plugin after Cilium, read through the Istio CNI node
#     agent of each node (scripts/verify-mesh-identity/lib/cni-chain.sh, shared with the mesh proof);
#   - Cilium runs with cni-exclusive=false;
#   - the allow-matrix lane pdp-adapter -> tsa-policy-engine answers 200 through both proxies;
#   - the default deny holds: data-plain, a data-plane pod without a lane, is refused;
# and, after the upgrade only, that a pod created after it (pdp-adapter, deleted and created again) is
# meshed: its proxy holds a certificate with its own SPIFFE ID issued by the SPIRE CA, and its lane
# answers 200. The upgrade waits for the Cilium rollout and then for the Istio CNI agent to be ready on
# every node, each bounded by a timeout that fails the run; the record gives the time between the two.
# The zones run the provider's Cilium, which this repository does not upgrade (docs/environments/osc.md);
# there the chain section of scripts/verify-mesh-identity is the re-check after a provider upgrade.
# Writes evidence.md and environment.json to a run directory outside the repository (see
# ZTD_EVIDENCE_DIR below) and prints that directory as its last line. Never run by CI.
#
# Usage:
#   scripts/verify-cni-chaining-upgrade/verify.sh           run the proof (creates and deletes its cluster)
#   scripts/verify-cni-chaining-upgrade/verify.sh --help    this text; touches nothing
#
# Exit status:
#   0        every check passed
#   1-124    the number of failed checks (capped at 124); the evidence is written
#   125      refused or not run (an argument, CI, an existing cluster of that name, a bad FAULT, a run
#            directory inside the repository): nothing created, nothing written
#   130/143  interrupted (INT/TERM); the cluster is deleted unless KEEP_CLUSTER=1; no evidence
#
# Environment:
#   FROM_CILIUM_VERSION  the Cilium chart the cluster starts with (default: 1.19.6, the zones' version)
#   TO_CILIUM_VERSION    the Cilium chart it is upgraded to (default: CILIUM_CRDS_VERSION of
#                        scripts/tools/pins.env, the repository's pin, also the default of kind-cilium-up.sh)
#   KIND_CLUSTER         the disposable cluster (default: ztd-cni-upgrade); refused when it already exists
#   KIND_NODE_IMAGE      the node image (default: KIND_NODE_IMAGE of scripts/tools/pins.env, Kubernetes
#                        1.35, which both Cilium versions support)
#   KEEP_CLUSTER         1 keeps the cluster at the end (default: deleted)
#   TIMEOUT              seconds each wait of the upgrade may take before it fails the run (default: 600)
#   ZTD_EVIDENCE_DIR     the run directory: created if missing, used as given, refused inside the
#                        repository. Default: a new directory per run,
#                        ${XDG_STATE_HOME:-$HOME/.local/state}/ztd/verify-cni-chaining-upgrade/<context>/<UTC start>/
#   FAULT                test only, to show that the proof fails: drop-istio-plugin removes the Istio
#                        plugin from one worker's CNI configuration after the upgrade (the node's Istio CNI
#                        agent is paused for the read, so it cannot repair the file first); the run must
#                        exit non-zero naming that node and the order it read. Any other value is refused.
#
# The kubectl context of the caller is left as found: every command names the cluster's context.
# shellcheck disable=SC1091,SC2317,SC2319
set -uo pipefail
usage() { sed -n '2,/^# shellcheck/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
case $# in
  0) ;;
  1) case $1 in -h|--help) usage; exit 0;; esac; usage >&2; echo "verify-cni-chaining-upgrade: unknown argument: $1" >&2; exit 125;;
  *) usage >&2; echo "verify-cni-chaining-upgrade: takes no arguments" >&2; exit 125;;
esac
refuse() { echo "verify-cni-chaining-upgrade: refusing: $*" >&2; exit 125; }
[ -z "${CI:-}" ] || refuse "under CI; the evidence is the record of a run on a cluster"
[ -n "${ZTD_EVIDENCE_DIR:-}" ] && ZTD_EVIDENCE_DIR=$(realpath -m -- "$ZTD_EVIDENCE_DIR")
cd "$(dirname "$0")" || exit 125
REPO=$(git rev-parse --show-toplevel)
. "$REPO/scripts/tools/pins.env"
. "$REPO/scripts/verify-mesh-identity/lib/cni-chain.sh"
FROM=${FROM_CILIUM_VERSION:-1.19.6}
TO=${TO_CILIUM_VERSION:-$CILIUM_CRDS_VERSION}
CLUSTER=${KIND_CLUSTER:-ztd-cni-upgrade}
CONTEXT=kind-$CLUSTER
TIMEOUT=${TIMEOUT:-600}
FAULT=${FAULT:-}
case $FAULT in ''|drop-istio-plugin) ;; *) refuse "FAULT=$FAULT; the only fault is drop-istio-plugin";; esac
for tool in kind kubectl helm cilium istioctl jq openssl docker python3; do
  command -v "$tool" >/dev/null || refuse "missing tool: $tool"
done
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" \
  && refuse "the cluster $CLUSTER exists; the proof creates its own disposable cluster (kind delete cluster --name $CLUSTER)"
if [ -n "${ZTD_EVIDENCE_DIR:-}" ]; then EVID=$ZTD_EVIDENCE_DIR
else EVID=$(realpath -m -- "${XDG_STATE_HOME:-$HOME/.local/state}")/ztd/verify-cni-chaining-upgrade/$CONTEXT; fi
case $EVID/ in "$REPO"/*) refuse "run directory '$EVID' is inside the repository, which holds no record of a run";; esac

CHART=$REPO/deployment/helm/ztd
ZONE_VALUES=$CHART/ci/values.yaml
INSTALL=$REPO/scripts/install-zone/install.sh
FIXTURE=$REPO/scripts/verify-mesh-identity/fixtures/stand-ins.yaml
yaml_get() { python3 -c 'import sys,yaml
v=yaml.safe_load(open(sys.argv[1]))
for k in sys.argv[2:]: v=v[k]
print(v)' "$@"; }
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
DATA=$(yaml_get "$CHART/values.yaml" planes data namespace)
TD=$(yaml_get "$ZONE_VALUES" zone trustDomain)
ISTIO_NS=istio-system; SPIRE_NS=spire-system

work=$(mktemp -d)
prev_context=$(kubectl config current-context 2>/dev/null || true)
created=0; frozen=""
# restore_context: the caller's current context as found (kind create switches it)
restore_context() {
  if [ -n "$prev_context" ]; then kubectl config use-context "$prev_context" >/dev/null 2>&1
  else kubectl config unset current-context >/dev/null 2>&1; fi
}
# shellcheck disable=SC2317  # called from the EXIT trap only
finish() {
  [ -n "$frozen" ] && docker exec "$frozen" pkill -CONT -x install-cni >/dev/null 2>&1
  if [ "$created" = 1 ] && [ "${KEEP_CLUSTER:-}" != 1 ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; fi
  restore_context
  rm -rf "$work"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

OUT=$work/evidence.md
failures=0
commit=$(git rev-parse HEAD)
dirty=false; [ -n "$(git status --porcelain)" ] && dirty=true
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ -z "${ZTD_EVIDENCE_DIR:-}" ]; then
  base=$EVID/$(date -u -d "$started" +%Y%m%dT%H%M%SZ); EVID=$base; n=1
  while [ -e "$EVID" ]; do EVID=$base-$n; n=$((n+1)); done
fi
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
# http <ns> <pod> <url>: HTTP code and the first line of the body; denied(<curl exit>) when the network
# refused the call (7 refused, 28 timed out, 52 empty reply, 56 reset); error(<exit>) otherwise
http() {
  local out rc
  out=$(k -n "$1" exec "$2" -c app -- curl -sS -m 15 -w '\n%{http_code}' "$3" 2>/dev/null); rc=$?
  case $rc in
    0) printf '%s %s' "$(tail -1 <<<"$out")" "$(head -1 <<<"$out" | cut -c1-110)";;
    7|28|52|56) echo "denied($rc)";;
    *) echo "error($rc)";;
  esac
}
# stand_ins <out>: the ServiceAccounts, Pods and Services of pdp-adapter, data-plain and tsa-policy-engine
# from the mesh proof's fixture, with the plane namespaces filled in
stand_ins() {
  sed -e "s/__DATA__/$DATA/g" -e "s/__MGMT__/$MGMT/g" "$FIXTURE" | python3 -c 'import sys,yaml
want = {"pdp-adapter", "data-plain", "tsa-policy-engine"}
yaml.safe_dump_all([d for d in yaml.safe_load_all(sys.stdin) if d and d["metadata"]["name"] in want], sys.stdout, sort_keys=False)' >"$1"
}
# wait_until <seconds> <command...>: status 0 once the command succeeds, 1 when the time runs out
wait_until() {
  local end=$(( $(date +%s) + $1 )); shift
  until "$@" >/dev/null 2>&1; do [ "$(date +%s)" -ge "$end" ] && return 1; sleep 5; done
}
# istio_cni_ready: every node runs a ready Istio CNI agent of the current DaemonSet generation
istio_cni_ready() {
  local js nodes
  nodes=$(k get nodes --no-headers | grep -c .)
  js=$(k -n "$ISTIO_NS" get ds istio-cni-node -o json) || return 1
  jq -e --argjson n "$nodes" '.status.desiredNumberScheduled == $n and .status.numberReady == $n
    and .status.updatedNumberScheduled == $n and .status.observedGeneration == .metadata.generation' <<<"$js"
}
# cilium_on_version: every pod of ds/cilium runs the image of TO and is ready
cilium_on_version() {
  local js
  js=$(k -n kube-system get pods -l k8s-app=cilium -o json) || return 1
  jq -e --arg v "v$TO" '(.items | length) > 0 and ([.items[] | select((.spec.containers[0].image | contains(":" + $v + "@") or endswith(":" + $v)) | not)] | length == 0)
    and ([.items[] | .status.containerStatuses[]? | select(.ready | not)] | length == 0)' <<<"$js"
}
# chain_checks <phase>: the chain on every node of the cluster (a node the read does not reach fails),
# and cni-exclusive=false
chain_checks() {
  local nodes seen="" node conf plugins
  nodes=$(k get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
  while IFS=$'\t' read -r node conf plugins; do
    [ -n "$node" ] || continue
    seen="$seen $node"
    cni_chain_ok "$plugins"; check $? "$1: the CNI configuration of node $node lists the Istio plugin after Cilium" "${conf:-no configuration read}: ${plugins:-no plugin order read}"
  done < <(cni_chain "$CONTEXT" "$ISTIO_NS")
  for node in $nodes; do
    [[ " $seen " == *" $node "* ]] || check 1 "$1: the CNI configuration of node $node lists the Istio plugin after Cilium" "no Istio CNI agent on the node read its configuration"
  done
  excl=$(k -n kube-system get cm cilium-config -o jsonpath='{.data.cni-exclusive}' 2>/dev/null)
  [ "$excl" = false ]; check $? "$1: Cilium runs with cni-exclusive=false" "cni-exclusive=${excl:-unread}"
}
# lane_checks <phase>: the allow-matrix lane answers 200 through the proxies, and the default deny holds
lane_checks() {
  local r
  r=$(http "$DATA" pdp-adapter "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
  [ "${r%% *}" = 200 ]; check $? "$1: pdp-adapter → tsa-policy-engine (allow-matrix lane pdp-adapter-to-tsa) is served through both proxies" "→ $r"
  r=$(http "$DATA" data-plain "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
  case $r in denied*) true;; *) false;; esac
  check $? "$1: data-plain → tsa-policy-engine (a data-plane pod without a lane) is refused: the default deny holds" "→ $r"
}

say "# CNI chain across a Cilium upgrade" ''
say "Run of \`scripts/verify-cni-chaining-upgrade/verify.sh\` at commit \`$commit\`$([ "$dirty" = true ] && echo ' (working tree with uncommitted changes)'), started $started." ''
say "Cilium $FROM (the zones' version) is upgraded to $TO (the repository's pin) on the disposable kind cluster \`$CLUSTER\`, with the zone installed from \`${ZONE_VALUES#"$REPO"/}\`.${FAULT:+ **Test fault: FAULT=$FAULT.**}" ''

# --------------------------------------------------------------------------------------------
section "1. The cluster at Cilium $FROM, and the zone"
created=1
KIND_CLUSTER=$CLUSTER CILIUM_VERSION=$FROM "$REPO/scripts/dev/kind-cilium-up.sh" >"$work/kind.log" 2>&1; rc=$?
restore_context
check $rc "the cluster $CLUSTER is created with Cilium $FROM chained (cni.exclusive=false)" "$(tail -1 "$work/kind.log")"
if [ $rc -ne 0 ]; then code "$(tail -20 "$work/kind.log")"; fi
image_from=$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
server=$(k version -o json 2>/dev/null | jq -r .serverVersion.gitVersion)
KUBE_CONTEXT=$CONTEXT ZONE_VALUES=$ZONE_VALUES "$INSTALL" install >"$work/install.log" 2>&1; rc=$?
check $rc "the zone is installed with scripts/install-zone/install.sh" "$(tail -1 "$work/install.log")"
[ $rc -ne 0 ] && code "$(tail -30 "$work/install.log")"
stand_ins "$work/stand-ins.yaml"
k apply -f "$work/stand-ins.yaml" >/dev/null 2>"$work/stand-ins.err"
k -n "$DATA" wait --for=condition=Ready pod/pdp-adapter pod/data-plain --timeout=300s >/dev/null 2>&1 \
  && k -n "$MGMT" wait --for=condition=Ready pod/tsa-policy-engine --timeout=300s >/dev/null 2>&1
check $? "the stand-ins pdp-adapter, data-plain ($DATA) and tsa-policy-engine ($MGMT) of scripts/verify-mesh-identity/fixtures/stand-ins.yaml are Ready" "$(head -1 "$work/stand-ins.err")"
code "$(k get nodes -o wide | sed 's/  */ /g')"

# --------------------------------------------------------------------------------------------
section "2. Before the upgrade (Cilium $FROM)"
chain_checks "before"
lane_checks "before"

# --------------------------------------------------------------------------------------------
section "3. The upgrade to Cilium $TO"
# The chart is taken from Cilium's repository by URL (--repo), never from a Helm repository named
# cilium that the caller's Helm configuration may already hold.
t0=$(date +%s)
h upgrade cilium cilium --repo https://helm.cilium.io/ --version "$TO" -n kube-system --reset-then-reuse-values >"$work/upgrade.log" 2>&1; up=$?
check $up "helm upgrade cilium cilium --repo https://helm.cilium.io/ --version $TO --reset-then-reuse-values (the release's own values over the new chart's defaults)" "$(grep -m1 -E 'has been upgraded|Error' "$work/upgrade.log")"
[ $up -ne 0 ] && code "$(head -20 "$work/upgrade.log")"
code "$(h get values cilium -n kube-system 2>&1)"
if [ $up -eq 0 ]; then
  k -n kube-system rollout status ds/cilium --timeout="${TIMEOUT}s" >"$work/rollout.log" 2>&1 && wait_until "$TIMEOUT" cilium_on_version; rc=$?
else
  rc=1
fi
t1=$(date +%s)
image_to=$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
check $rc "the Cilium DaemonSet has rolled out: every pod of ds/cilium runs v$TO and is ready (within ${TIMEOUT}s)" "$((t1 - t0))s after the upgrade started; image $image_to"
wait_until "$TIMEOUT" istio_cni_ready; rc=$?
t2=$(date +%s)
check $rc "the Istio CNI node agent is ready on every node after the Cilium rollout (within ${TIMEOUT}s)" "$((t2 - t1))s after the Cilium rollout"
say '' "Time between the Cilium rollout and the Istio CNI agent's readiness on every node: **$((t2 - t1)) s** (upgrade started → Cilium rolled out: $((t1 - t0)) s)." ''
code "$(k -n kube-system get pods -l k8s-app=cilium -o wide | sed 's/  */ /g'; echo; k -n "$ISTIO_NS" get pods -l k8s-app=istio-cni-node -o wide | sed 's/  */ /g')"

if [ "$FAULT" = drop-istio-plugin ]; then
  section "Test fault: drop-istio-plugin"
  fnode=$(k get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].metadata.name}')
  fconf=$(cni_chain "$CONTEXT" "$ISTIO_NS" | awk -F'\t' -v n="$fnode" '$1 == n {print $2}')
  frozen=$fnode
  if docker exec "$fnode" pkill -STOP -x install-cni && [ -n "$fconf" ] \
     && docker exec "$fnode" cat "$fconf" | jq '.plugins |= map(select(.type != "istio-cni"))' >"$work/fault.conflist" \
     && docker exec -i "$fnode" sh -c 'cat > "$1"' _ "$fconf" <"$work/fault.conflist"; then
    say "The Istio CNI agent of node \`$fnode\` is paused (SIGSTOP) and the Istio plugin is removed from \`$fconf\` there; the checks below must report it." ''
  else
    say "**The fault could not be applied on node \`${fnode:-none}\`.**" ''
    failures=$((failures+1))
  fi
fi

# --------------------------------------------------------------------------------------------
section "4. After the upgrade (Cilium $TO)"
chain_checks "after"
lane_checks "after"
say '' '### A pod created after the upgrade' ''
k -n "$DATA" delete pod pdp-adapter --wait=true >/dev/null 2>&1
python3 -c 'import sys,yaml
yaml.safe_dump_all([d for d in yaml.safe_load_all(open(sys.argv[1])) if d and d["kind"] == "Pod" and d["metadata"]["name"] == "pdp-adapter"], sys.stdout)' "$work/stand-ins.yaml" >"$work/pdp-adapter.yaml"
k apply -f "$work/pdp-adapter.yaml" >/dev/null 2>&1
k -n "$DATA" wait --for=condition=Ready pod/pdp-adapter --timeout=300s >/dev/null 2>&1
check $? "pdp-adapter, deleted and created again after the upgrade, is Ready with its proxy" "uid $(k -n "$DATA" get pod pdp-adapter -o jsonpath='{.metadata.uid}' 2>/dev/null), node $(k -n "$DATA" get pod pdp-adapter -o jsonpath='{.spec.nodeName}' 2>/dev/null), created $(k -n "$DATA" get pod pdp-adapter -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
k -n "$SPIRE_NS" exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show >"$work/spire-bundle.pem" 2>/dev/null
for _ in $(seq 12); do
  istioctl --context "$CONTEXT" proxy-config secret pdp-adapter -n "$DATA" -o json >"$work/secret.json" 2>/dev/null
  jq -r '.dynamicActiveSecrets[]? | select(.name == "default") | .secret.tlsCertificate.certificateChain.inlineBytes // empty' "$work/secret.json" 2>/dev/null \
    | base64 -d 2>/dev/null | openssl x509 -out "$work/leaf.pem" 2>/dev/null && [ -s "$work/leaf.pem" ] && break
  sleep 5
done
uri=$(openssl x509 -noout -ext subjectAltName -in "$work/leaf.pem" 2>/dev/null | grep -o 'URI:spiffe://[^,]*' | head -1 | sed 's/^URI://')
issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 -in "$work/leaf.pem" 2>/dev/null)
ca_subject=$(openssl x509 -noout -subject -nameopt RFC2253 -in "$work/spire-bundle.pem" 2>/dev/null)
[ "$uri" = "spiffe://$TD/ns/$DATA/sa/pdp-adapter" ] && [ -n "$issuer" ] && [ "${issuer#issuer=}" = "${ca_subject#subject=}" ] \
  && openssl verify -CAfile "$work/spire-bundle.pem" "$work/leaf.pem" >/dev/null 2>&1
check $? "its proxy presents its own SPIFFE ID, issued by the SPIRE CA and chaining to the bundle read from the SPIRE server" "URI ${uri:-none}; ${issuer:-no certificate read}; SPIRE CA ${ca_subject:-unread}"
r=$(http "$DATA" pdp-adapter "http://tsa-policy-engine.$MGMT.svc:8080/hostname")
[ "${r%% *}" = 200 ]; check $? "the new pod's lane pdp-adapter → tsa-policy-engine is served through both proxies" "→ $r"
if [ -n "$frozen" ]; then docker exec "$frozen" pkill -CONT -x install-cni >/dev/null 2>&1; frozen=""; fi

# --------------------------------------------------------------------------------------------
say '' '## Result' ''
if [ "$failures" -eq 0 ]; then say 'All checks passed.'; else say "**$failures check(s) failed.**"; fi
say '' "Cluster: $([ "${KEEP_CLUSTER:-}" = 1 ] && echo "kept (\`$CONTEXT\`)" || echo "deleted at the end of the run")."
jq -n --arg commit "$commit" --argjson dirty "$dirty" --arg date "$started" --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg context "$CONTEXT" --arg server "$server" --arg nodeImage "${KIND_NODE_IMAGE}" --arg zone "${ZONE_VALUES#"$REPO"/}" \
  --arg from "$FROM" --arg to "$TO" --arg imageFrom "$image_from" --arg imageTo "$image_to" --arg fault "$FAULT" \
  --argjson upgradeToRollout "$((t1 - t0))" --argjson rolloutToIstioCni "$((t2 - t1))" \
  --arg kind "$(kind version 2>/dev/null)" --arg helm "$(helm version --short 2>/dev/null)" \
  --arg kubectl "$(kubectl version --client -o json 2>/dev/null | jq -r .clientVersion.gitVersion)" \
  --arg istioctl "$(istioctl version --remote=false 2>/dev/null | sed 's/^client version: //' | head -1)" \
  --argjson failures "$failures" '{
    commit: $commit, dirty: $dirty, date: $date, finished: $finished,
    cluster: { context: $context, kind: "kind", kubernetes: $server, kindNodeImage: $nodeImage },
    zone: { file: $zone },
    cilium: { from: $from, to: $to, imageFrom: $imageFrom, imageTo: $imageTo },
    seconds: { upgradeToCiliumRollout: $upgradeToRollout, ciliumRolloutToIstioCniReady: $rolloutToIstioCni },
    fault: (if $fault == "" then null else $fault end),
    tools: { kind: $kind, helm: $helm, kubectl: $kubectl, istioctl: $istioctl },
    result: { failures: $failures }
  }' >"$work/environment.json"
if ! { mkdir -p "$EVID" && cp "$OUT" "$EVID/evidence.md" && cp "$work/environment.json" "$EVID/environment.json"; }; then
  echo "verify-cni-chaining-upgrade: the evidence could not be written to $EVID" >&2
  failures=$((failures+1))
  exit $(( failures > 124 ? 124 : failures ))
fi
echo "evidence written ($failures failure(s)); run directory:"
# The last line of the output is the run directory, alone, so a caller takes it with tail -n 1.
echo "$EVID"
exit $(( failures > 124 ? 124 : failures ))
