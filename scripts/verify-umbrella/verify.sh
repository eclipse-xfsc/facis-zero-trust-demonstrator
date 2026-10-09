#!/usr/bin/env bash
# Evidence for the umbrella chart on the local kind cluster (scripts/dev/kind-cilium-up.sh). Every
# step appends to evidence.md next to this script; the exit status is non-zero if any check failed.
#
#   KUBE_CONTEXT       kubectl context           (default: kind-ztd)
#   VALUES             zone file                 (default: deployment/helm/ztd/ci/values.yaml)
#   AMBIENT_VALUES     zone file in ambient mode (default: ambient-values.yaml next to this script),
#                      the excursion: sidecar is the installed baseline (ADR-0009), ambient the
#                      parked mode the script switches to and back
#
# Every check is "<test>; check $? <title>": the status of the test is what the check records.
# shellcheck disable=SC2319
set -uo pipefail
cd "$(dirname "$0")" || exit 1
REPO=$(git rev-parse --show-toplevel)
CHART=$REPO/deployment/helm/ztd
VALUES=${VALUES:-$CHART/ci/values.yaml}
AMBIENT_VALUES=${AMBIENT_VALUES:-$PWD/ambient-values.yaml}
CONTEXT=${KUBE_CONTEXT:-kind-ztd}
RELEASE=ztd; RNS=ztd-system
# yaml_get <file> <key>... : one value out of a YAML file; the path travels as an argument, never inside the source
yaml_get() { python3 -c 'import sys,yaml
v=yaml.safe_load(open(sys.argv[1]))
for k in sys.argv[2:]: v=v[k]
print(v)' "$@"; }
MGMT=$(yaml_get "$CHART/values.yaml" planes management namespace)
DATA=$(yaml_get "$CHART/values.yaml" planes data namespace)
# The control-plane namespaces of the zone file (planes.extra with mesh: false): spire-system, istio-system
read -ra CTRL <<<"$(python3 -c 'import sys,yaml
z=yaml.safe_load(open(sys.argv[1]))
print(" ".join(e["name"] for e in (z.get("planes") or {}).get("extra") or [] if e.get("mesh") is False))' "$VALUES")"
# Stand-in images for the probes; nothing here is consumed by a real zone.
AGNHOST=registry.k8s.io/e2e-test-images/agnhost:2.53
CURL=docker.io/curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b
OUT=evidence.md
failures=0
# The commit and the dirty flag are read before the evidence is written into the tree.
commit=$(git rev-parse HEAD)
dirty=false; [ -n "$(git status --porcelain)" ] && dirty=true

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
# curl from a pod; prints the HTTP code or "denied(<curl exit>)"
probe() { # probe <namespace> <pod> <url>
  local out rc
  out=$(k -n "$1" exec "$2" -- curl -sS -m 5 -o /dev/null -w '%{http_code}' "$3" 2>/dev/null); rc=$?
  if [ $rc -eq 0 ]; then echo "$out"; else echo "denied($rc)"; fi
}
expect_allow() { local r; r=$(probe "$1" "$2" "$3"); [ "$r" = 200 ]; check $? "$4" "→ $r"; }
expect_deny() { local r; r=$(probe "$1" "$2" "$3"); case $r in denied*) true;; *) false;; esac; check $? "$4" "→ $r"; }

: > "$OUT"
say "# Umbrella chart evidence ($(date -u +%Y-%m-%dT%H:%M:%SZ))" ''
say "Commit \`$commit\`, tree dirty: $dirty." ''
say "Cluster context \`$CONTEXT\`, chart \`deployment/helm/ztd\` $(grep '^version:' "$CHART/Chart.yaml" | cut -d' ' -f2), zone file \`${VALUES#"$REPO"/}\` (mesh mode $(yaml_get "$VALUES" mesh mode), the installed baseline), excursion fixture \`${AMBIENT_VALUES#"$REPO"/}\`." ''
say "Tools: helm $(h version --short 2>/dev/null), kubectl client $(k version --client -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["clientVersion"]["gitVersion"])'). The CI chart job pins Helm v4.3.0." ''
say 'Probe results: `200` means the call went through; `denied(28)` means curl gave up after 5 s because the policy dropped the packets.' ''

say '' '## 0. Preconditions' ''
server=$(k version -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')
recorded=$(yaml_get "$VALUES" zone kubernetesVersion)
[ "$server" = "$recorded" ]; check $? "the zone file records the server version the cluster runs" "server $server, recorded $recorded"
cni=$(k -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
[ -n "$cni" ]; check $? "Cilium is the CNI" "$cni"
excl=$(k -n kube-system get cm cilium-config -o jsonpath='{.data.cni-exclusive}' 2>/dev/null)
[ "$excl" = "false" ]; check $? "cni-exclusive=false (Istio CNI can chain)" "cni-exclusive=$excl"
code "$(k get nodes -o wide | sed 's/  */ /g')"

say '' '## 1. Clean slate' ''
h uninstall "$RELEASE" -n "$RNS" --ignore-not-found >/dev/null 2>&1
for ns in "$MGMT" "$DATA" "${CTRL[@]}"; do k delete ns "$ns" --ignore-not-found --wait=true >/dev/null 2>&1; done
# hook resources are not part of the release; clear leftovers of an earlier failed run
k -n "$RNS" delete job "${RELEASE}-verify-layout" --ignore-not-found >/dev/null 2>&1
k delete clusterrole,clusterrolebinding "${RELEASE}-verify-layout" --ignore-not-found >/dev/null 2>&1
k get ns "$MGMT" "$DATA" "${CTRL[@]}" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "no plane namespace exists before the install"

say '' '## 2. Install from zero' ''
start=$(date +%s)
out=$(h upgrade --install "$RELEASE" "$CHART" -n "$RNS" --create-namespace -f "$VALUES" --wait --timeout 5m 2>&1); rc=$?
check $rc "helm upgrade --install from an empty cluster returns 0" "$(( $(date +%s) - start ))s"
code "$(printf '%s\n' "$out" | grep -vE '^(NOTES|LAST DEPLOYED|NAMESPACE|STATUS|REVISION|TEST SUITE):' | head -20)"
status=$(h status "$RELEASE" -n "$RNS" -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["info"]["status"])')
[ "$status" = deployed ]; check $? "release status is deployed (a failing verification hook would have failed it)" "$status"
# On success Helm removes the hook job (hook-succeeded); a failed one stays with its log.
if k -n "$RNS" get "job/${RELEASE}-verify-layout" >/dev/null 2>&1; then
  check 1 "the post-install verification job passed and was removed by its hook policy" "a failed job remains:"
  code "$(k -n "$RNS" logs "job/${RELEASE}-verify-layout" 2>&1)"
else
  check 0 "the post-install verification job passed and was removed by its hook policy" "(a failing job would have failed the release above)"
fi

say '' '## 3. The layout' ''
say "The control-plane namespaces of the zone file (\`${CTRL[*]}\`) are management-plane namespaces without the mesh label; the SPIRE and Istio releases that install into them are proven by \`scripts/verify-mesh-identity\`." ''
code "$(k get ns "$MGMT" "$DATA" "${CTRL[@]}" -L ztd.facis.io/plane,istio.io/dataplane-mode,istio-injection | sed 's/  */ /g')"
ctrl_re=$(IFS='|'; echo "${CTRL[*]}")
code "$(k get netpol -A | grep -E "^(NAMESPACE|$MGMT|$DATA${ctrl_re:+|$ctrl_re}) " | sed 's/  */ /g')"
code "$(k get ciliumnetworkpolicy -A 2>/dev/null | sed 's/  */ /g')"
for ns in "$MGMT" "$DATA" "${CTRL[@]}"; do k -n "$ns" get netpol default-deny >/dev/null 2>&1; check $? "default-deny present in $ns"; done
for ns in "${CTRL[@]}"; do [ "$(k get ns "$ns" -o jsonpath='{.metadata.labels.ztd\.facis\.io/plane}')" = management ] && [ -z "$(k get ns "$ns" -o jsonpath='{.metadata.labels.istio-injection}')" ]; check $? "control-plane namespace $ns: management plane, no injection label"; done
for ns in "$MGMT" "$DATA"; do [ "$(k get ns "$ns" -o jsonpath='{.metadata.labels.istio-injection}')" = enabled ]; check $? "sidecar mode (the baseline): istio-injection=enabled on $ns"; done
for ns in "$MGMT" "$DATA"; do [ -z "$(k get ns "$ns" -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}')" ]; check $? "sidecar mode: no ambient label on $ns"; done
k get ciliumclusterwidenetworkpolicy "${RELEASE}-allow-ambient-hostprobes" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "sidecar mode: no ambient host-probe exception is rendered"

say '' '## 4. Install again: idempotent' ''
h get manifest "$RELEASE" -n "$RNS" > /tmp/ztd-manifest-1.yaml
out=$(h upgrade --install "$RELEASE" "$CHART" -n "$RNS" -f "$VALUES" --wait --timeout 5m 2>&1); rc=$?
check $rc "second helm upgrade --install returns 0"
h get manifest "$RELEASE" -n "$RNS" > /tmp/ztd-manifest-2.yaml
diff -q /tmp/ztd-manifest-1.yaml /tmp/ztd-manifest-2.yaml >/dev/null; check $? "rendered manifest identical between the two installs"
rev=$(h status "$RELEASE" -n "$RNS" -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["version"])')
say "  revision after the second install: $rev"

say '' '## 5. Cross-plane calls: the negative case, and the matrix lanes' ''
say 'Stand-in pods carry the matrix labels; nothing else about them is real. Targets serve HTTP on 8080.' ''
k -n "$MGMT" run tsa-policy-engine --image="$AGNHOST" --labels=app.kubernetes.io/name=tsa-policy-engine --port=8080 --expose -- netexec --http-port=8080 >/dev/null 2>&1
k -n "$MGMT" run openbao --image="$AGNHOST" --labels=app.kubernetes.io/name=openbao --port=8080 --expose -- netexec --http-port=8080 >/dev/null 2>&1
k -n "$DATA" run data-target --image="$AGNHOST" --labels=app.kubernetes.io/name=data-target --port=8080 --expose -- netexec --http-port=8080 >/dev/null 2>&1
k -n "$DATA" run data-plain --image="$CURL" --labels=app.kubernetes.io/name=data-plain --command -- sleep 3600 >/dev/null 2>&1
k -n "$DATA" run pdp-adapter --image="$CURL" --labels=app.kubernetes.io/name=pdp-adapter --command -- sleep 3600 >/dev/null 2>&1
k -n "$MGMT" run mgmt-probe --image="$CURL" --labels=app.kubernetes.io/name=mgmt-probe --command -- sleep 3600 >/dev/null 2>&1
k -n "$MGMT" wait --for=condition=Ready pod/tsa-policy-engine pod/openbao pod/mgmt-probe --timeout=180s >/dev/null 2>&1; check $? "management stand-ins Ready"
k -n "$DATA" wait --for=condition=Ready pod/data-target pod/data-plain pod/pdp-adapter --timeout=180s >/dev/null 2>&1; check $? "data-plane stand-ins Ready"
expect_deny  "$DATA" data-plain  "http://openbao.$MGMT.svc:8080/hostname"           "unlabelled data-plane pod → openbao (management): DENIED"
expect_deny  "$DATA" data-plain  "http://tsa-policy-engine.$MGMT.svc:8080/hostname" "unlabelled data-plane pod → tsa-policy-engine (management): DENIED"
expect_allow "$DATA" pdp-adapter "http://tsa-policy-engine.$MGMT.svc:8080/hostname" "pdp-adapter → tsa-policy-engine: ALLOWED (matrix lane pdp-adapter-to-tsa)"
expect_deny  "$DATA" pdp-adapter "http://openbao.$MGMT.svc:8080/hostname"           "pdp-adapter → openbao: DENIED (a lane is one pair, not a licence)"
expect_allow "$DATA" data-plain  "http://data-target.$DATA.svc:8080/hostname"        "data-plane pod → data-plane pod: ALLOWED (intra-plane lane)"
expect_deny  "$MGMT" mgmt-probe  "http://data-target.$DATA.svc:8080/hostname"        "management pod → data plane: DENIED (default deny is both directions)"
r=$(k -n "$DATA" exec data-plain -- nslookup "tsa-policy-engine.$MGMT.svc.cluster.local" 2>&1 | tail -3 | tr '\n' ' '); k -n "$DATA" exec data-plain -- nslookup "tsa-policy-engine.$MGMT.svc.cluster.local" >/dev/null 2>&1; check $? "DNS bypass: the denied pod still resolves names" "$r"

say '' '## 6. Mesh mode is one label: the excursion to the parked ambient mode, and back' ''
say 'Sidecar is the installed baseline (ADR-0009). The release is switched to ambient with the excursion fixture, which must bring the ambient label and the Cilium host-probe exception while the denial and the lane hold, and then back to sidecar, which must leave neither behind.' ''
out=$(h upgrade --install "$RELEASE" "$CHART" -n "$RNS" -f "$AMBIENT_VALUES" --wait --timeout 5m 2>&1); rc=$?
check $rc "upgrade to ambient mode returns 0"
code "$(k get ns "$MGMT" "$DATA" -L ztd.facis.io/plane,istio.io/dataplane-mode,istio-injection | sed 's/  */ /g')"
for ns in "$MGMT" "$DATA"; do [ "$(k get ns "$ns" -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}')" = ambient ]; check $? "ambient mode: istio.io/dataplane-mode=ambient on $ns"; done
[ -z "$(k get ns "$DATA" -o jsonpath='{.metadata.labels.istio-injection}')" ]; check $? "ambient mode: the sidecar label is gone"
k get ciliumclusterwidenetworkpolicy "${RELEASE}-allow-ambient-hostprobes" >/dev/null 2>&1; check $? "ambient mode: the Cilium host-probe exception is rendered (mode ambient, Cilium)"
expect_deny  "$DATA" data-plain  "http://openbao.$MGMT.svc:8080/hostname"           "ambient mode: cross-plane call still DENIED"
expect_allow "$DATA" pdp-adapter "http://tsa-policy-engine.$MGMT.svc:8080/hostname" "ambient mode: matrix lane still ALLOWED"
out=$(h upgrade --install "$RELEASE" "$CHART" -n "$RNS" -f "$VALUES" --wait --timeout 5m 2>&1); rc=$?
check $rc "back to sidecar mode returns 0"
code "$(k get ns "$MGMT" "$DATA" -L ztd.facis.io/plane,istio.io/dataplane-mode,istio-injection | sed 's/  */ /g')"
for ns in "$MGMT" "$DATA"; do [ "$(k get ns "$ns" -o jsonpath='{.metadata.labels.istio-injection}')" = enabled ]; check $? "sidecar mode restored: istio-injection=enabled on $ns"; done
[ -z "$(k get ns "$DATA" -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}')" ]; check $? "sidecar mode restored: the ambient label is gone"
k get ciliumclusterwidenetworkpolicy "${RELEASE}-allow-ambient-hostprobes" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "sidecar mode restored: the ambient host-probe exception is gone"
expect_deny  "$DATA" data-plain  "http://openbao.$MGMT.svc:8080/hostname"           "sidecar mode restored: cross-plane call still DENIED"
expect_allow "$DATA" pdp-adapter "http://tsa-policy-engine.$MGMT.svc:8080/hostname" "sidecar mode restored: matrix lane still ALLOWED"

say '' '## 7. Guards that refuse a wrong configuration: the lint and render steps of the CI chart gate' ''
say 'The CI job runs `helm lint` and then `helm template`. Schema violations fail both steps; a `fail` call in a template fails the render step only, because lint mode renders `fail` as a no-op by design.' ''
h lint "$CHART" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "no zone file: lint refused by the schema"
h template "$RELEASE" "$CHART" >/dev/null 2>/tmp/ztd-g1; [ $? -ne 0 ]; check $? "no zone file: render refused by the schema" "$(grep -m1 -oE "at '/zone/[a-zA-Z]+'.*" /tmp/ztd-g1)"
h lint "$CHART" -f "$VALUES" --set mesh.mode=both >/dev/null 2>&1; [ $? -ne 0 ]; check $? "unknown mesh mode: lint refused by the schema"
h template "$RELEASE" "$CHART" -f "$VALUES" --set mesh.mode=both >/dev/null 2>/tmp/ztd-g3; [ $? -ne 0 ]; check $? "unknown mesh mode: render refused" "$(grep -m1 -oE "at '/mesh/mode'.*" /tmp/ztd-g3)"
NOCILIUM=(--set cni.cilium.enabled=false --set mesh.mode=none --set networkPolicy.kubeApi.enabled=true --set networkPolicy.kubeApi.cidrs=null)
h lint "$CHART" -f "$VALUES" "${NOCILIUM[@]}" >/dev/null 2>&1; check $? "kubeApi lane without cidrs on a zone without Cilium (an ipBlock lane): lint passes, as lint mode ignores the template guard; the render step below is the one that catches it"
h template "$RELEASE" "$CHART" -f "$VALUES" "${NOCILIUM[@]}" >/dev/null 2>/tmp/ztd-g2; [ $? -ne 0 ]; check $? "kubeApi lane without cidrs on a zone without Cilium: render refused" "$(grep -m1 -oE 'networkPolicy.kubeApi.enabled needs.*' /tmp/ztd-g2)"
h template "$RELEASE" "$CHART" -f "$VALUES" --set zone.trustDomain= >/dev/null 2>/tmp/ztd-g4; [ $? -ne 0 ]; check $? "meshed zone without zone.trustDomain: render refused by the schema" "$(grep -m1 -oE "at '/zone/trustDomain'.*" /tmp/ztd-g4)"
h template "$RELEASE" "$CHART" -f "$VALUES" --set zone.kubernetesVersion=v1.32.0 >/dev/null 2>/tmp/ztd-g5; [ $? -ne 0 ]; check $? "sidecar mode on Kubernetes v1.32.0: render refused (native sidecars need 1.33)" "$(grep -m1 -oE 'mesh.mode sidecar needs native.*' /tmp/ztd-g5)"
h template "$RELEASE" "$CHART" -f "$VALUES" --set cni.cilium.enabled=false >/dev/null 2>/tmp/ztd-g6; [ $? -ne 0 ]; check $? "meshed zone without Cilium: render refused, naming the control-plane openings and the derogation" "$(grep -m1 -oE 'mesh.mode sidecar needs Cilium[^:]*' /tmp/ztd-g6)"

say '' '## 8. Teardown leaves no plane namespace behind' ''
for ns in "$MGMT" "$DATA"; do k delete pod --all -n "$ns" --wait=false >/dev/null 2>&1; k delete svc --all -n "$ns" --wait=false >/dev/null 2>&1; done
out=$(h uninstall "$RELEASE" -n "$RNS" --wait --timeout 5m 2>&1); rc=$?
check $rc "helm uninstall returns 0" "$out"
for _ in $(seq 1 60); do k get ns "$MGMT" "$DATA" "${CTRL[@]}" >/dev/null 2>&1 || break; sleep 2; done
k get ns "$MGMT" "$DATA" "${CTRL[@]}" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "plane namespaces are gone, the control-plane namespaces with them"
k get ciliumclusterwidenetworkpolicy "${RELEASE}-allow-ambient-hostprobes" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "cluster-wide Cilium exception is gone"
k get clusterrole,clusterrolebinding "${RELEASE}-verify-layout" >/dev/null 2>&1; [ $? -ne 0 ]; check $? "no hook resource left behind (hook-succeeded policy)"
say "  the release namespace \`$RNS\` remains, as expected: it was created by --create-namespace and is not owned by the release" ''

say '' '## Result' ''
if [ "$failures" -eq 0 ]; then say 'All checks passed.'; else say "**$failures check(s) failed.**"; fi
echo "evidence written to $OUT ($failures failure(s))"
exit $(( failures > 0 ))
