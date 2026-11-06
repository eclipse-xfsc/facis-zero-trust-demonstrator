# shellcheck shell=bash
# The cases of zone-policy's L7 owner rule (l7-owner-is-the-mesh), sent as real requests to an API
# server: every document of fixtures/cilium-l7.yaml, in file order. Used by the mesh identity proof
# (scripts/verify-mesh-identity/verify.sh, section cilium-l7-refused-in-planes); the same function runs
# the rule's test against a bare API server with the Cilium CRDs. Sourced, never run. Needs kubectl,
# python3 with PyYAML.
#
#   cilium_l7_cases <context> <fixture> <data namespace> <management namespace> <outside namespace>
#       sends each case and prints one tab-separated line per case:
#         <case> <expect> <outcome> <PASS|FAIL> <detail>
#       outcome is one of: refused-by-rule (the refusal names l7-owner-is-the-mesh), refused-by-schema
#       (the CRD schema refused a field it does not define), refused-otherwise, admitted, not-served
#       (the API server serves no such kind, so no such object can be created). A case passes when:
#         expect refused   refused-by-rule, or refused-by-schema for a case annotated
#                          verify.ztd.facis.io/refused-by: rule-or-schema;
#         expect admitted  admitted; in the outside namespace, anything but refused-by-rule (the
#                          zone's rule does not refuse it; another admission rule may);
#         either           not-served.
#       A case in the outside namespace is sent as a server-side dry run (nothing stored). A case
#       annotated verify.ztd.facis.io/update-of is sent with kubectl replace (an UPDATE), the others with
#       kubectl create. Admitted objects stay until cilium_l7_cleanup.
#   cilium_l7_cleanup <context> <data namespace>
#       deletes every Cilium policy and Envoy configuration labelled
#       app.kubernetes.io/part-of=verify-mesh-identity in the data namespace and cluster-wide, and
#       prints what is left (nothing when the cleanup is complete)

cilium_l7_cases() {
  local ctx=$1 fixture=$2 data=$3 mgmt=$4 outside=$5 dir doc name expect by update ns kind verb dry out rc outcome pass detail
  dir=$(mktemp -d)
  sed -e "s/__DATA__/$data/g" -e "s/__MGMT__/$mgmt/g" -e "s/__OUTSIDE__/$outside/g" "$fixture" | python3 -c '
import sys, yaml
for i, d in enumerate(d for d in yaml.safe_load_all(sys.stdin) if d):
    a = d["metadata"]["annotations"]
    path = f"{sys.argv[1]}/{i:02d}.yaml"
    yaml.safe_dump(d, open(path, "w"), sort_keys=False)
    print("\t".join([path, a["verify.ztd.facis.io/case"], a["verify.ztd.facis.io/expect"],
                     a.get("verify.ztd.facis.io/refused-by", "rule"), a.get("verify.ztd.facis.io/update-of", "-"),
                     d["metadata"].get("namespace", "-"), d["kind"]]))' "$dir" >"$dir/index" || { rm -rf "$dir"; return 1; }
  while IFS=$'\t' read -r doc name expect by update ns kind; do
    verb=create; [ "$update" != - ] && verb=replace
    dry=(); [ "$ns" = "$outside" ] && dry=(--dry-run=server)
    out=$(kubectl --context "$ctx" "$verb" "${dry[@]}" -f "$doc" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then outcome=admitted
    elif grep -q "l7-owner-is-the-mesh" <<<"$out"; then outcome=refused-by-rule
    elif grep -qiE "no matches for kind|the server doesn't have a resource type" <<<"$out"; then outcome=not-served
    elif grep -qE "strict decoding error|unknown field|must validate one and only one schema|Unsupported value" <<<"$out"; then outcome=refused-by-schema
    else outcome=refused-otherwise; fi
    pass=FAIL
    case $expect/$outcome in
      */not-served|refused/refused-by-rule) pass=PASS;;
      refused/refused-by-schema) [ "$by" = rule-or-schema ] && pass=PASS;;
      admitted/admitted) pass=PASS;;
      admitted/*) [ "$ns" = "$outside" ] && [ "$outcome" != refused-by-rule ] && pass=PASS;;
    esac
    detail=$(grep -o "denied request: .*" <<<"$out" | head -1)
    [ -n "$detail" ] || detail=$(head -c 400 <<<"$out")
    detail="$kind ${ns/#-/<cluster>}, $verb${dry:+ (server dry run)}: $(tr '\n\t' '  ' <<<"$detail" | cut -c1-500)"
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$expect" "$outcome" "$pass" "$detail"
  done <"$dir/index"
  rm -rf "$dir"
}

cilium_l7_cleanup() {
  local ctx=$1 data=$2 sel=app.kubernetes.io/part-of=verify-mesh-identity served r
  served=$(kubectl --context "$ctx" api-resources --api-group=cilium.io -o name 2>/dev/null)
  for r in ciliumnetworkpolicies ciliumenvoyconfigs; do
    grep -qx "$r.cilium.io" <<<"$served" && kubectl --context "$ctx" -n "$data" delete "$r" -l "$sel" --wait=true >/dev/null 2>&1
  done
  for r in ciliumclusterwidenetworkpolicies ciliumclusterwideenvoyconfigs; do
    grep -qx "$r.cilium.io" <<<"$served" && kubectl --context "$ctx" delete "$r" -l "$sel" --wait=true >/dev/null 2>&1
  done
  for r in ciliumnetworkpolicies ciliumenvoyconfigs; do
    grep -qx "$r.cilium.io" <<<"$served" && { kubectl --context "$ctx" -n "$data" get "$r" -l "$sel" -o name 2>/dev/null || echo "a read of $r failed"; }
  done
  for r in ciliumclusterwidenetworkpolicies ciliumclusterwideenvoyconfigs; do
    grep -qx "$r.cilium.io" <<<"$served" && { kubectl --context "$ctx" get "$r" -l "$sel" -o name 2>/dev/null || echo "a read of $r failed"; }
  done
  return 0
}
