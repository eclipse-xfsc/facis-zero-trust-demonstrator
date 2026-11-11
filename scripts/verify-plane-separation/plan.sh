# The pure part of scripts/verify-plane-separation/verify.sh: the rows, their cross-check against the
# plane-separation section, the probe plan and the per-row decision over matrix.csv. Each function reads
# the files given as arguments and writes to stdout; none reads a cluster. verify.sh feeds them what it
# read from the cluster, and verify_test.sh feeds them canned input. Sourced; defines functions only.
# Needs jq, and python3 with PyYAML for yaml_docs (as scripts/lib/proof.sh's yaml_get).
#
#   plan_rows <umbrella values> <zone file> <rendered umbrella>   the allowMatrix rows, as JSON
#   plan_fixtures <fixtures dir> <rows.json>                      the fixtures checked against the rows
#   plan_crosscheck <rows.json> <doc rows TSV> <fixtures dir>     the rows against section 6
#   plan_plan <rows.json> <doc rows TSV> <namespaces.json> <services.json> <endpointslices.json> <pods.json>
#             <spire ns> <istio ns>                               the probe plan of both directions, as JSON
#   plan_reverse_crosscheck <reverse doc rows TSV>                section 6's management plane -> data plane row
#   plan_reverse_rule <namespaces.json> <policies.json> <istio ns>  the rules that open that direction
#   plan_mtls_mode <peerauthentications.json> <ns> <labels> <port> <root ns>  the mutual TLS mode in force
#   plan_decide <matrix.csv>                                      one verdict per row
# plan_fixtures, plan_crosscheck, plan_reverse_crosscheck, plan_reverse_rule and plan_decide print OK or FAIL
# lines and return 1 on a failure.
# shellcheck shell=bash disable=SC2016

# yaml_docs <file>: the non-empty YAML documents of <file>, as one JSON array (an absent file: status 1)
yaml_docs() { python3 -c 'import json,sys,yaml
print(json.dumps([d for d in yaml.safe_load_all(open(sys.argv[1])) if d]))' "$1"; }

# The rules shared by the functions below, prepended to their jq programs.
# OWN_LABELS: the labels a fixture may carry besides its row's: its own marker and the SPIRE registration
# label every meshed workload of a plane namespace carries (the ClusterSPIFFEID selects on it).
# DENY_ROWS: the DENY rows of section 6 the verifier probes with a destination of its own, by the
# destination the row's From column names; the catch-all row is found by its role.
PLAN_JQ_LIB='
def PART_OF: "verify-plane-separation";
def OWN_LABELS: ["app.kubernetes.io/part-of", "spiffe.io/spire-managed-identity"];
def DENY_ROWS: ["tspa", "spire-server"];
def TSPA_SELECTOR: {"app.kubernetes.io/name": "tspa"};
def XDS_PORT: 15012;
# the row of section 6'"'"'s table of the management plane -> data plane direction
def REVERSE_ROW: "management-to-data";
def EXAMPLES: ["estserver", "openbao", "argocd", "harbor"];
def role_of: (.metadata.annotations // {})["verify-plane-separation/role"] // "";
# the rows of section 6 as verify.sh writes them with the shared reader: from, role, verdict, name
def doc_rows: split("\n") | map(select(length > 0) | split("\t") | {from: (.[0] // ""), role: (.[1] // ""), verdict: (.[2] // ""), name: (.[3] // "")});
def doc_key: if .role | startswith("any management-plane destination") then "catch-all"
  elif .name != "" then .name
  else .from | split("→") | (if length > 1 then .[1:] | join("→") else .[0] end) | sub("^\\s+"; "") | sub("\\s+$"; "") | split(" (")[0] | ascii_downcase | gsub(" "; "-") end;
def selects($labels): (length > 0) and (to_entries | all(. as $e | $labels[$e.key] == $e.value));
# fixture_problems($fx; $rows): every row has a fixture file holding a destination, a caller and (for a row
# naming a caller'"'"'s service account) an impostor and an unlabelled caller, whose labels and service accounts
# are exactly the row'"'"'s; every object carries the part-of label. $fx maps a row name to its documents.
def fixture_problems($fx; $rows):
  [ $rows[] as $r
    | if ($fx | has($r.name) | not) then "row \($r.name): no fixture file fixtures/rows/\($r.name).yaml, so the row has no probe"
      else ($fx[$r.name]) as $docs
      | ( $docs[] | select((.metadata.labels // {})["app.kubernetes.io/part-of"] != PART_OF)
          | "row \($r.name): \(.kind) \(.metadata.name) lacks app.kubernetes.io/part-of: \(PART_OF)" ),
        ( (reduce ($docs[] | select(.kind == "Pod")) as $p ({}; .[$p | role_of] = $p)) as $pods
          | ( [["destination", $r.toSelector, $r.toServiceAccount]]
              + if $r.fromServiceAccount then [["caller", $r.fromSelector, $r.fromServiceAccount], ["impostor", $r.fromSelector, null], ["unlabelled", {}, $r.fromServiceAccount]]
                else [["caller", {}, null]] end ) as $want
          | ( $want[] as [$role, $labels, $account]
              | if ($pods | has($role) | not) then "row \($r.name): no \($role) pod in its fixture file"
                else $pods[$role] as $p
                | (($p.metadata.labels // {}) | with_entries(select(.key as $k | OWN_LABELS | index($k) | not))) as $own
                | ($p.spec.serviceAccountName) as $sa
                | (if $own != $labels then "row \($r.name): the \($role)'"'"'s labels \($own | tojson) are not the row'"'"'s \($labels | tojson)" else empty end),
                  (if $account != null and $sa != $account then "row \($r.name): the \($role)'"'"'s service account \($sa) is not the row'"'"'s \($account)" else empty end),
                  (if $role == "impostor" and $sa == $r.fromServiceAccount then "row \($r.name): the impostor runs as the row'"'"'s own service account" else empty end)
                end ),
            ( ($pods | keys) - [$want[][0]] | select(length > 0) | "row \($r.name): fixture pods of no probe: \(tojson)" ) )
      end ];
'

# plan_fixture_docs <fixtures dir> <rows.json>: the fixture documents of every row that has a file, as
# one JSON object from row name to its documents
plan_fixture_docs() {
  local name f out='{}'
  for name in $(jq -r '.[].name' "$2"); do
    f=$1/rows/$name.yaml
    [ -f "$f" ] || continue
    out=$(jq -c --arg n "$name" --argjson d "$(yaml_docs "$f")" '.[$n] = $d' <<<"$out") || return 1
  done
  echo "$out"
}

# plan_rows <umbrella values> <zone file> <rendered umbrella>: the allowMatrix rows of the zone document (the
# umbrella's values with the zone file on top, merged as scripts/install-zone merges them), each with the
# namespaces, selectors and ports of the NetworkPolicy pair the umbrella rendered for it, and the service
# accounts of the zone document (a NetworkPolicy names none)
plan_rows() {
  local base zone rendered
  base=$(yaml_docs "$1") && zone=$(yaml_docs "$2") && rendered=$(yaml_docs "$3") || return 1
  jq -n --argjson base "$base" --argjson zone "$zone" --argjson rendered "$rendered" '
    (($base[0] // {}) * ($zone[0] // {})) as $doc
    | ($doc.planes // {}) as $planes
    | (reduce ($rendered[] | select(.kind == "NetworkPolicy" and ((.metadata.annotations // {}) | has("ztd.facis.io/allow-matrix"))))
         as $p ({}; .[$p.metadata.name] = $p)) as $pols
    | def ns($e): $e.namespace // ($planes[$e.plane // ""] // {}).namespace;
      [ ($doc.allowMatrix // [])[]
        | (.from // {}) as $f | (.to // {}) as $t
        | $pols["allow-\(.name)-egress"] as $eg | $pols["allow-\(.name)-ingress"] as $ing
        | { name,
            fromNs: (if $eg then $eg.metadata.namespace else ns($f) end),
            fromSelector: (if $eg then ($eg.spec.podSelector.matchLabels // {}) else ($f.podSelector // {}) end),
            fromServiceAccount: $f.serviceAccount,
            toNs: (if $ing then $ing.metadata.namespace else ns($t) end),
            toSelector: (if $ing then ($ing.spec.podSelector.matchLabels // {}) else ($t.podSelector // {}) end),
            toServiceAccount: $t.serviceAccount,
            ports: ([($t.ports // [])[] | .port | tonumber] | sort),
            rendered: (($eg != null) and ($ing != null)) } ]'
}

# plan_fixtures <fixtures dir> <rows.json>: every row's fixture file against the row
plan_fixtures() {
  local fx out
  fx=$(plan_fixture_docs "$1" "$2") || return 1
  out=$(jq -r --argjson fx "$fx" "$PLAN_JQ_LIB"'
    fixture_problems($fx; .) as $p
    | if ($p | length) > 0 then $p[] | "FAIL " + . else "OK \(length) rows: every fixture carries exactly its row'"'"'s labels and service account" end' "$2") || return 1
  echo "$out"
  ! grep -q '^FAIL ' <<<"$out"
}

# plan_crosscheck <rows.json> <doc rows TSV> <fixtures dir>: fails on a row present in only one source, a
# verdict that disagrees, a DENY row the verifier has no probe for, an allow row the umbrella did not
# render, and a fixture that is not its row's
plan_crosscheck() {
  local fx out
  fx=$(plan_fixture_docs "$3" "$1") || return 1
  out=$(jq -r -n --slurpfile rows "$1" --rawfile doc "$2" --argjson fx "$fx" "$PLAN_JQ_LIB"'
    $rows[0] as $rows | ($doc | doc_rows) as $doc
    | (reduce $rows[] as $r ({}; .[$r.name] = $r)) as $vals
    | [$doc[] | doc_key] as $seen
    | [ ( $doc[] | doc_key as $key
          | if $key == "catch-all" then
              (if .verdict != "DENY" then "row catch-all: section 6 says \(if .verdict == "" then "nothing" else .verdict end), the verifier probes it as DENY" else empty end)
            elif ($vals | has($key)) then
              (if .verdict != "ALLOW" then "row \($key): section 6 says \(if .verdict == "" then "nothing" else .verdict end), the umbrella'"'"'s allowMatrix permits it (ALLOW)" else empty end)
            elif .verdict == "ALLOW" then "row \($key): ALLOW in section 6 but no allowMatrix row of the umbrella"
            elif (DENY_ROWS | index($key)) == null then "row \($key): DENY in section 6 but the verifier has no probe for it"
            else empty end ),
        ( $rows[] | .name as $n
          | (if ($seen | index($n)) == null then "row \(.name): allowMatrix row of the umbrella absent from section 6" else empty end),
            (if .rendered | not then "row \(.name): the umbrella rendered no NetworkPolicy pair allow-\(.name)-egress/-ingress" else empty end) ),
        ( if ($seen | index("catch-all")) == null then "row catch-all: section 6 has no catch-all row" else empty end ),
        ( DENY_ROWS[] | select(. as $k | $seen | index($k) | not) | "row \(.): probed by the verifier but absent from section 6" ),
        fixture_problems($fx; $rows)[] ] as $p
    | if ($p | length) > 0 then $p[] | "FAIL " + . else "OK \($doc | length) rows of section 6 match the \($rows | length) allowMatrix rows and the verifier'"'"'s probes" end') || return 1
  echo "$out"
  ! grep -q '^FAIL ' <<<"$out"
}

# plan_plan <rows.json> <doc rows TSV> <namespaces.json> <services.json> <endpointslices.json> <pods.json>
# <spire ns> <istio ns>: the data-plane namespaces, the destinations of the DENY and catch-all rows and the
# ports to probe on each; for the management plane -> data plane direction, the management-plane namespaces
# that exist (sourceNamespaces), those with injection, and every Service with ready endpoints in a data-plane
# namespace (reverseDestinations, row management-to-data). A catch-all destination is every Service with ready endpoints in a namespace
# labelled management plane, in the SPIRE or the Istio namespace, minus those of an allowMatrix row (probed
# by their rows). The TSPA and SPIRE server rows are told apart by their pods; a stand-in is marked as such.
# A pod address and port is a target of the first Service (in the API's order) that reaches it, so two
# Services selecting the same pods are probed once: the later one holds no targets.
plan_plan() {
  jq -n --slurpfile rows "$1" --rawfile doc "$2" --slurpfile nss "$3" --slurpfile svcs "$4" --slurpfile eps "$5" \
    --slurpfile pods "$6" --arg spire "$7" --arg istio "$8" "$PLAN_JQ_LIB"'
    $rows[0] as $rows
    | (reduce ($doc | doc_rows)[] as $d ({}; .[$d | doc_key] = $d)) as $docmap
    | ($nss[0].items // []) as $nss
    | ([$nss[] | select((.metadata.labels // {})["ztd.facis.io/plane"] == "data") | .metadata.name] | sort) as $data
    | ([$nss[] | select((.metadata.labels // {})["ztd.facis.io/plane"] == "management") | .metadata.name] + [$spire, $istio] | unique) as $mgmt
    | (reduce ($pods[0].items // [])[] as $p ({}; .["\($p.metadata.namespace)/\($p.metadata.name)"] = $p)) as $podmap
    | def tcp: (.protocol // "TCP") == "TCP";
      def pod_info: {
        name: .metadata.name,
        ip: ((.status // {}).podIP // ""),
        node: (.spec.nodeName // ""),
        serviceAccount: (.spec.serviceAccountName // "default"),
        labels: (.metadata.labels // {}),
        meshed: ([(.spec.containers // [])[], (.spec.initContainers // [])[] | select(.name == "istio-proxy")] | length > 0),
        containerPorts: ([(.spec.containers // [])[] | (.ports // [])[] | select(tcp) | .containerPort | tonumber] | unique) };
      (reduce ($eps[0].items // [])[] as $s ({};
          (($s.metadata.labels // {})["kubernetes.io/service-name"]) as $svc
          | if $svc == null or $svc == "" then . else
              "\($s.metadata.namespace)/\($svc)" as $k
              | .[$k].pods += [($s.endpoints // [])[] | select((.conditions // {}).ready != false) | (.targetRef // {}) | select(.kind == "Pod") | .name]
              | .[$k].ports += [($s.ports // [])[] | select(tcp and (.port // 0) != 0) | .port | tonumber]
            end)) as $slices
    | [$rows[] | {ns: .toNs, sel: .toSelector}] as $own
    # dests($nsset; $reverse): the destinations of the Services with ready endpoints in $nsset. Forward (data
    # -> management): minus those of an allowMatrix row, each under its DENY row or the catch-all. Reverse
    # (management -> data): every one, under the row management-to-data.
    | def dests($nsset; $reverse):
        reduce ($svcs[0].items // [])[] as $svc ({dests: [], seen: {}};
        ($svc.metadata.namespace) as $ns | ($svc.metadata.name) as $name
        | $slices["\($ns)/\($name)"] as $e
        | if ($nsset | index($ns)) == null or $e == null or (($e.pods // []) | length) == 0 then . else
            [($e.pods | unique)[] | $podmap["\($ns)/\(.)"] | select(. != null)] as $backing
            | [$backing[] | .metadata.labels // {}] as $labels
            | if ($backing | length) == 0 then .
              elif ($reverse | not) and any($own[]; .ns == $ns and (.sel as $sel | all($labels[]; . as $l | $sel | selects($l)))) then .
              else
                (if $reverse then REVERSE_ROW
                 elif $ns == $spire and all($backing[]; .metadata.name | startswith("spire-server-")) then "spire-server"
                 elif all($labels[]; . as $l | TSPA_SELECTOR | selects($l)) then "tspa" else "catch-all" end) as $row
                | [$backing[] | pod_info] as $info
                | (($e.ports // []) | unique) as $eports
                | (reduce ($info[] | . as $pi | (($pi.containerPorts + $eports) | unique)[] | {pod: $pi.name, ip: $pi.ip, node: $pi.node, port: .}) as $t
                    ({seen: .seen, targets: []};
                     "\($t.ip) \($t.port)" as $k
                     | if .seen[$k] then . else .seen[$k] = true | .targets += [$t + {declared: ($ns == $istio and $t.port == XDS_PORT)}] end)) as $tg
                | .seen = $tg.seen
                | .dests += [{
                    row: $row, role: (($docmap[$row] // {}).role // ""), namespace: $ns, service: $name,
                    selector: ($svc.spec.selector // {}),
                    servicePorts: [($svc.spec.ports // [])[] | select(tcp) | (.targetPort // .port) as $tp
                      | {port: (.port | tonumber), targetPort: (if ($tp | tostring | test("^[0-9]+$")) then ($tp | tonumber) else null end), name: (.name // "")}],
                    meshed: all($info[]; .meshed),
                    standIn: all($labels[]; .["app.kubernetes.io/part-of"] == PART_OF),
                    serviceAccount: $info[0].serviceAccount,
                    pods: $info, targets: $tg.targets }]
              end
          end) | .dests;
      dests($mgmt; false) as $dests
    | ([$dests[] | "\(.namespace)/\(.service)"] | join(" ") | ascii_downcase) as $names
    | ([$nss[] | .metadata.name]) as $present
    | {dataNamespaces: $data, managementNamespaces: $mgmt,
       sourceNamespaces: [$mgmt[] | select(. as $n | $present | index($n))],
       injectedNamespaces: ([$nss[] | select(((.metadata.labels // {})["istio-injection"] == "enabled") or ((.metadata.labels // {}) | has("istio.io/rev"))) | .metadata.name] | sort),
       destinations: $dests,
       reverseDestinations: dests($data; true),
       absentExamples: [EXAMPLES[] | select(. as $x | $names | contains($x) | not)]}'
}

# plan_reverse_crosscheck <reverse doc rows TSV>: section 6's table of the management plane -> data plane
# direction (from, verdict, name; read by verify.sh) holds the one row the verifier probes, management-to-data,
# and says DENY for it
plan_reverse_crosscheck() {
  local out
  out=$(jq -R -s -r "$PLAN_JQ_LIB"'
    [split("\n")[] | select(length > 0) | split("\t") | {from: (.[0] // ""), verdict: (.[1] // ""), name: (.[2] // "")}] as $d
    | [ (if ($d | length) == 0 then "row \(REVERSE_ROW): section 6 has no management plane -> data plane table, or it holds no row" else empty end),
        ( $d[] | select(.name != REVERSE_ROW) | "row \(if .name == "" then .from else .name end): in section 6'"'"'s management plane -> data plane table, but the verifier has no probe for it" ),
        ( $d[] | select(.name == REVERSE_ROW and .verdict != "DENY") | "row \(REVERSE_ROW): section 6 says \(if .verdict == "" then "nothing" else .verdict end), the verifier probes it as DENY" ),
        ( if ($d | length) > 0 and ([$d[] | select(.name == REVERSE_ROW)] | length) == 0 then "row \(REVERSE_ROW): probed by the verifier but absent from section 6" else empty end ) ] as $p
    | if ($p | length) > 0 then $p[] | "FAIL " + . else "OK section 6 disposes the management plane -> data plane direction as one DENY row, \(REVERSE_ROW)" end' "$1") || return 1
  echo "$out"
  ! grep -q '^FAIL ' <<<"$out"
}

# plan_reverse_rule <namespaces.json> <policies.json> <istio ns>: the rules that admit a connection initiated
# from a management-plane namespace (labelled management, plus the SPIRE and Istio namespaces' label) to a
# data-plane namespace. <policies.json> is one object {items: [...]} of NetworkPolicy, CiliumNetworkPolicy,
# CiliumClusterwideNetworkPolicy and AuthorizationPolicy objects (the rendered umbrella, or what the cluster
# holds). Section 6 disposes that
# direction as DENY by the default deny alone, so every rule found is an opening it does not dispose, named
# on a FAIL line:
#   - NetworkPolicy: an ingress rule of a data-plane namespace with no peer (every source) or a
#     namespaceSelector that selects a management-plane namespace; an egress rule of a management-plane
#     namespace with no peer or a namespaceSelector that selects a data-plane namespace. An ipBlock peer is
#     not counted: under Cilium, which the run's routing precondition requires, a CIDR rule never selects a
#     cluster endpoint.
#   - CiliumNetworkPolicy: the same, read from fromEndpoints/toEndpoints (their namespace label) and from
#     the entities "all" and "cluster".
#   - CiliumClusterwideNetworkPolicy (each of spec and specs): an ingress rule of a policy whose
#     endpointSelector can select a data-plane namespace, with the entity "all" or "cluster" or a
#     fromEndpoints selector that can select a management-plane namespace; the egress rule of one that can
#     select a management-plane namespace, mirrored. A selector is read by its namespace terms only (the pod
#     namespace label, the namespace-label keys io.cilium.k8s.namespace.labels.<key>), so a selector without
#     one selects every namespace. A policy with a nodeSelector only selects hosts, no pod. CIDR rules are not
#     counted, as above.
#   - AuthorizationPolicy (ALLOW) in a data-plane namespace or in the mesh root namespace: a rule with no
#     source (every caller), or a source whose namespaces or principals name a management-plane namespace
#     or "*"; a source given only by notPrincipals, notNamespaces or IP blocks counts as admitting it.
plan_reverse_rule() {
  local out
  out=$(jq -n -r --slurpfile nss "$1" --slurpfile pol "$2" --arg istio "$3" '
    ($nss[0].items // []) as $nss
    | (reduce $nss[] as $n ({}; .[$n.metadata.name] = (($n.metadata.labels // {}) + {"kubernetes.io/metadata.name": $n.metadata.name}))) as $nslabels
    | ([$nss[] | select((.metadata.labels // {})["ztd.facis.io/plane"] == "data") | .metadata.name]) as $data
    | ([$nss[] | select((.metadata.labels // {})["ztd.facis.io/plane"] == "management") | .metadata.name]) as $mgmt
    | def sel_matches($l): (.matchLabels // {} | to_entries | all(. as $e | $l[$e.key] == $e.value))
        and ((.matchExpressions // []) | all(. as $x | ($l[$x.key]) as $v
          | if $x.operator == "In" then ($v != null and ($x.values | index($v)) != null)
            elif $x.operator == "NotIn" then ($v == null or ($x.values | index($v)) == null)
            elif $x.operator == "Exists" then $v != null
            elif $x.operator == "DoesNotExist" then $v == null else false end));
      # selects($set): the namespaces of $set a NetworkPolicy peer'"'"'s namespaceSelector selects
      def ns_selected($set): . as $s | [$set[] | select(. as $n | $s | sel_matches($nslabels[$n] // {}))];
      def cnp_ns: (.matchLabels // {}) | (.["k8s:io.kubernetes.pod.namespace"] // .["io.kubernetes.pod.namespace"]);
      # cil_ns($set): the namespaces of $set a Cilium endpoint selector of a clusterwide policy can select. Only
      # its namespace terms are read (the pod namespace label and the namespace-label keys
      # io.cilium.k8s.namespace.labels.<key>, with or without the k8s: prefix), so a selector without one
      # selects every namespace; a selector of null selects none.
      def cil_lbls($n): {"k8s:io.kubernetes.pod.namespace": $n, "io.kubernetes.pod.namespace": $n}
        + (($nslabels[$n] // {}) | with_entries(.key |= "io.cilium.k8s.namespace.labels." + .))
        + (($nslabels[$n] // {}) | with_entries(.key |= "k8s:io.cilium.k8s.namespace.labels." + .));
      def ns_key: test("^(k8s:)?io[.]kubernetes[.]pod[.]namespace$|^(k8s:)?io[.]cilium[.]k8s[.]namespace[.]labels[.]");
      def cil_ns($set): if . == null then [] else
        {matchLabels: ((.matchLabels // {}) | with_entries(select(.key | ns_key))),
         matchExpressions: ((.matchExpressions // []) | map(select(.key | ns_key)))} as $s
        | [$set[] | select(. as $n | $s | sel_matches(cil_lbls($n)))] end;
      def name: "\(.kind) \(.metadata.namespace // "-")/\(.metadata.name)";
      [ ($pol[0].items // [])[] | . as $p | (.metadata.namespace // "") as $ns
        | if .kind == "NetworkPolicy" then
            ( if ($data | index($ns)) != null then
                (.spec.ingress // [])[] | (.from // []) as $from
                | if ($from | length) == 0 then "\($p | name): an ingress rule with no peer admits every source, the management plane included"
                  else $from[] | select(.namespaceSelector != null) | (.namespaceSelector | ns_selected($mgmt)) as $hit
                    | select($hit | length > 0) | "\($p | name): an ingress rule admits the management-plane namespace(s) \($hit | join(", "))" end
              else empty end ),
            ( if ($mgmt | index($ns)) != null then
                (.spec.egress // [])[] | (.to // []) as $to
                | if ($to | length) == 0 then "\($p | name): an egress rule with no peer admits every destination, the data plane included"
                  else $to[] | select(.namespaceSelector != null) | (.namespaceSelector | ns_selected($data)) as $hit
                    | select($hit | length > 0) | "\($p | name): an egress rule admits the data-plane namespace(s) \($hit | join(", "))" end
              else empty end )
          elif .kind == "CiliumNetworkPolicy" then
            ( if ($data | index($ns)) != null then
                (.spec.ingress // [])[] as $r
                | ( ($r.fromEntities // [])[] | select(. == "all" or . == "cluster") | "\($p | name): an ingress rule admits the entity \(.)" ),
                  ( ($r.fromEndpoints // [])[] | (cnp_ns // $ns) as $from | select(($mgmt | index($from)) != null)
                    | "\($p | name): an ingress rule admits endpoints of the management-plane namespace \($from)" )
              else empty end ),
            ( if ($mgmt | index($ns)) != null then
                (.spec.egress // [])[] as $r
                | ( ($r.toEntities // [])[] | select(. == "all" or . == "cluster") | "\($p | name): an egress rule admits the entity \(.)" ),
                  ( ($r.toEndpoints // [])[] | (cnp_ns // $ns) as $to | select(($data | index($to)) != null)
                    | "\($p | name): an egress rule admits endpoints of the data-plane namespace \($to)" )
              else empty end )
          elif .kind == "CiliumClusterwideNetworkPolicy" then
            ((.spec // empty), (.specs // [])[]) as $sp
            | ($sp.endpointSelector | cil_ns($data)) as $sdata | ($sp.endpointSelector | cil_ns($mgmt)) as $smgmt
            | ( if ($sdata | length) > 0 then
                  ($sp.ingress // [])[] as $r
                  | ( ($r.fromEntities // [])[] | select(. == "all" or . == "cluster")
                      | "\($p | name): an ingress rule of the endpoints of \($sdata | join(", ")) admits the entity \(.)" ),
                    ( ($r.fromEndpoints // [])[] | (. // {} | cil_ns($mgmt)) as $hit | select($hit | length > 0)
                      | "\($p | name): an ingress rule of the endpoints of \($sdata | join(", ")) admits endpoints of the management-plane namespace(s) \($hit | join(", "))" )
                else empty end ),
              ( if ($smgmt | length) > 0 then
                  ($sp.egress // [])[] as $r
                  | ( ($r.toEntities // [])[] | select(. == "all" or . == "cluster")
                      | "\($p | name): an egress rule of the endpoints of \($smgmt | join(", ")) admits the entity \(.)" ),
                    ( ($r.toEndpoints // [])[] | (. // {} | cil_ns($data)) as $hit | select($hit | length > 0)
                      | "\($p | name): an egress rule of the endpoints of \($smgmt | join(", ")) admits endpoints of the data-plane namespace(s) \($hit | join(", "))" )
                else empty end )
          elif .kind == "AuthorizationPolicy" and ((.spec.action // "ALLOW") == "ALLOW") and ((($data | index($ns)) != null) or $ns == $istio) then
            (.spec.rules // [])[] | (.from // []) as $from
            | if ($from | length) == 0 then "\($p | name): an ALLOW rule with no source admits every caller, the management plane included"
              else $from[] | (.source // {}) as $s
                | ([($s.namespaces // [])[], (($s.principals // [])[] | (capture("/ns/(?<n>[^/]+)/") | .n) // .)] ) as $named
                | if ($named | length) == 0 then "\($p | name): an ALLOW rule whose source names no namespace or principal (only exclusions or addresses) admits the management plane"
                  else ($named | map(select(. == "*" or (. as $n | $mgmt | index($n)) != null))) as $hit
                    | select($hit | length > 0) | "\($p | name): an ALLOW rule admits the management plane (\($hit | unique | join(", ")))" end end
          else empty end ] as $p
    | if ($p | length) > 0 then $p[] | "FAIL " + . else "OK no rule admits a connection from a management-plane namespace (\($mgmt | join(", "))) to a data-plane namespace (\($data | join(", ")))" end') || return 1
  echo "$out"
  ! grep -q '^FAIL ' <<<"$out"
}

# plan_mtls_mode <peerauthentications.json> <ns> <pod labels JSON> <port> <root ns>: the mutual TLS mode in
# force for that pod's port (STRICT, PERMISSIVE or DISABLE), by Istio's precedence: a port-level setting of a
# workload policy, then the workload policy, the namespace policy, the mesh-wide policy of the root
# namespace; UNSET inherits; nothing set is PERMISSIVE, Istio's default.
plan_mtls_mode() {
  jq -r --arg ns "$2" --argjson l "$3" --arg port "$4" --arg root "$5" '
    def m: if . == null or . == "UNSET" then null else . end;
    [(.items // [])[] | select(.metadata.namespace == $ns and ((.spec.selector.matchLabels // {}) | length > 0)
       and (.spec.selector.matchLabels | to_entries | all(. as $e | $l[$e.key] == $e.value)))] as $wl
    | [(.items // [])[] | select(.metadata.namespace == $ns and ((.spec.selector.matchLabels // {}) | length == 0))] as $nsp
    | [(.items // [])[] | select(.metadata.namespace == $root and ((.spec.selector.matchLabels // {}) | length == 0))] as $mesh
    | [ ($wl[0].spec.portLevelMtls // {})[$port].mode | m, ($wl[0].spec.mtls.mode | m), ($nsp[0].spec.mtls.mode | m), ($mesh[0].spec.mtls.mode | m) ]
    | map(select(. != null)) | .[0] // "PERMISSIVE"' "$1"
}

# The columns of matrix.csv, one line per row x caller's namespace x probe (README.md, "The record").
PLAN_COLUMNS='row,role,namespace,probe,caller,destination,port,expected,outcome,layer,evidence,kind,verdict'
# plan_decide <matrix.csv>: per row, failed when a line failed (or carries an unknown verdict), declared
# when a line is a declared opening and none failed, green otherwise; one "<row> <verdict>" line per row in
# the order of their first line. A file whose header is not PLAN_COLUMNS, or that holds no probe, decides
# nothing. Status 0 only when every row is green or declared and both directions were probed: a line of the
# row management-to-data and a line of another row. internal/bdd decides the Annex row by the same
# rule; both are held to the cases of internal/bdd/testdata/plane-matrix/.
plan_decide() {
  local header
  header=$(head -n 1 "$1" 2>/dev/null | tr -d '\r')
  if [ "$header" != "$PLAN_COLUMNS" ]; then echo "FAIL matrix.csv: the header is '${header}', expected '$PLAN_COLUMNS'"; return 1; fi
  tail -n +2 "$1" | jq -R -s -r '
    def fields: [scan("(?:^|,)(\"(?:[^\"]|\"\")*\"|[^,]*)") | .[0] | if startswith("\"") then .[1:-1] | gsub("\"\""; "\"") else . end];
    [split("\n")[] | rtrimstr("\r") | select(length > 0) | fields | {row: .[0], verdict: .[-1]}]
    | if length == 0 then ("FAIL matrix.csv holds no probe\n" | halt_error(1)) else . end
    | reduce .[] as $l ({order: [], v: {}};
        (if .v | has($l.row) then . else .order += [$l.row] | .v[$l.row] = "green" end)
        | if $l.verdict == "fail" then .v[$l.row] = "failed"
          elif $l.verdict == "declared" then (if .v[$l.row] == "green" then .v[$l.row] = "declared" else . end)
          elif ($l.verdict == "pass" or $l.verdict == "n/a") then .
          else .v[$l.row] = "failed" end)
    | . as $d | ($d.order[] | "\(.) \($d.v[.])"),
      (if ($d.v | has("management-to-data") | not) then ("FAIL matrix.csv holds no line of the row management-to-data: the management plane -> data plane direction was not probed\n" | halt_error(1))
       elif ([$d.order[] | select(. != "management-to-data")] | length) == 0 then ("FAIL matrix.csv holds no row of the data plane -> management plane direction\n" | halt_error(1))
       elif [$d.v[]] | all(. == "green" or . == "declared") then empty else ("" | halt_error(1)) end)' 2>&1
}
