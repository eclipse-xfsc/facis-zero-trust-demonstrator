# Classify every object observed in a BDD pool namespace and list what violates the expected
# state. An empty .violations means the predicate holds. See docs/bdd.md for the model:
#
#   baseline     the pool's documented platform objects, with their recorded UIDs
#   helm         the release's Helm storage Secrets, each mapped to one history revision
#   expected     the top-level objects the release rendered
#   descendants  an explicit allow-list of objects the expected ones legitimately own
#   events       ignored, recorded only as a count
#   unexplained  everything else - it must always be empty
#
# Inputs: $objects (namespaced items), $expected ([{apiVersion,kind,name,uid}]),
# $history ([{revision,status}]), $documented ([{kind,name}]), $recorded ([{kind,name,uid}] or
# null), $release, $mode ("present" | "absent").

def key: "\(.kind)/\(.metadata.name)";
def has($list; $x): any($list[]; . == $x);
def controller: [(.metadata.ownerReferences // [])[] | select(.controller == true)][0];
def owned_by($kind; $uids): (controller) as $c | $c != null and $c.kind == $kind and has($uids; $c.uid);
def ready: any((.status.conditions // [])[]; .type == "Ready" and .status == "True");
def family($ip): if ($ip | contains(":")) then "IPv6" else "IPv4" end;
def selects($selector): . as $pod | all($selector | to_entries[]; $pod.metadata.labels[.key] == .value);

[$objects[] | select(.kind != "Event")] as $objs
| ($documented | map("\(.kind)/\(.name)")) as $docKeys
| ($expected | map("\(.kind)/\(.name)")) as $expKeys

# baseline
| [$objs[] | select(key as $k | has($docKeys; $k))] as $B

# helm storage for this release
| [$objs[] | select(.kind == "Secret" and .type == "helm.sh/release.v1"
                    and .metadata.labels.owner == "helm" and .metadata.labels.name == $release)] as $H

# expected top-level objects (live)
| [$objs[] | select(key as $k | has($expKeys; $k))] as $E

# ownership roots: live expected objects, plus the captured UIDs so that leftovers of an
# uninstalled release are still recognised as its descendants
| ([$E[] | select(.kind == "Deployment") | .metadata.uid]
   + [$expected[] | select(.kind == "Deployment") | .uid]) as $deployUids
| ([$E[] | select(.kind == "Service") | .metadata.uid]
   + [$expected[] | select(.kind == "Service") | .uid]) as $serviceUids
| [$E[] | select(.kind == "Service" and ((.spec.selector // {}) | length) > 0) | .metadata.name] as $selectorServices

# descendants: the allow-list, nothing else
| [$objs[] | select(.kind == "ReplicaSet" and owned_by("Deployment"; $deployUids))] as $RS
| ($RS | map(.metadata.uid)) as $rsUids
| [$objs[] | select(.kind == "Pod" and owned_by("ReplicaSet"; $rsUids))] as $P
| [$objs[] | select(.kind == "EndpointSlice" and owned_by("Service"; $serviceUids)
                    and .metadata.labels["endpointslice.kubernetes.io/managed-by"] == "endpointslice-controller.k8s.io"
                    and ((controller).uid as $owner | .metadata.labels["kubernetes.io/service-name"] as $s
                         | any($objs[]; .kind == "Service" and .metadata.uid == $owner
                                        and .metadata.name == $s)))] as $EPS
| [$objs[] | select(.kind == "Endpoints" and has($selectorServices; .metadata.name))] as $EP
| ($RS + $P + $EPS + $EP) as $D

| ($B + $H + $E + $D | map(.metadata.uid)) as $known
| [$objs[] | select(.metadata.uid as $u | has($known; $u) | not)] as $U

| (
    # --- always -------------------------------------------------------------------------
    [ $docKeys[] | . as $k | select(($B | map(key)) | has(.; $k) | not) | "baseline object missing: \($k)" ]
  + (if $recorded == null then [] else
      [ $recorded[] | "\(.kind)/\(.name)" as $k | .uid as $u
        | select(any($B[]; key == $k and .metadata.uid == $u) | not)
        | "baseline object replaced or missing (UID changed): \($k)" ]
    end)
  + [ $U[] | "unexplained object: \(key)\(if controller then " (owned by \(controller.kind)/\(controller.name))" else "" end)" ]

  + if $mode == "absent" then
      # --- release gone ------------------------------------------------------------------
      [ $H[] | "helm release record still present: \(.metadata.name)" ]
    + (if ($history | length) > 0 then ["helm history still lists \($history | length) revision(s)"] else [] end)
    + [ $expKeys[] | . as $k | select(any($objs[]; key == $k)) | "expected object still present: \($k)" ]
    + [ $D[] | "descendant still present: \(key)" ]
    else
      # --- release present and converged -------------------------------------------------
      (if ($expected | length) == 0 then ["expected inventory is empty"] else [] end)
    + [ $expected[] | "\(.kind)/\(.name)" as $k | .uid as $u
        | ([$E[] | select(key == $k)][0]) as $live
        | if $live == null then "expected object missing: \($k)"
          elif $u != null and $live.metadata.uid != $u then "expected object replaced (UID changed): \($k)"
          else empty end ]

      # readiness by kind; an unsupported workload kind fails rather than passing on existence
    + [ $E[] | key as $k
        | if .kind == "Deployment" then
            (.spec.replicas // 1) as $want
            | select(((.status.observedGeneration // 0) >= .metadata.generation
                      and (.status.updatedReplicas // 0) == $want
                      and (.status.availableReplicas // 0) == $want
                      and (.status.unavailableReplicas // 0) == 0
                      and any((.status.conditions // [])[]; .type == "Progressing" and .reason == "NewReplicaSetAvailable")) | not)
            | "deployment rollout not complete: \($k)"
          elif .kind == "StatefulSet" then
            (.spec.replicas // 1) as $want
            | select(((.status.observedGeneration // 0) >= .metadata.generation
                      and .status.currentRevision == .status.updateRevision
                      and (.status.readyReplicas // 0) == $want
                      and (.status.updatedReplicas // 0) == $want) | not)
            | "statefulset rollout not complete: \($k)"
          elif .kind == "DaemonSet" then
            select(((.status.observedGeneration // 0) >= .metadata.generation
                    and (.status.updatedNumberScheduled // 0) == .status.desiredNumberScheduled
                    and (.status.numberAvailable // 0) == .status.desiredNumberScheduled) | not)
            | "daemonset rollout not complete: \($k)"
          elif .kind == "Job" then
            select((any((.status.conditions // [])[]; .type == "Complete" and .status == "True")
                    and (any((.status.conditions // [])[]; .type == "Failed" and .status == "True") | not)) | not)
            | "job not complete: \($k)"
          elif has(["ReplicaSet", "Pod", "CronJob", "ReplicationController"]; .kind) then
            "unsupported workload kind at top level: \($k)"
          elif has(["Service", "ConfigMap", "Secret", "ServiceAccount", "Role", "RoleBinding",
                    "NetworkPolicy", "PersistentVolumeClaim", "Ingress", "PodDisruptionBudget"]; .kind) then
            empty
          else
            "unsupported kind (no readiness rule): \($k)"
          end ]

      # owned pods must be healthy
    + [ $P[] | select((ready or .status.phase == "Succeeded") | not)
        | "pod not ready: \(key) (\(.status.phase))" ]

      # duplicates: one active ReplicaSet per Deployment, and the desired number of pods
    + [ $E[] | select(.kind == "Deployment") | . as $d
        | [$RS[] | select((controller).uid == $d.metadata.uid and (.spec.replicas // 0) > 0)] as $active
        | if ($active | length) != 1 then
            "deployment \($d.metadata.name) has \($active | length) active ReplicaSets, want 1"
          else
            ([$P[] | select((controller).uid == $active[0].metadata.uid)] | length) as $n
            | select($n != ($d.spec.replicas // 1))
            | "deployment \($d.metadata.name) owns \($n) pods, want \($d.spec.replicas // 1)"
          end ]

      # endpoint consistency: the Service publishes exactly its ready, selected pods
    + [ $E[] | select(.kind == "Service" and ((.spec.selector // {}) | length) > 0) | . as $svc
        | [$P[] | select(selects($svc.spec.selector))] as $selected
        | ($selected | map(select(ready))) as $readyPods
        | ($selected | map(.metadata.uid)) as $podUids
        | ($svc.spec.ipFamilies // ["IPv4"]) as $families
        | ([ $svc.spec.ports[] | . as $p
             | { name: ($p.name // ""), protocol: ($p.protocol // "TCP"),
                 port: (if ($p.targetPort | type) == "number" then $p.targetPort
                        elif ($p.targetPort | type) == "string" then
                          ([$selected[].spec.containers[].ports[]? | select(.name == $p.targetPort) | .containerPort][0])
                        else $p.port end) } ] | sort_by(.name, .protocol, .port)) as $wantPorts
        | [$EPS[] | select(.metadata.labels["kubernetes.io/service-name"] == $svc.metadata.name)] as $slices
        | ( [ $families[] | . as $fam
              | ([$readyPods[] | .status.podIPs[]?.ip | select(family(.) == $fam)] | unique) as $want
              | ([$slices[] | select(.addressType == $fam) | .endpoints[]?
                  | select(.conditions.ready == true) | .addresses[]] | unique) as $got
              | select($want != $got)
              | "service \($svc.metadata.name) \($fam) endpoints \($got) differ from ready pods \($want)" ]
          + [ $slices[] | .metadata.name as $n | .endpoints[]? | select(.targetRef != null)
              | select((.targetRef.kind == "Pod" and has($podUids; .targetRef.uid)) | not)
              | "endpointslice \($n) points at \(.targetRef.kind)/\(.targetRef.name), not a selected pod" ]
          + [ $slices[] | .metadata.name as $n
              | ([.ports[]? | {name: (.name // ""), protocol: (.protocol // "TCP"), port}] | sort_by(.name, .protocol, .port)) as $got
              | select($got != $wantPorts)
              | "endpointslice \($n) ports \($got) differ from resolved backend ports \($wantPorts)" ]
          + ( [$EP[] | select(.metadata.name == $svc.metadata.name)][0] as $legacy
              | if $legacy == null then ["service \($svc.metadata.name) has no legacy Endpoints"] else
                  ([$readyPods[] | .status.podIPs[]?.ip | select(family(.) == $families[0])] | unique) as $want
                  | ([$legacy.subsets[]?.addresses[]?.ip] | unique) as $got
                  | ([$legacy.subsets[]?.ports[]? | {name: (.name // ""), protocol: (.protocol // "TCP"), port}]
                     | unique | sort_by(.name, .protocol, .port)) as $gotPorts
                  | (if $want != $got then ["legacy Endpoints \($svc.metadata.name) addresses \($got) differ from \($want)"] else [] end)
                  + (if ($got | length) > 0 and $gotPorts != $wantPorts
                     then ["legacy Endpoints \($svc.metadata.name) ports \($gotPorts) differ from \($wantPorts)"] else [] end)
                end ) )[] ]

      # helm storage maps one-to-one onto the history, with exactly one deployed revision
    + ( ($history | map(.revision) | sort) as $revs
        | ([$H[] | .metadata.name | capture("^sh\\.helm\\.release\\.v1\\.(?<r>.+)\\.v(?<n>[0-9]+)$")
            | select(.r == $release) | (.n | tonumber)] | sort) as $named
        | (if ($H | length) != ($revs | length) or $named != $revs
           then ["helm storage secrets \($H | map(.metadata.name)) do not map one-to-one onto history revisions \($revs)"] else [] end)
        + (([$history[] | select(.status == "deployed")] | length) as $n
           | if $n != 1 then ["helm history has \($n) deployed revisions, want 1"] else [] end) )
    end
  ) as $violations

| {
    violations: $violations,
    classes: {
      baseline: [$B[] | {kind, name: .metadata.name, uid: .metadata.uid}],
      helm: [$H[] | .metadata.name],
      expected: [$E[] | {kind, name: .metadata.name, uid: .metadata.uid}],
      descendants: [$D[] | {kind, name: .metadata.name, uid: .metadata.uid}],
      unexplained: [$U[] | {kind, name: .metadata.name}]
    },
    eventsIgnored: ([$objects[] | select(.kind == "Event")] | length)
  }
