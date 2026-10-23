#!/usr/bin/env bash
# Capability sheet of one cluster, measured rather than written down: Kubernetes version, nodes, CNI,
# whether NetworkPolicy is enforced, storage, LoadBalancer and ingress classes. Every capability is
# recorded as measured, unsupported (affirmative evidence only), forbidden (the identity may not do or
# see it) or unknown (the measurement was inconclusive, with the reason).
#
# It only ever creates objects under names unique to the run (ztdcap-<random>-...), with `create`, so it
# cannot adopt or alter anything that already exists, and it deletes only the objects it created. With
# cluster rights it works in a namespace of its own; with a namespace-scoped identity, pass the namespace.
# Writes the Markdown sheet to stdout; exits non-zero if it could not remove what it created.
#
#   scripts/baseline/capabilities.sh <kubeconfig> [<namespace>] > sheet.md
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <kubeconfig> [<namespace>]" >&2; exit 2; }
export KUBECONFIG="$1"
image="registry.k8s.io/e2e-test-images/agnhost:2.53"
rid="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
p="ztdcap-$rid"
wait_s="${CAPABILITY_WAIT:-180}"
k() { kubectl --request-timeout=30s "$@"; }
rows=()
row() { rows+=("| $1 | **$2** | $3 |"); }
created=() # "<kind>/<name> <uid>" of every object this run created, in creation order
own_ns=false ns_uid=""

# The API path of an object this script creates.
path_of() { # path_of <kind/name>
  local kind="${1%%/*}" name="${1#*/}"
  case "$kind" in
    namespace) echo "/api/v1/namespaces/$name" ;;
    pod) echo "/api/v1/namespaces/$ns/pods/$name" ;;
    service) echo "/api/v1/namespaces/$ns/services/$name" ;;
    persistentvolumeclaim) echo "/api/v1/namespaces/$ns/persistentvolumeclaims/$name" ;;
    networkpolicy) echo "/apis/networking.k8s.io/v1/namespaces/$ns/networkpolicies/$name" ;;
  esac
}
# delete_owned <kind/name> <uid>: deletes the object only if it is still the one this run created.
delete_owned() {
  printf '{"kind":"DeleteOptions","apiVersion":"v1","preconditions":{"uid":"%s"}}' "$2" |
    k delete --raw "$(path_of "$1")" -f - >/dev/null 2>&1
}
# gone <kind/name> <uid>: 0 removed (NotFound, or the name now holds an object that is not ours),
# 1 still present, 2 unverifiable.
gone() {
  local out
  if out="$(k get --raw "$(path_of "$1")" 2>&1)"; then
    if grep -q "\"uid\":\"$2\"" <<<"$out"; then return 1; fi
    return 0
  fi
  if grep -q NotFound <<<"$out"; then return 0; fi
  return 2
}
cleanup() {
  local i obj uid status=0 g
  if $own_ns; then
    [ -n "$ns_uid" ] || return 0
    created=("namespace/$ns $ns_uid")
  fi
  for ((i = ${#created[@]} - 1; i >= 0; i--)); do
    delete_owned "${created[i]% *}" "${created[i]#* }" || true
  done
  for obj in "${created[@]}"; do
    uid="${obj#* }" obj="${obj% *}"
    g=1
    for _ in $(seq 30); do
      g=0; gone "$obj" "$uid" || g=$?
      [ "$g" = 1 ] || break
      sleep 2
    done
    case "$g" in
      0) ;;
      1) echo "capabilities: $obj was not removed" >&2; status=1 ;;
      *) echo "capabilities: could not confirm that $obj was removed" >&2; status=1 ;;
    esac
  done
  return "$status"
}
trap 'cleanup || true' EXIT
trap 'cleanup || true; trap - EXIT; exit 130' INT TERM

# create <kind/name> <manifest>: 0 created, 3 forbidden, 2 any other failure. Only created objects are
# recorded for clean-up, with their UID; `create` refuses an existing name, so nothing foreign is taken over.
create() {
  local obj="$1" uid err
  if uid="$(k -n "$ns" create -f - -o jsonpath='{.metadata.uid}' 2>"$errf" <<<"$2")" && [ -n "$uid" ]; then
    created+=("$obj $uid")
    return 0
  fi
  err="$(cat "$errf")"
  if grep -qi forbidden <<<"$err"; then return 3; fi
  echo "capabilities: creating $obj failed: $err" >&2
  return 2
}
# can <verb> <resource> [flags]: 0 allowed, 1 denied, 2 the question could not be answered.
can() {
  local out
  out="$(k auth can-i "$@" 2>/dev/null)" || true
  # A completed review answers "yes", or "no" optionally followed by " - <reason>"; anything else
  # (no answer, an error) leaves the question open.
  if [[ "$out" == yes ]]; then return 0; fi
  if [[ "$out" =~ ^no($|[[:space:]]) ]]; then return 1; fi
  return 2
}
errf="$(mktemp)"

if [ $# -ge 2 ]; then
  ns="$2"
else
  ns="$p"
  ns_uid="$(k create -f - -o jsonpath='{.metadata.uid}' <<NS
{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"$ns","labels":{"ztd-capability-probe":"$rid"}}}
NS
)"
  own_ns=true
fi

# Containers ask for what a typical LimitRange minimum allows (100m, 128Mi).
res='{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"100m","memory":"128Mi"}}'
sec='{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"runAsUser":65534,"capabilities":{"drop":["ALL"]}}'
podjson() { # podjson <name> <role> <args json>
  printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s","labels":{"ztd-capability-probe":"%s","ztdcap-role":"%s"}},"spec":{"restartPolicy":"Never","containers":[{"name":"c","image":"%s","args":%s,"resources":%s,"securityContext":%s}]}}' \
    "$1" "$rid" "$2" "$image" "$3" "$res" "$sec"
}
# connects <name>: 0 the client reached the server, 1 it ran and was refused or timed out, 2 inconclusive
connects() {
  local name="$p-$1" phase="" logs
  create "pod/$name" "$(podjson "$name" client "[\"connect\",\"--timeout=5s\",\"$p-server.$ns.svc:8080\"]")" || return 2
  for _ in $(seq 45); do
    phase="$(k -n "$ns" get pod "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded) return 0 ;; Failed) break ;; esac
    sleep 2
  done
  [ "$phase" = Failed ] || return 2
  logs="$(k -n "$ns" logs "$name" 2>/dev/null || true)"
  if grep -qE 'TIMEOUT|REFUSED' <<<"$logs"; then return 1; fi
  return 2
}

# Version and nodes
if version="$(k version -o json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' 2>/dev/null)"; then
  row "Kubernetes version" measured "$version"
else
  row "Kubernetes version" unknown "the API server did not answer"
fi
c=0; can list nodes || c=$?
if [ "$c" = 1 ]; then
  row "Nodes" forbidden "this identity may not list nodes"
elif [ "$c" = 2 ]; then
  row "Nodes" unknown "the permission check failed"
elif nodes="$(k get nodes --no-headers 2>/dev/null)"; then
  row "Nodes" measured "$(wc -l <<<"$nodes" | tr -d ' ') visible"
else
  row "Nodes" unknown "listing nodes failed"
fi

# CNI: the daemonsets of the known plugins in kube-system
c=0; can list daemonsets -n kube-system || c=$?
if [ "$c" = 1 ]; then
  row "CNI" forbidden "this identity may not list daemonsets in kube-system"
elif [ "$c" = 2 ]; then
  row "CNI" unknown "the permission check failed"
elif ds="$(k -n kube-system get daemonsets -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)"; then
  cni="$(grep -E -o '^(cilium|calico-node|kube-flannel-ds|weave-net|kindnet|antrea-agent)' <<<"$ds" | sort -u | paste -sd, - || true)"
  if [ -n "$cni" ]; then row "CNI" measured "$cni"; else row "CNI" unknown "no known CNI daemonset in kube-system"; fi
else
  row "CNI" unknown "listing daemonsets failed"
fi

# NetworkPolicy: prove the path first, deny it, prove it closed, remove the policy, prove it open
np() { # np <reason row>
  row "NetworkPolicy enforcement" "$1" "$2"
}
rc=0
create "pod/$p-server" "$(podjson "$p-server" server '["netexec","--http-port=8080"]')" || rc=$?
if [ "$rc" = 0 ]; then
  create "service/$p-server" "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"$p-server\",\"labels\":{\"ztd-capability-probe\":\"$rid\"}},\"spec\":{\"selector\":{\"ztd-capability-probe\":\"$rid\",\"ztdcap-role\":\"server\"},\"ports\":[{\"port\":8080}]}}" || rc=$?
fi
if [ "$rc" = 3 ]; then
  np forbidden "this identity may not create the probe pods or service"
elif [ "$rc" != 0 ] || ! k -n "$ns" wait --for=condition=Ready "pod/$p-server" --timeout=120s >/dev/null 2>&1; then
  np unknown "the probe server could not be started"
else
  c=0; connects control || c=$?
  if [ "$c" != 0 ]; then
    np unknown "control failed: the client could not reach the server before any policy"
  else
    rc=0
    create "networkpolicy/$p-deny" "{\"apiVersion\":\"networking.k8s.io/v1\",\"kind\":\"NetworkPolicy\",\"metadata\":{\"name\":\"$p-deny\",\"labels\":{\"ztd-capability-probe\":\"$rid\"}},\"spec\":{\"podSelector\":{\"matchLabels\":{\"ztd-capability-probe\":\"$rid\",\"ztdcap-role\":\"server\"}},\"policyTypes\":[\"Ingress\"],\"ingress\":[]}}" || rc=$?
    if [ "$rc" = 3 ]; then
      np forbidden "this identity may not create a NetworkPolicy"
    elif [ "$rc" != 0 ]; then
      np unknown "the deny policy could not be created"
    else
      sleep 5
      # Policies are additive: any other policy that allows this traffic keeps it open, whatever the CNI.
      listed=true
      if ! all="$(k -n "$ns" get networkpolicy -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)"; then
        listed=false
      fi
      others="$(grep -v "^$p-" <<<"$all" | grep -v '^$' | paste -sd, - || true)"
      d=0; connects denied || d=$?
      if [ "$d" = 0 ] && [ -n "$others" ]; then
        np unknown "the connection survived a deny policy, but other policies in the namespace ($others) may allow it; policies are additive"
      elif [ "$d" = 0 ] && ! $listed; then
        np unknown "the connection survived a deny policy, and the other policies in the namespace could not be listed"
      elif [ "$d" = 0 ]; then
        np unsupported "a deny-all ingress policy was the only policy and the connection still succeeded"
      elif [ "$d" = 2 ]; then
        np unknown "the client under the deny policy did not run to a connection result"
      else
        dropped=false
        for o in "${created[@]}"; do
          if [ "${o% *}" = "networkpolicy/$p-deny" ] && delete_owned "${o% *}" "${o#* }"; then
            dropped=true
          fi
        done
        if ! $dropped; then
          np unknown "refused under the policy, but the policy could not be taken away to re-check the path"
        else
          sleep 5
          r=0; connects restored || r=$?
          if [ "$r" = 0 ]; then
            np measured "enforced: reachable, refused under a deny policy, reachable again once removed"
          else
            np unknown "refused under the policy but not reachable again after removing it"
          fi
        fi
      fi
    fi
  fi
fi

# Storage: classes if visible, and a claim consumed by a pod
c=0; can list storageclasses || c=$?
if [ "$c" = 1 ]; then
  row "Storage classes" forbidden "this identity may not list storage classes"
elif [ "$c" = 2 ]; then
  row "Storage classes" unknown "the permission check failed"
elif sc="$(k get storageclass -o jsonpath='{range .items[*]}{.metadata.name}{" ("}{.provisioner}{")"}{"\n"}{end}' 2>/dev/null)"; then
  row "Storage classes" measured "$(paste -sd';' - <<<"$sc")"
else
  row "Storage classes" unknown "listing storage classes failed"
fi
rc=0
create "persistentvolumeclaim/$p-claim" "{\"apiVersion\":\"v1\",\"kind\":\"PersistentVolumeClaim\",\"metadata\":{\"name\":\"$p-claim\",\"labels\":{\"ztd-capability-probe\":\"$rid\"}},\"spec\":{\"accessModes\":[\"ReadWriteOnce\"],\"resources\":{\"requests\":{\"storage\":\"1Gi\"}}}}" || rc=$?
if [ "$rc" = 0 ]; then
  create "pod/$p-volume" "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"$p-volume\",\"labels\":{\"ztd-capability-probe\":\"$rid\"}},\"spec\":{\"restartPolicy\":\"Never\",\"securityContext\":{\"fsGroup\":65534},\"containers\":[{\"name\":\"c\",\"image\":\"$image\",\"args\":[\"pause\"],\"resources\":$res,\"securityContext\":$sec,\"volumeMounts\":[{\"name\":\"v\",\"mountPath\":\"/data\"}]}],\"volumes\":[{\"name\":\"v\",\"persistentVolumeClaim\":{\"claimName\":\"$p-claim\"}}]}}" || rc=$?
fi
if [ "$rc" = 3 ]; then
  row "Persistent volume (default class)" forbidden "this identity may not create the claim or the pod"
elif [ "$rc" != 0 ]; then
  row "Persistent volume (default class)" unknown "the claim or the pod could not be created"
else
  start=$SECONDS
  if k -n "$ns" wait --for=condition=Ready "pod/$p-volume" --timeout="${wait_s}s" >/dev/null 2>&1; then
    row "Persistent volume (default class)" measured "claim bound and mounted by a pod in $((SECONDS - start)) s"
  else
    why="$(k -n "$ns" get events --field-selector "involvedObject.name=$p-claim" -o jsonpath='{.items[-1:].message}' 2>/dev/null || true)"
    row "Persistent volume (default class)" unknown "not mounted within ${wait_s} s${why:+: $why}"
  fi
fi

# LoadBalancer: an address within the wait, or unknown with the latest event
rc=0
create "service/$p-lb" "{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"$p-lb\",\"labels\":{\"ztd-capability-probe\":\"$rid\"}},\"spec\":{\"type\":\"LoadBalancer\",\"selector\":{\"ztd-capability-probe\":\"$rid\",\"ztdcap-role\":\"server\"},\"ports\":[{\"port\":8080}]}}" || rc=$?
if [ "$rc" = 3 ]; then
  row "LoadBalancer service" forbidden "this identity may not create a LoadBalancer service"
elif [ "$rc" != 0 ]; then
  row "LoadBalancer service" unknown "the service could not be created"
else
  start=$SECONDS addr=""
  while [ $((SECONDS - start)) -lt "$wait_s" ]; do
    addr="$(k -n "$ns" get service "$p-lb" -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)"
    [ -n "$addr" ] && break
    sleep 5
  done
  if [ -n "$addr" ]; then
    row "LoadBalancer service" measured "address assigned in $((SECONDS - start)) s (address not recorded)"
  else
    why="$(k -n "$ns" get events --field-selector "involvedObject.name=$p-lb" -o jsonpath='{.items[-1:].message}' 2>/dev/null || true)"
    row "LoadBalancer service" unknown "no address within ${wait_s} s${why:+: $why}"
  fi
fi

# Ingress classes
c=0; can list ingressclasses || c=$?
if [ "$c" = 1 ]; then
  row "Ingress classes" forbidden "this identity may not list ingress classes"
elif [ "$c" = 2 ]; then
  row "Ingress classes" unknown "the permission check failed"
elif ic="$(k get ingressclass -o jsonpath='{range .items[*]}{.metadata.name}{" ("}{.spec.controller}{")"}{"\n"}{end}' 2>/dev/null)"; then
  if [ -n "$ic" ]; then row "Ingress classes" measured "$(paste -sd';' - <<<"$ic")"; else row "Ingress classes" measured "none"; fi
else
  row "Ingress classes" unknown "listing ingress classes failed"
fi

identity="$(k auth whoami -o jsonpath='{.status.userInfo.username}' 2>/dev/null || echo unknown)"
trap - EXIT INT TERM
clean=0
cleanup || clean=1
rm -f "$errf"
cat <<SHEET
| Capability | Result | Detail |
|---|---|---|
$(printf '%s\n' "${rows[@]}")

Measured $(date -u +%Y-%m-%dT%H:%M:%SZ) by \`scripts/baseline/capabilities.sh\` as \`$identity\`, in namespace \`$ns\`.
SHEET
exit "$clean"
