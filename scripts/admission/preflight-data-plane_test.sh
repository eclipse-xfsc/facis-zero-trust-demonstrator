#!/usr/bin/env bash
# Cases for preflight-data-plane.sh against a mocked kubectl (plan: each class, every workload kind
# including ReplicationControllers and CronJobs, allow-list drift between the provider and the
# constraint, a prefix with a trailing "/" under both prefix rules, repositories that differ).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat > "$work/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *configmap*) jq -c . "$MOCK/policy.json" ;;
  *k8sztdallowedrepositories*) cat "$MOCK/constraint.json" ;;
  *"get pods,"*replicationcontrollers*) cat "$MOCK/list.json" ;;
  *) echo "unexpected kubectl $*" >&2; exit 9 ;;
esac
EOF
chmod +x "$work/bin/kubectl"
export MOCK="$work" PATH="$work/bin:$PATH"

a=$(printf 'a%.0s' {1..64})
d=d86cba0dd1eb15c00b6901c69ce5ae3d2d5f8427a47751098cf8c3ab2a4a62e9
proxy="docker.io/istio/proxyv2@sha256:$d"
policy() { # repositories-json allowed-json
  printf '{"repositories":%s,"publicKeys":"x","allowedDigests":%s}' "$1" "$2" > "$work/policy.json"
}
constraint() { # repositories-json allowed-json
  printf '{"spec":{"parameters":{"repositories":%s,"allowedDigests":%s}}}' "$1" "$2" > "$work/constraint.json"
}
pods() { # kind:image ...
  local items="" kind image spec
  for p in "$@"; do
    kind=${p%%:*} image=${p#*:}
    spec="{\"containers\":[{\"name\":\"c\",\"image\":\"$image\"}]}"
    case "$kind" in
      Pod) ;;
      CronJob) spec="{\"jobTemplate\":{\"spec\":{\"template\":{\"spec\":$spec}}}}" ;;
      *) spec="{\"template\":{\"spec\":$spec}}" ;;
    esac
    items+="${items:+,}{\"kind\":\"$kind\",\"metadata\":{\"name\":\"w\"},\"spec\":$spec}"
  done
  echo "{\"items\":[$items]}" > "$work/list.json"
}

failures=0
expect() { # name want-exit grep-pattern...
  local name=$1 want=$2 got=0 p
  shift 2
  "$here/preflight-data-plane.sh" ztd-data > "$work/out" 2>&1 || got=$?
  [ "$got" = "$want" ] || { echo "FAIL  $name (exit $got, want $want)"; sed 's/^/        /' "$work/out"; failures=$((failures + 1)); return; }
  for p in "$@"; do
    grep -qE -- "$p" "$work/out" || { echo "FAIL  $name (no line matching $p)"; sed 's/^/        /' "$work/out"; failures=$((failures + 1)); return; }
  done
  echo "ok    $name"
}

org='["ghcr.io/org"]'
policy "$org" "[\"$proxy\"]"; constraint "$org" "[\"$proxy\"]"
pods "Pod:ghcr.io/org/app@sha256:$a" "ReplicationController:$proxy" "CronJob:ghcr.io/org/job@sha256:$a"
expect "trusted and allow-listed, every kind read" 0 "^trusted-repository .*Pod/w/c" "^allow-listed .*ReplicationController/w/c" \
  "^trusted-repository .*CronJob/w/c" "3 image use\(s\) in ztd-data, 0 would be denied"

pods "Deployment:busybox:1.36" "StatefulSet:docker.io/istio/proxyv2@sha256:$a" "DaemonSet:ghcr.io/org-evil/app@sha256:$a"
expect "tag, other digest, lookalike repository" 1 "^DENIED ADM-NOT-DIGEST .*busybox" \
  "^DENIED ADM-REGISTRY-DENIED .*proxyv2@sha256:$a" "^DENIED ADM-REGISTRY-DENIED .*org-evil"

policy "$org" "[\"$proxy\"]"; constraint "$org" "[]"
pods "Pod:$proxy"
expect "on the provider's allow-list only: denied, drift reported" 1 "^POLICY DRIFT" "^DENIED ADM-REGISTRY-DENIED .*proxyv2"

policy "$org" "[]"; constraint "$org" "[\"$proxy\"]"
expect "on the constraint's allow-list only: denied, drift reported" 1 "^POLICY DRIFT" "^DENIED ADM-REGISTRY-DENIED .*proxyv2"

policy "$org" "[]"; constraint "$org" "[]"
pods "Pod:ghcr.io/org/app@sha256:$a"
expect "empty allow-lists agree" 0 "0 would be denied"

slash='["ghcr.io/org/"]'
policy "$slash" "[]"; constraint "$slash" "[]"
pods "Pod:ghcr.io/org/app@sha256:$a"
expect "prefix with a trailing /: an image under it" 0 "^trusted-repository"
pods "Pod:ghcr.io/org@sha256:$a"
expect "prefix with a trailing /: the bare name (the provider denies it)" 1 "^DENIED ADM-REGISTRY-DENIED"

policy "$org" "[]"; constraint '["ghcr.io/other"]' "[]"
pods "Pod:ghcr.io/org/app@sha256:$a"
expect "allowed by the provider, not by the constraint" 1 "^DENIED ADM-REGISTRY-DENIED"

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "all preflight cases passed"
