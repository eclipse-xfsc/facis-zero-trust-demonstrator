#!/usr/bin/env bash
# The admission proof's fault cases on a real cluster, run by the cluster administrator from the
# operator machine and recorded step by step. Faults are injected with the administrator identity;
# every admission is attempted with the namespaced tester identity. Workloads outside the admission
# namespaces are checked with server-side dry runs, so nothing is created there.
#
#   ADMIN_KUBECONFIG=... TESTER_KUBECONFIG=... FIXTURES=<case ref list> EVIDENCE=<dir> \
#   [BIN=...] [OUTSIDE_NAMESPACES="ns ..."] \
#   [CLUSTER_KIND=target|non-target] [DATA_NAMESPACE=ztd-data] [MGMT_NAMESPACE=ztd-mgmt] \
#   scripts/admission/fault-injection.sh
#
# OUTSIDE_NAMESPACES are the namespaces outside admission control that must stay schedulable while
# admission is down (default: the IONOS proof's ztd-orce, kube-system, ztd-bdd-tdr-001); any of them
# that carries facis.ztd/admission-proof=true on the cluster is under admission control, so it is left
# out - a caller cannot make an enforced data plane count as outside. CLUSTER_KIND is recorded with
# the evidence (default non-target, as on IONOS).
#
# Data plane: when DATA_NAMESPACE carries facis.ztd/admission-proof=true (the umbrella's
# admission.enforceDataPlane), the provider-down and Gatekeeper-down steps also expect a pod there to
# be denied, and pods in MGMT_NAMESPACE and kube-system to stay admitted. Read from the namespace, so
# there is nothing to set; without the label (or without the namespace) the steps are unchanged.
#
# Restore: before anything is changed, the provider's settings as installed are snapshotted
# (admission_installed_provider: image, replicas, trust keys, repositories, allowedDigests,
# registryAuth.secretName) and every restore puts them back - never values given by the caller, so an
# interruption after the key-removal step never leaves the test key installed and a private-registry
# credential is never dropped. The standalone layout (scripts/admission/install.sh) is restored with
# install.sh RESTORE=1 from that snapshot and needs BIN (the pinned Gatekeeper chart); the umbrella
# layout (release gatekeeper of deployment/helm/ztd) by upgrading that release with its own values and
# needs the umbrella's dependencies built (helm dependency build deployment/helm/ztd). The restore is
# proven runnable first - a server-side dry run of it - and the script refuses to inject any fault
# otherwise, so a restore that cannot run never follows a fault (the break-glass removes the webhook).
#
# Steps: ZT-13 mechanism (non-Linux and index refused), provider down, Gatekeeper down, trusted key
# removed while the provider cache is warm, break-glass (webhook removed, then restored with
# install.sh or the umbrella upgrade), and the admission latency (Gatekeeper's own webhook histogram,
# and the provider's). The admission path is restored after every step; the script exits non-zero if
# any case failed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/admission/checks.sh
. scripts/admission/checks.sh
: "${ADMIN_KUBECONFIG:?}" "${TESTER_KUBECONFIG:?}" "${FIXTURES:?}" "${EVIDENCE:?}"
layout=$(KUBECONFIG="$ADMIN_KUBECONFIG" admission_layout)
helm_home="$(mktemp -d)"
case "$layout" in
  standalone) : "${BIN:?set BIN, the directory with the pinned Gatekeeper chart}" ;;
  umbrella) KUBECONFIG="$ADMIN_KUBECONFIG" admission_helm_home "$helm_home" ;;
  *) echo "admission path not installed" >&2; exit 1 ;;
esac
snapshot="$helm_home/provider.json"
KUBECONFIG="$ADMIN_KUBECONFIG" admission_installed_provider > "$snapshot" || { echo "cannot read the installed provider" >&2; exit 1; }
TRUST_KEY="$helm_home/trusted.pub"
jq -j '.trust.publicKeys' "$snapshot" > "$TRUST_KEY"
mkdir -p "$EVIDENCE"
ns=ztd-adm-001
log="$EVIDENCE/fault-injection.log"
: > "$log"
failures=0
note() { echo "$*" | tee -a "$log"; }
pass() { note "PASS  $*"; }
fail() { note "FAIL  $*"; failures=$((failures + 1)); }
admin() { KUBECONFIG="$ADMIN_KUBECONFIG" kubectl "$@"; }
tester() { KUBECONFIG="$TESTER_KUBECONFIG" kubectl "$@"; }
fixture() { awk -v k="$1" '$1 == k {print $2}' "$FIXTURES"; }
now() { date -u +%FT%TZ; }

# A pod that meets the restricted Pod Security Standard, so a refusal is the admission policy's.
pod() { # name image namespace
  printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: %s, namespace: %s}\nspec:\n  securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: RuntimeDefault}}\n  containers:\n    - name: app\n      image: "%s"\n      command: [sleep, "3600"]\n      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}\n' "$1" "$3" "$2"
}
# Server-side dry run as the tester (admission namespace) or the administrator (elsewhere).
try() { # who name image namespace
  if [ "$1" = tester ]; then pod "$2" "$3" "$4" | tester create --dry-run=server -f - 2>&1; else pod "$2" "$3" "$4" | admin create --dry-run=server -f - 2>&1; fi
}
expect_denied() { # case code who name image namespace
  local out
  if out=$(try "$3" "$4" "$5" "$6"); then fail "$1: admitted, expected $2"; elif grep -q -- "$2" <<<"$out"; then pass "$1: denied ($2)"; else fail "$1: denied without $2: $out"; fi
  echo "$out" >> "$log"
}
expect_admitted() { # case who name image namespace
  local out
  if out=$(try "$2" "$3" "$4" "$5"); then pass "$1: admitted"; else fail "$1: denied: $out"; fi
}
# A cold verification fails closed and completes in the background; retry only while verifying.
eventually_admitted() { # case name image
  local out
  for _ in $(seq 24); do
    if out=$(try tester "$2" "$3" "$ns"); then pass "$1: admitted"; return; fi
    grep -qE 'ADM-PROVIDER-DOWN: verification (still in progress|did not finish)|failed calling webhook|no endpoints|connection refused' <<<"$out" || break
    sleep 5
  done
  fail "$1: not admitted: $out"
}
# A denial with a verdict, after any transient answer of a verification still in progress.
eventually_denied() { # case code name image
  local out status
  for _ in $(seq 24); do
    status=0; out=$(try tester "$3" "$4" "$ns") || status=$?
    if [ "$status" -eq 0 ] || ! grep -qE 'ADM-PROVIDER-DOWN: verification (still in progress|did not finish)' <<<"$out"; then break; fi
    sleep 5
  done
  echo "$out" >> "$log"
  if [ "$status" -eq 0 ]; then fail "$1: admitted, expected $2"; elif grep -q -- "$2" <<<"$out"; then pass "$1: denied ($2)"; else fail "$1: denied without $2: $out"; fi
}
# The namespaces outside admission: the given ones without any that carries the admission label.
enforced_namespaces=" $(admin get namespaces -l facis.ztd/admission-proof=true -o jsonpath='{.items[*].metadata.name}') "
outside=()
for n in ${OUTSIDE_NAMESPACES:-ztd-orce kube-system ztd-bdd-tdr-001}; do
  [[ "$enforced_namespaces" == *" $n "* ]] || outside+=("$n")
done
outside_admitted() { # step
  local n
  for n in ${outside[@]+"${outside[@]}"}; do
    expect_admitted "$1: $n pod" admin ztd-other "$(fixture unsigned)" "$n"
  done
}
signed="$(fixture app)"
data_ns=${DATA_NAMESPACE:-ztd-data}
mgmt_ns=${MGMT_NAMESPACE:-ztd-mgmt}
data_enforced=$(admin get namespace "$data_ns" -o jsonpath='{.metadata.labels.facis\.ztd/admission-proof}' 2>/dev/null || true)
# With the data plane enforced, an outage denies there (fail closed) and nowhere outside the label.
data_plane() { # step code
  [ "$data_enforced" = true ] || return 0
  expect_denied "$1: $data_ns pod (data plane enforced)" "$2" admin ztd-fi-data "$signed" "$data_ns"
  expect_admitted "$1: $mgmt_ns pod" admin ztd-other "$(fixture unsigned)" "$mgmt_ns"
  expect_admitted "$1: kube-system pod" admin ztd-other "$(fixture unsigned)" kube-system
}
provider=deploy/ztd-admission-provider
gatekeeper=deploy/gatekeeper-controller-manager

# The state to come back to, recorded before anything is changed, and restored on any exit - a
# failure or an interruption mid-step never leaves the cluster degraded.
provider_replicas=$(admin -n gatekeeper-system get "$provider" -o jsonpath='{.spec.replicas}')
gatekeeper_replicas=$(admin -n gatekeeper-system get "$gatekeeper" -o jsonpath='{.spec.replicas}')
[ -n "$provider_replicas" ] && [ -n "$gatekeeper_replicas" ] || { echo "admission path not installed" >&2; exit 1; }
# The installed digest allow-list (the provider's trust policy and the ztd-allowed-repositories
# constraint must hold the same one), passed to every reinstall so a restore never drops it; the
# installed list wins over any ALLOWED_DIGESTS in the environment.
allowed_provider=$(admin -n gatekeeper-system get configmap ztd-admission-provider-trust -o jsonpath='{.data.policy\.json}' | jq -r '.allowedDigests // [] | sort | join(" ")')
allowed_constraint=$(admin get k8sztdallowedrepositories ztd-allowed-repositories -o json | jq -r '.spec.parameters.allowedDigests // [] | sort | join(" ")')
[ "$allowed_provider" = "$allowed_constraint" ] ||
  { echo "allowedDigests differ: provider [$allowed_provider], constraint [$allowed_constraint]; reinstall first" >&2; exit 1; }
other="$(mktemp)"
# install.sh, or the umbrella release upgraded with its own values, with the recorded replica counts
# and allow-list, so a restore never changes them. In the umbrella layout the allow-list is the
# provider's trust.allowedDigests, from which the release renders the constraint's too (where it
# owns the constraint; where Argo CD does, the constraint is Argo CD's and left alone).
reinstall() {
  if [ "$layout" = standalone ]; then
    KUBECONFIG="$ADMIN_KUBECONFIG" GATEKEEPER_REPLICAS="$gatekeeper_replicas" PROVIDER_REPLICAS="$provider_replicas" \
      RESTORE=1 RESTORE_FROM="$snapshot" scripts/admission/install.sh &&
      trusted_key_installed
  else
    KUBECONFIG="$ADMIN_KUBECONFIG" admission_umbrella_upgrade --set gatekeeper.replicas="$gatekeeper_replicas" \
      --set admissionProvider.replicas="$provider_replicas" \
      --set-json "admissionProvider.trust.allowedDigests=$(jq -Rc 'split(" ") | map(select(. != ""))' <<<"$allowed_provider")" \
      --set-file admissionProvider.trust.publicKeys="$TRUST_KEY" --wait --timeout 8m &&
      KUBECONFIG="$ADMIN_KUBECONFIG" admission_wait_enforced &&
      trusted_key_installed
  fi
}
# The provider's trust policy holds the snapshotted key again.
trusted_key_installed() {
  [ "$(admin -n gatekeeper-system get configmap ztd-admission-provider-trust -o jsonpath='{.data.policy\.json}' | jq -j '.publicKeys')" = "$(cat "$TRUST_KEY")" ] ||
    { echo "the provider's trust policy does not hold the trusted key of the start" >&2; return 1; }
}
restore() {
  local status=$?
  set +e
  note "== $(now) restore (provider $provider_replicas, Gatekeeper $gatekeeper_replicas replicas, trusted key, webhook)"
  # Every recovery step runs; any that fails makes the run fail.
  admin -n gatekeeper-system scale "$gatekeeper" --replicas="$gatekeeper_replicas" >/dev/null || { note "FAIL  restore: scaling Gatekeeper"; status=1; }
  admin -n gatekeeper-system scale "$provider" --replicas="$provider_replicas" >/dev/null || { note "FAIL  restore: scaling the provider"; status=1; }
  reinstall >> "$log" 2>&1 || { note "FAIL  restore: the $layout reinstall failed"; status=1; }
  admin -n gatekeeper-system rollout status "$gatekeeper" --timeout=300s >/dev/null || { note "FAIL  restore: Gatekeeper rollout"; status=1; }
  admin -n gatekeeper-system rollout status "$provider" --timeout=300s >/dev/null || { note "FAIL  restore: provider rollout"; status=1; }
  rm -rf "$other" "$helm_home"
  exit "$status"
}
# The restore must be able to run before any fault is injected: a server-side dry run of it, which
# also proves the charts it needs are there (the pinned Gatekeeper chart, or the umbrella's built
# dependencies).
restore_runnable() {
  if [ "$layout" = standalone ]; then
    # install.sh's own preflight: the archive against its pinned digest, then server dry runs of the
    # Gatekeeper release (through the webhook-scope post-renderer) and of the provider from the snapshot.
    KUBECONFIG="$ADMIN_KUBECONFIG" GATEKEEPER_REPLICAS="$gatekeeper_replicas" PROVIDER_REPLICAS="$provider_replicas" \
      RESTORE=1 RESTORE_FROM="$snapshot" PREFLIGHT=1 scripts/admission/install.sh
  else
    KUBECONFIG="$ADMIN_KUBECONFIG" admission_umbrella_upgrade --set gatekeeper.replicas="$gatekeeper_replicas" \
      --set admissionProvider.replicas="$provider_replicas" --set-file admissionProvider.trust.publicKeys="$TRUST_KEY" --dry-run=server >/dev/null
  fi
}
if ! out=$(restore_runnable 2>&1); then
  echo "the $layout restore cannot run, so no fault is injected: $out" >&2
  rm -rf "$other" "$helm_home"
  exit 1
fi
trap restore EXIT
trap 'exit 130' INT TERM

# The provider pods that serve: Running and not being deleted (a terminating pod is still listed).
serving() {
  admin -n gatekeeper-system get pods -l app.kubernetes.io/name=ztd-admission-provider -o json |
    jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")
      | "pod/" + .metadata.name + " " + .metadata.uid + "/" + (.status.containerStatuses[0].containerID // "") + "/" + ((.status.containerStatuses[0].restartCount // 0) | tostring)'
}
# The latest trust-policy revision of every serving provider replica, "pod revision" per line; fails
# when a log cannot be read or a replica has not logged a revision.
revisions() {
  local p rev
  for p in $(serving | awk '{print $1}'); do
    rev=$(admin -n gatekeeper-system logs "$p" | grep '"trust policy loaded"' | tail -1 | grep -o '"revision":"[^"]*"') || return 1
    [ -n "$rev" ] || return 1
    echo "$p $rev"
  done
}
# Change the trusted key, keeping the given replica count (the release would otherwise reset it and
# replace the pods under test); wait until the same set of replicas has each loaded one new revision.
set_trust() { # key-file replicas
  local before after
  before=$(revisions) || return 1
  KUBECONFIG="$ADMIN_KUBECONFIG" admission_provider_upgrade --set replicas="$2" --set-file trust.publicKeys="$1" --wait >/dev/null
  for _ in $(seq 120); do
    if after=$(revisions) && [ "$(awk '{print $1}' <<<"$after")" = "$(awk '{print $1}' <<<"$before")" ] &&
      ! grep -qxF -f <(echo "$before") <<<"$after" && [ "$(awk '{print $2}' <<<"$after" | sort -u | wc -l)" -eq 1 ] &&
      ! grep -qF -f <(awk '{print $2}' <<<"$before") <<<"$(awk '{print $2}' <<<"$after")"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

note "== $(now) baseline ($layout layout)"
if [ "$data_enforced" = true ]; then note "data plane $data_ns enforced (facis.ztd/admission-proof=true)"; else note "data plane $data_ns not enforced"; fi
admin get pods -A -o wide > "$EVIDENCE/pods-before.txt"
admin get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration -o yaml > "$EVIDENCE/webhook.yaml"
eventually_admitted "signed image" ztd-fi-signed "$signed"
eventually_denied "unsigned image" ADM-UNSIGNED ztd-fi-unsigned "$(fixture unsigned)"

note "== $(now) ZT-13 mechanism (non-target evidence; the row stays pending)"
eventually_denied "non-Linux image, signed and attested" ADM-NOT-LINUX ztd-fi-windows "$(fixture windows)"
eventually_denied "image index, signed and attested" ADM-INDEX-UNSUPPORTED ztd-fi-index "$(fixture index)"

note "== $(now) provider down"
admin -n gatekeeper-system scale "$provider" --replicas=0 >/dev/null
admin -n gatekeeper-system wait --for=delete pod -l app.kubernetes.io/name=ztd-admission-provider --timeout=180s >/dev/null 2>&1 || true
expect_denied "signed image, provider down" ADM-PROVIDER-DOWN tester ztd-fi-signed "$signed" "$ns"
outside_admitted "provider down"
data_plane "provider down" ADM-PROVIDER-DOWN
admin -n gatekeeper-system scale "$provider" --replicas="$provider_replicas" >/dev/null
admin -n gatekeeper-system rollout status "$provider" --timeout=300s >/dev/null
eventually_admitted "signed image, provider back" ztd-fi-signed "$signed"

note "== $(now) Gatekeeper down"
admin -n gatekeeper-system scale "$gatekeeper" --replicas=0 >/dev/null
admin -n gatekeeper-system wait --for=delete pod -l control-plane=controller-manager --timeout=180s >/dev/null 2>&1 || true
expect_denied "signed image, Gatekeeper down" "failed calling webhook" tester ztd-fi-signed "$signed" "$ns"
outside_admitted "Gatekeeper down"
data_plane "Gatekeeper down" "failed calling webhook"
admin -n gatekeeper-system scale "$gatekeeper" --replicas="$gatekeeper_replicas" >/dev/null
admin -n gatekeeper-system rollout status "$gatekeeper" --timeout=300s >/dev/null
eventually_admitted "signed image, Gatekeeper back" ztd-fi-signed "$signed"

note "== $(now) trusted key removed while the provider cache is warm"
# One fresh provider replica, so the cache that answers is known to hold a positive verdict made at a
# known time (a cache hit does not extend it), and the same replica must answer after the change.
# Scaled to one replica, whose pod is then replaced (the pod template stays as the release has it).
admin -n gatekeeper-system scale "$provider" --replicas=1 >/dev/null
admin -n gatekeeper-system rollout status "$provider" --timeout=300s >/dev/null
admin -n gatekeeper-system delete pod -l app.kubernetes.io/name=ztd-admission-provider --wait=true >/dev/null
admin -n gatekeeper-system rollout status "$provider" --timeout=300s >/dev/null
for _ in $(seq 90); do [ "$(serving | wc -l)" -eq 1 ] && [ "$(admin -n gatekeeper-system get pods -l app.kubernetes.io/name=ztd-admission-provider -o name | wc -l)" -eq 1 ] && break; sleep 2; done
[ "$(serving | wc -l)" -eq 1 ] || { fail "trusted key removed: the provider did not settle on one serving replica"; exit 1; }
warm_pod=$(serving | awk '{print $2}')
eventually_admitted "signed image, verified into a fresh cache" ztd-fi-signed "$signed"
verified_at=$(date +%s)
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl ec -pubout 2>/dev/null > "$other"
if ! set_trust "$other" 1; then
  fail "trusted key removed: the provider did not load the new trust policy"
else
  elapsed=$(( $(date +%s) - verified_at ))
  if [ "$(serving | awk '{print $2}')" != "$warm_pod" ]; then
    fail "trusted key removed: the provider container was replaced or restarted during the test (its cache with it)"
  elif [ "$elapsed" -ge 240 ]; then
    fail "trusted key removed: reloaded ${elapsed}s after the verdict was cached, too close to its 300 s lifetime"
  else
    expect_denied "trusted key removed (reloaded ${elapsed}s after the verdict was cached): next admission" ADM-UNSIGNED tester ztd-fi-signed "$signed" "$ns"
    # The same container, with the same cache, must have answered that admission.
    [ "$(serving | awk '{print $2}')" = "$warm_pod" ] || fail "trusted key removed: the provider container changed during the admission"
  fi
fi
set_trust "$TRUST_KEY" 1 || fail "trusted key restored: the provider did not reload"
admin -n gatekeeper-system scale "$provider" --replicas="$provider_replicas" >/dev/null
admin -n gatekeeper-system rollout status "$provider" --timeout=300s >/dev/null
eventually_admitted "signed image, trusted key restored" ztd-fi-signed "$signed"

note "== $(now) break-glass"
admin delete validatingwebhookconfiguration gatekeeper-validating-webhook-configuration >/dev/null
expect_admitted "break-glass: unsigned image admitted while the webhook is removed" tester ztd-fi-unsigned "$(fixture unsigned)" "$ns"
outside_admitted "break-glass"
note "restoring ($layout layout)"
reinstall >> "$log" 2>&1 || fail "break-glass: the $layout restore did not complete"
eventually_denied "after restore: unsigned image" ADM-UNSIGNED ztd-fi-unsigned "$(fixture unsigned)"
eventually_admitted "after restore: signed image" ztd-fi-signed "$signed"

note "== $(now) admission latency"
# Every provider replica must hold the verdict before the load: a cold replica fails closed while it
# verifies. Requests are balanced across replicas, so warm until 20 in a row are admitted.
streak=0
for _ in $(seq 120); do
  if try tester ztd-fi-signed "$signed" "$ns" >/dev/null; then streak=$((streak + 1)); else streak=0; sleep 2; fi
  [ "$streak" -ge 20 ] && break
done
if [ "$streak" -ge 20 ]; then pass "warm-up: 20 consecutive admissions"; else fail "warm-up: never 20 consecutive admissions"; fi
# Every Gatekeeper webhook replica's metrics, one file per pod, with its UID and restart count, read
# through the API server's pod proxy.
scrape() { # dir
  local p
  mkdir -p "$1"
  admin -n gatekeeper-system get pods -l control-plane=controller-manager \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.uid} {.status.containerStatuses[0].restartCount}{"\n"}{end}' > "$1/pods.txt"
  while read -r p _; do
    # A replica that has served no validation request yet exposes no histogram: zero, not a failure;
    # the delta reconciliation below still requires the load to appear in the sum.
    admin get --raw "/api/v1/namespaces/gatekeeper-system/pods/$p:8888/proxy/metrics" < /dev/null > "$1/$p.txt" || return 1
    grep -q '^gatekeeper_' "$1/$p.txt" || return 1
  done < "$1/pods.txt"
}
requests=200 admitted=0 scraped=
if scrape "$EVIDENCE/latency-before"; then
  for i in $(seq "$requests"); do
    if out=$(try tester "ztd-fi-latency-$i" "$signed" "$ns"); then admitted=$((admitted + 1)); else echo "latency request $i: $out" >> "$log"; fi
  done
  scrape "$EVIDENCE/latency-after" && scraped=1
fi
p99=none
if [ -z "$scraped" ]; then
  fail "admission latency: the Gatekeeper metrics of every replica could not be read"
elif [ "$admitted" -ne "$requests" ]; then
  fail "admission latency: $admitted of $requests requests admitted"
elif ! cmp -s "$EVIDENCE/latency-before/pods.txt" "$EVIDENCE/latency-after/pods.txt"; then
  fail "admission latency: a Gatekeeper replica restarted or changed during the load"
else
  # Per replica, the bucket deltas of the validation histogram (a negative delta is a counter reset);
  # summed, the smallest bucket holding 99 % of the requests is the p99 upper bound.
  p99=$(while read -r p _; do
      awk -v pod="$p" '/^gatekeeper_validation_request_duration_seconds_bucket/ {
          match($1, /le="[^"]*"/); le = substr($1, RSTART + 4, RLENGTH - 5)
          if (FNR == NR) b[$1] = $2; else { d = $2 - b[$1]; if (d < 0) { print "reset"; exit } sum[le] += d }
        } END { for (le in sum) print le, sum[le] }' "$EVIDENCE/latency-before/$p.txt" "$EVIDENCE/latency-after/$p.txt"
    done < "$EVIDENCE/latency-after/pods.txt" | awk -v want="$requests" '
      $1 == "reset" { print "reset"; exit }
      { d[$1] += $2 }
      END {
        total = d["+Inf"]
        if (total < want || total > want + 10) { print "count " total; exit }
        best = "+Inf"; bestv = 1e18
        for (le in d) if (le != "+Inf" && d[le] >= 0.99 * total && le + 0 < bestv) { bestv = le + 0; best = le }
        print best, total
      }')
  note "Gatekeeper validation requests during the load: p99 <= ${p99%% *} s (${p99#* } observations for $requests admitted requests)"
  case "$p99" in
    reset*|count*|+Inf*) fail "admission latency: not measurable ($p99)" ;;
    *) if awk -v v="${p99%% *}" 'BEGIN { exit !(v + 0 < 1.5) }'; then pass "admission p99 <= ${p99%% *} s (< 1.5 s)"; else fail "admission p99 ${p99%% *} s >= 1.5 s"; fi ;;
  esac
fi

note "== $(now) after"
admin get pods -A -o wide > "$EVIDENCE/pods-after.txt"
note "evidence: ${CLUSTER_KIND:-non-target} cluster; interim signing key; not the client trust chain"
[ "$failures" -eq 0 ] || { note "$failures case(s) failed"; exit 1; }
note "all fault cases passed"
