#!/usr/bin/env bash
# zone-policy's no-sidecar-in-planes, as rendered for the demonstrator cluster's ambient zone
# (ADR-0018), in a throwaway kind cluster: the admission half of the proof's checks 9 and 10, for CI.
# Renders the zone with scripts/install-zone (zones/ionos.yaml and the CI overlay), creates the plane
# namespaces as the umbrella renders them (ztd-mgmt and ztd-data enrolled in the mesh, istio-system
# not), installs only the policy and its binding, and fails unless every case below behaves:
#   denied   in an enrolled namespace: the opt-out label, the inbound-capture bypass, hostNetwork, a
#            hostPort, a privileged container, hostPID, hostIPC, a hostPath volume, an added
#            capability outside the Pod Security Standards baseline (NET_ADMIN, SYS_ADMIN, ALL,
#            SYS_MODULE, DAC_READ_SEARCH, SYS_RAWIO, SYS_PTRACE; any case, with or without CAP_; in a
#            container, an init container or an ephemeral container), seccomp or AppArmor (field or
#            annotation) Unconfined, a procMount Unmasked, a Windows hostProcess, an SELinux type
#            spc_t or an SELinux user, an unsafe sysctl, a host in a probe or a lifecycle hook;
#            through pods/status the opt-out label and the bypass (the API itself refuses an AppArmor
#            annotation added on update); through pods/ephemeralcontainers a privileged, NET_ADMIN, SYS_PTRACE or
#            istio-proxy container
#   admitted a plain plane pod, a plain status update and a plain ephemeral container in an enrolled
#            namespace, and each control's allowed value there (baseline capabilities in any case
#            and with CAP_, seccomp and AppArmor RuntimeDefault, the AppArmor annotation
#            runtime/default, procMount Default, hostProcess false, SELinux type container_t, a
#            safe sysctl, an empty probe host); in istio-system a host-network pod, copies of the
#            rendered pod templates of istiod, istio-cni and ztunnel, and a status update of a
#            running pod there
# The live cluster's own pods are checked by scripts/verify-ambient-mesh/verify.sh (section 10).
#
#   BIN=<dir with kind and kubectl> scripts/verify-ambient-mesh/admission-kind.sh
#
# Needs docker, helm, curl and python3 with PyYAML. KEEP=1 leaves the cluster running for inspection.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# shellcheck source=scripts/tools/pins.env disable=SC1091
. scripts/tools/pins.env
bin="$(cd "${BIN:-.tools/bin}" && pwd)"
export PATH="$bin:$PATH"

cluster=ztd-ambient-admission
AGNHOST=registry.k8s.io/e2e-test-images/agnhost:2.53@sha256:99c6b4bb4a1e1df3f0b3752168c89358794d02258ebebc26bf21c29399011a85
work="$(mktemp -d)"
export KUBECONFIG="$work/kubeconfig"
cleanup() {
  if [ -n "${KEEP:-}" ]; then echo "kept: cluster $cluster, KUBECONFIG=$KUBECONFIG"; return; fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

RENDER_DIR="$work/render" ZONE_VALUES=deployment/helm/ztd/zones/ionos.yaml \
  ZONE_OVERLAY=deployment/helm/ztd/ci/ionos.overlay.yaml scripts/install-zone/install.sh render >/dev/null
# From the render: the plane Namespaces (ztd), the policy and its binding (zone-policy), the mesh's
# ServiceAccounts and, as Pods in the mesh root namespace, its pod templates (istiod, istio-cni, ztunnel).
python3 - "$work/render" "$work" <<'PY'
import os, sys, yaml
d, w = sys.argv[1], sys.argv[2]
def docs(name):
    return [x for x in yaml.safe_load_all(open(os.path.join(d, name + ".yaml"))) if x]
ns = [x for x in docs("ztd") if x["kind"] == "Namespace"]
vap = [x for x in docs("zone-policy") if x["kind"].startswith("ValidatingAdmissionPolicy")]
sas, shapes = [], []
for rel in ("istiod", "istio-cni", "ztunnel"):
    for x in docs(rel):
        if x["kind"] == "ServiceAccount":
            sas.append(x)
        if x["kind"] in ("Deployment", "DaemonSet"):
            t = x["spec"]["template"]
            shapes.append({"apiVersion": "v1", "kind": "Pod", "spec": t["spec"], "metadata": {
                "name": "shape-" + x["metadata"]["name"], "namespace": x["metadata"].get("namespace", "istio-system"),
                "labels": t["metadata"].get("labels", {}), "annotations": t["metadata"].get("annotations", {})}})
if len(vap) != 2 or len(shapes) < 3:
    sys.exit(f"admission-kind: render has {len(vap)} policy objects and {len(shapes)} mesh workloads")
for name, objs in (("ns", ns), ("vap", vap), ("sa", sas)):
    yaml.safe_dump_all(objs, open(os.path.join(w, name + ".yaml"), "w"))
for s in shapes:
    yaml.safe_dump(s, open(os.path.join(w, s["metadata"]["name"] + ".shape.yaml"), "w"))
PY

kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 180s >/dev/null
kubectl apply -f "$work/ns.yaml" >/dev/null
for ns in ztd-mgmt ztd-data; do
  [ "$(kubectl get namespace "$ns" -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}')" = ambient ] \
    || { echo "admission-kind: the umbrella does not enrol $ns in the mesh" >&2; exit 1; }
done
[ -z "$(kubectl get namespace istio-system -o jsonpath='{.metadata.labels.istio\.io/dataplane-mode}')" ] \
  || { echo "admission-kind: istio-system is enrolled in the mesh" >&2; exit 1; }
kubectl apply -f "$work/sa.yaml" -f "$work/vap.yaml" >/dev/null
# Every expression must type-check against the Pod schema: a warning here would be a rule that fails
# at admission (failurePolicy Fail) instead of refusing what it names.
for _ in $(seq 30); do
  tc=$(kubectl get validatingadmissionpolicy no-sidecar-in-planes -o jsonpath='{.status.observedGeneration} {.status.typeChecking}')
  [ "${tc%% *}" = 1 ] && break
  sleep 1
done
[ "${tc#* }" = '{}' ] || [ "${tc#* }" = '' ] || { echo "admission-kind: no-sidecar-in-planes does not type-check: ${tc#* }" >&2; exit 1; }
kubectl -n ztd-data run plain --image="$AGNHOST" -- pause >/dev/null
kubectl -n istio-system run mesh --image="$AGNHOST" --labels=istio.io/rev=default,sidecar.istio.io/inject=false -- pause >/dev/null
kubectl -n ztd-data wait pod/plain --for=condition=Ready --timeout=180s >/dev/null
kubectl -n istio-system wait pod/mesh --for=condition=Ready --timeout=180s >/dev/null

failed=0
pod() { # pod <namespace> <spec as a flow map>: the server-side dry run's output
  kubectl create --dry-run=server -f - 2>&1 <<YAML
apiVersion: v1
kind: Pod
metadata: {name: case, namespace: $1}
spec: $2
YAML
}
status() { kubectl -n "$1" patch pod "$2" --subresource=status --type=merge -p "$3" --dry-run=server 2>&1; }
ephemeral() { kubectl -n ztd-data patch pod plain --subresource=ephemeralcontainers --type=strategic --dry-run=server 2>&1 \
  -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"$1\",\"image\":\"$AGNHOST\"$2}]}}"; }
expect() { # expect deny|admit <message text, for deny> <title> <output>
  local got=admit
  grep -q "no-sidecar-in-planes" <<<"$4" && grep -q denied <<<"$4" && got=deny
  if [ "$1" = deny ] && [ $got = deny ] && grep -qE "$2" <<<"$4"; then echo "ok    denied:   $3"
  elif [ "$1" = admit ] && [ $got = admit ] && ! grep -qiE 'error|forbidden' <<<"$4"; then echo "ok    admitted: $3"
  else echo "FAIL  expected $1: $3"; echo "      ${4:0:400}"; failed=1; fi
}
# The policy is enforced a few seconds after it is created.
for _ in $(seq 60); do
  pod ztd-data "{hostPID: true, containers: [{name: c, image: $AGNHOST}]}" | grep -q denied && break
  sleep 2
done

C="containers: [{name: c, image: $AGNHOST}]"
c() { echo "containers: [{name: c, image: $AGNHOST, securityContext: $1}]"; }
i() { echo "initContainers: [{name: i, image: $AGNHOST, securityContext: $1}], $C"; }
PRIV='may not run a privileged container'; HOSTNS='may not share the node'; HOSTPATH='may not mount a hostPath volume'
CAPS='may not add the capability'; HOSTNET='may not use the host network'
for ns in ztd-data ztd-mgmt; do
  expect deny "$PRIV|$HOSTNS" "$ns: privileged container with hostPID" "$(pod "$ns" "{hostPID: true, $(c '{privileged: true}')}")"
  expect deny "$HOSTPATH" "$ns: a hostPath volume (/) alone" "$(pod "$ns" "{volumes: [{name: h, hostPath: {path: /}}], $C}")"
  expect deny "$CAPS" "$ns: NET_ADMIN added" "$(pod "$ns" "{$(c '{capabilities: {add: [NET_ADMIN]}}')}")"
  expect deny 'may not opt out' "$ns: istio.io/dataplane-mode=none" \
    "$(kubectl create --dry-run=server -f - 2>&1 <<<"{apiVersion: v1, kind: Pod, metadata: {name: case, namespace: $ns, labels: {istio.io/dataplane-mode: none}}, spec: {$C}}")"
  expect admit '' "$ns: a plain pod" "$(pod "$ns" "{$C}")"
done
expect deny "$HOSTNS" "ztd-data: hostPID alone" "$(pod ztd-data "{hostPID: true, $C}")"
expect deny "$HOSTNS" "ztd-data: hostIPC" "$(pod ztd-data "{hostIPC: true, $C}")"
expect deny "$HOSTNET" "ztd-data: hostNetwork" "$(pod ztd-data "{hostNetwork: true, $C}")"
expect deny "$HOSTNET" "ztd-mgmt: a hostPort" "$(pod ztd-mgmt "{containers: [{name: c, image: $AGNHOST, ports: [{containerPort: 80, hostPort: 18080}]}]}")"
expect deny "$PRIV" "ztd-data: a privileged init container" "$(pod ztd-data "{$(i '{privileged: true}')}")"
expect deny "$CAPS" "ztd-data: SYS_ADMIN added in an init container" "$(pod ztd-data "{$(i '{capabilities: {add: [SYS_ADMIN]}}')}")"
expect deny "$CAPS" "ztd-data: all added, in lower case" "$(pod ztd-data "{$(c '{capabilities: {add: [all]}}')}")"
expect deny "$CAPS" "ztd-data: cap_net_admin added" "$(pod ztd-data "{$(c '{capabilities: {add: [cap_net_admin]}}')}")"
expect admit '' "ztd-data: NET_BIND_SERVICE added, ALL dropped" "$(pod ztd-data "{$(c '{capabilities: {add: [NET_BIND_SERVICE], drop: [ALL]}}')}")"
for cap in SYS_MODULE DAC_READ_SEARCH cap_sys_rawio Sys_Ptrace NET_RAW BPF; do
  expect deny "$CAPS" "ztd-mgmt: $cap added (outside baseline)" "$(pod ztd-mgmt "{$(c "{capabilities: {add: [CHOWN, $cap]}}")}")"
done
expect admit '' "ztd-mgmt: every baseline capability added, in any case and with CAP_" \
  "$(pod ztd-mgmt "{$(c '{capabilities: {add: [AUDIT_WRITE, chown, CAP_DAC_OVERRIDE, fowner, FSETID, KILL, MKNOD, cap_net_bind_service, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT]}}')}")"
SECCOMP='may not run without a seccomp profile'; APPARMOR='may not run without an AppArmor profile'; PROC='may not unmask /proc'
WINHOST='may not run a Windows host process'; SELINUX='may not set an SELinux type'; SYSCTL='may not set a sysctl'; PROBEHOST='may not name a host in a probe'
expect deny "$SECCOMP" "ztd-data: seccomp Unconfined for the pod" "$(pod ztd-data "{securityContext: {seccompProfile: {type: Unconfined}}, $C}")"
expect deny "$SECCOMP" "ztd-data: seccomp Unconfined in an init container" "$(pod ztd-data "{$(i '{seccompProfile: {type: Unconfined}}')}")"
expect admit '' "ztd-data: seccomp RuntimeDefault" "$(pod ztd-data "{securityContext: {seccompProfile: {type: RuntimeDefault}}, $(c '{seccompProfile: {type: RuntimeDefault}}')}")"
expect deny "$APPARMOR" "ztd-mgmt: AppArmor Unconfined in a container" "$(pod ztd-mgmt "{$(c '{appArmorProfile: {type: Unconfined}}')}")"
expect deny "$APPARMOR" "ztd-mgmt: AppArmor Unconfined for the pod" "$(pod ztd-mgmt "{securityContext: {appArmorProfile: {type: Unconfined}}, $C}")"
expect deny "$APPARMOR" "ztd-mgmt: the AppArmor annotation unconfined" \
  "$(kubectl create --dry-run=server -f - 2>&1 <<<"{apiVersion: v1, kind: Pod, metadata: {name: case, namespace: ztd-mgmt, annotations: {container.apparmor.security.beta.kubernetes.io/c: unconfined}}, spec: {$C}}")"
expect admit '' "ztd-mgmt: AppArmor RuntimeDefault, and the annotation runtime/default" \
  "$(kubectl create --dry-run=server -f - 2>&1 <<<"{apiVersion: v1, kind: Pod, metadata: {name: case, namespace: ztd-mgmt, annotations: {container.apparmor.security.beta.kubernetes.io/c: runtime/default}}, spec: {$(c '{appArmorProfile: {type: RuntimeDefault}}')}}")"
expect deny "$PROC" "ztd-data: procMount Unmasked" "$(pod ztd-data "{hostUsers: false, $(c '{procMount: Unmasked}')}")"
expect admit '' "ztd-data: procMount Default" "$(pod ztd-data "{$(c '{procMount: Default}')}")"
# The API admits a hostProcess container only with hostNetwork; the hostProcess rule is checked first.
expect deny "$WINHOST" "ztd-data: a Windows hostProcess container (with hostNetwork)" "$(pod ztd-data "{hostNetwork: true, $(c '{windowsOptions: {hostProcess: true}}')}")"
expect admit '' "ztd-data: hostProcess false" "$(pod ztd-data "{$(c '{windowsOptions: {hostProcess: false}}')}")"
expect deny "$SELINUX" "ztd-mgmt: SELinux type spc_t" "$(pod ztd-mgmt "{$(c '{seLinuxOptions: {type: spc_t}}')}")"
expect deny "$SELINUX" "ztd-mgmt: an SELinux user for the pod" "$(pod ztd-mgmt "{securityContext: {seLinuxOptions: {user: system_u}}, $C}")"
expect admit '' "ztd-mgmt: SELinux type container_t" "$(pod ztd-mgmt "{$(c '{seLinuxOptions: {type: container_t, level: "s0:c1,c2"}}')}")"
expect deny "$SYSCTL" "ztd-data: the unsafe sysctl net.ipv4.ip_forward" "$(pod ztd-data "{securityContext: {sysctls: [{name: net.ipv4.ip_forward, value: '1'}]}, $C}")"
expect admit '' "ztd-data: the safe sysctl net.ipv4.ip_unprivileged_port_start" "$(pod ztd-data "{securityContext: {sysctls: [{name: net.ipv4.ip_unprivileged_port_start, value: '0'}]}, $C}")"
expect deny "$PROBEHOST" "ztd-data: a readiness probe with httpGet.host" \
  "$(pod ztd-data "{containers: [{name: c, image: $AGNHOST, readinessProbe: {httpGet: {host: 10.0.0.1, port: 80}}}]}")"
expect deny "$PROBEHOST" "ztd-mgmt: an init container's startup probe with tcpSocket.host" \
  "$(pod ztd-mgmt "{initContainers: [{name: i, image: $AGNHOST, restartPolicy: Always, startupProbe: {tcpSocket: {host: 10.0.0.1, port: 80}}}], $C}")"
expect deny "$PROBEHOST" "ztd-data: a preStop hook with httpGet.host" \
  "$(pod ztd-data "{containers: [{name: c, image: $AGNHOST, lifecycle: {preStop: {httpGet: {host: 10.0.0.1, port: 80}}}}]}")"
expect admit '' "ztd-data: a readiness probe without a host" \
  "$(pod ztd-data "{containers: [{name: c, image: $AGNHOST, readinessProbe: {httpGet: {port: 80}}, lifecycle: {preStop: {tcpSocket: {port: 80}}}}]}")"

expect deny 'may not opt out' "pods/status: the opt-out label on a running pod" \
  "$(status ztd-data plain '{"metadata":{"labels":{"istio.io/dataplane-mode":"none"}}}')"
expect deny 'bypass-inbound-capture' "pods/status: the capture bypass on a running pod" \
  "$(status ztd-data plain '{"metadata":{"annotations":{"ambient.istio.io/bypass-inbound-capture":"true"}}}')"
expect admit '' "pods/status: a plain label on a running pod" "$(status ztd-data plain '{"metadata":{"labels":{"case":"plain"}}}')"
expect deny "$PRIV" "pods/ephemeralcontainers: a privileged container" "$(ephemeral dbg ',"securityContext":{"privileged":true}')"
expect deny "$CAPS" "pods/ephemeralcontainers: NET_ADMIN added" "$(ephemeral dbg ',"securityContext":{"capabilities":{"add":["NET_ADMIN"]}}')"
expect deny "$CAPS" "pods/ephemeralcontainers: SYS_PTRACE added (kubectl debug --profile=general)" "$(ephemeral dbg ',"securityContext":{"capabilities":{"add":["SYS_PTRACE"]}}')"
expect deny 'may not carry a proxy container' "pods/ephemeralcontainers: a container istio-proxy" "$(ephemeral istio-proxy '')"
expect admit '' "pods/ephemeralcontainers: a plain container" "$(ephemeral dbg '')"

expect admit '' "istio-system: a host-network pod (not enrolled)" "$(pod istio-system "{hostNetwork: true, $C}")"
for f in "$work"/*.shape.yaml; do
  expect admit '' "istio-system: the rendered pod template $(basename "$f" .shape.yaml)" "$(kubectl create --dry-run=server -f "$f" 2>&1)"
done
expect admit '' "istio-system: a status update of a running pod" "$(status istio-system mesh '{"metadata":{"labels":{"case":"plain"}}}')"

if [ $failed -ne 0 ]; then echo "admission-kind: FAILED" >&2; exit 1; fi
echo "admission-kind: no-sidecar-in-planes behaves on every case"
