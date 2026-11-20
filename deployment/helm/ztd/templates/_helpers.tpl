{{/*
Common labels for everything the chart creates.
*/}}
{{- define "ztd.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
ztd.facis.io/zone: {{ .Values.zone.name }}
{{- end }}

{{/*
The plane namespaces as a JSON list of {name, plane, mesh}: the two fixed planes, then
planes.extra. `mesh` is false only for an extra entry that sets `mesh: false` (the control-plane
namespaces), which then carries no mesh label. Read it back with fromJsonArray.
*/}}
{{- define "ztd.planeNamespaces" -}}
{{- $out := list (dict "name" .Values.planes.management.namespace "plane" "management" "mesh" true) (dict "name" .Values.planes.data.namespace "plane" "data" "mesh" true) -}}
{{- range .Values.planes.extra -}}
{{- $out = append $out (dict "name" .name "plane" .plane "mesh" (ne (toString .mesh) "false")) -}}
{{- end -}}
{{- toJson $out -}}
{{- end }}

{{/*
Namespace behind an allow-matrix endpoint: an explicit namespace, or the namespace of its plane.
Called with (dict "root" $ "endpoint" <endpoint>).
*/}}
{{- define "ztd.endpointNamespace" -}}
{{- if .endpoint.namespace -}}
{{- .endpoint.namespace -}}
{{- else if eq (toString .endpoint.plane) "management" -}}
{{- .root.Values.planes.management.namespace -}}
{{- else if eq (toString .endpoint.plane) "data" -}}
{{- .root.Values.planes.data.namespace -}}
{{- else -}}
{{- fail (printf "allowMatrix endpoint needs a plane (management|data) or a namespace, got %v" .endpoint) -}}
{{- end -}}
{{- end }}

{{/*
Mesh label key and value for the plane namespaces, by mode: sidecar (the ADR-0009 baseline of the
zones) and ambient (the demonstrator cluster's, ADR-0018; parked with Cilium) differ in this one
namespace label, in the HBONE port of the allow-matrix lanes, and, under the declared CNI
derogation, in the openings ("ztd.derogated").
*/}}
{{- define "ztd.meshLabelKey" -}}
{{- if eq .Values.mesh.mode "ambient" -}}istio.io/dataplane-mode
{{- else if eq .Values.mesh.mode "sidecar" -}}{{ if .Values.mesh.revision }}istio.io/rev{{ else }}istio-injection{{ end }}
{{- end -}}
{{- end }}

{{- define "ztd.meshLabelValue" -}}
{{- if eq .Values.mesh.mode "ambient" -}}ambient
{{- else if eq .Values.mesh.mode "sidecar" -}}{{ if .Values.mesh.revision }}{{ .Values.mesh.revision }}{{ else }}enabled{{ end }}
{{- end -}}
{{- end }}

{{/*
The declared CNI derogation (ADR-0018): "true" when the zone declares cni.derogation calico-ambient,
which is valid only with mesh.mode ambient and Cilium disabled; empty otherwise. A derogation
declared on any other zone fails the render, naming it (the schema refuses it first, but lint mode
skips nothing here and a template guard keeps the message next to the code that relies on it).
*/}}
{{- define "ztd.derogated" -}}
{{- $d := toString (.Values.cni.derogation | default "") -}}
{{- if $d -}}
{{- if ne $d "calico-ambient" -}}
{{- fail (printf "cni.derogation %q is not a declared derogation (calico-ambient, ADR-0018)" $d) -}}
{{- end -}}
{{- if or (ne .Values.mesh.mode "ambient") .Values.cni.cilium.enabled -}}
{{- fail (printf "cni.derogation calico-ambient applies to mesh.mode ambient without Cilium only (ADR-0018); this zone sets mesh.mode %s and cni.cilium.enabled %v" .Values.mesh.mode .Values.cni.cilium.enabled) -}}
{{- end -}}
true
{{- end -}}
{{- end }}

{{/*
Hook-weight scheme (docs/umbrella-chart.md). Six bands of twenty weights. A hook names its band
and an offset inside it, never a raw number, so the order between the jobs of different components
is a lookup and not a convention remembered by hand:
  preflight       0-19   checks that must hold before anything is installed
  identity       20-39   SPIRE: checks on the server, the trust bundle and the registration entries
                         (the zone-policy chart, through a copy of these helpers)
  platform       40-59   jobs of OpenBao, Harbor, TSPA, estserver, observability and admission
                         (OpenBao: the ztd-openbao chart, through a copy of these helpers)
  policy         60-79   jobs of the mesh and admission policy that depends on identity and platform
  workloads      80-99   jobs of the demonstrator workloads
  verification 100-119   read-back checks that fail the release when the layout is wrong
Hooks are for Jobs: waits and checks. A long-lived component is never a hook, because hook
resources are not tracked by the release and would survive helm uninstall. Nothing a regular
resource needs in order to become ready is a post-install hook either: with --wait, Helm runs those
hooks only after every regular resource is ready, so the install would time out. That is why a
registration is a regular resource and not a hook job.
The bands order jobs within one release. The order between releases (the umbrella, SPIRE, Istio,
zone-policy, ztd-openbao) is the installer's, scripts/install-zone/install.sh.
*/}}
{{- define "ztd.hook.weight" -}}
{{- $bands := dict "preflight" 0 "identity" 20 "platform" 40 "policy" 60 "workloads" 80 "verification" 100 -}}
{{- $band := toString .band -}}
{{- if not (hasKey $bands $band) -}}
{{- fail (printf "ztd.hook.weight: unknown band %q (preflight|identity|platform|policy|workloads|verification)" $band) -}}
{{- end -}}
{{- $offset := int (default 0 .offset) -}}
{{- if or (lt $offset 0) (gt $offset 19) -}}
{{- fail (printf "ztd.hook.weight: offset %d is outside the band (0-19)" $offset) -}}
{{- end -}}
{{- add (index $bands $band) $offset -}}
{{- end }}

{{/*
Hook annotations from the scheme. Called with
(dict "phase" "post-install,post-upgrade" "band" "identity" "offset" 5 ["deletePolicy" "..."]).
*/}}
{{- define "ztd.hook.annotations" -}}
helm.sh/hook: {{ .phase | quote }}
helm.sh/hook-weight: {{ include "ztd.hook.weight" . | quote }}
helm.sh/hook-delete-policy: {{ .deletePolicy | default "before-hook-creation,hook-succeeded" | quote }}
{{- end }}
