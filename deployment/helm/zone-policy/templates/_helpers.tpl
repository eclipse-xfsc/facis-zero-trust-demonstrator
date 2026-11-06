{{/*
Common labels for everything the chart creates.
*/}}
{{- define "zone-policy.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{/*
zone-policy.pairNamespace: the namespace of one endpoint of a pair, called with
(dict "root" $ "endpoint" .from|.to): its namespace when it names one, else the namespace of its
plane (planes.<plane>.namespace, a zone fact the installer fills), which must then be set.
*/}}
{{- define "zone-policy.pairNamespace" -}}
{{- $e := .endpoint -}}
{{- if $e.namespace -}}
{{- $e.namespace -}}
{{- else if eq (toString $e.plane) "management" -}}
{{- required "zone-policy: a pair names the management plane, so planes.management.namespace is required (scripts/install-zone fills it)" .root.Values.planes.management.namespace -}}
{{- else if eq (toString $e.plane) "data" -}}
{{- required "zone-policy: a pair names the data plane, so planes.data.namespace is required (scripts/install-zone fills it)" .root.Values.planes.data.namespace -}}
{{- else -}}
{{- fail (printf "zone-policy: a pair endpoint needs a plane (management|data) or a namespace, got %v" $e) -}}
{{- end -}}
{{- end }}

{{/*
zone-policy.principal: the SPIFFE principal of a pair's caller as Istio's `principals` field takes
it, the SPIFFE ID without its scheme: <trustDomain>/ns/<namespace>/sa/<serviceAccount>. Called with
(dict "root" $ "namespace" <ns> "serviceAccount" <sa>).
*/}}
{{- define "zone-policy.principal" -}}
{{- printf "%s/ns/%s/sa/%s" .root.Values.trustDomain .namespace .serviceAccount -}}
{{- end }}

{{/*
zone-policy.ciliumProxyField: CEL, true when a Cilium port rule (p, one entry of toPorts) carries the
field given as the context, one of the fields that send the port's traffic to Cilium's L7 proxy:
rules.http, rules.kafka, rules.l7, rules.l7proto, listener, serverNames, terminatingTLS or
originatingTLS. Every optional field is guarded with has() (an empty serverNames never reaches the
rule: the CRDs require at least one item).
*/}}
{{- define "zone-policy.ciliumProxyField" -}}
{{- if hasPrefix "rules." . -}}
has(p.rules) && has(p.{{ . }})
{{- else -}}
has(p.{{ . }})
{{- end -}}
{{- end }}

{{/*
zone-policy.ciliumL7Rule: CEL, true when a Cilium policy (object) carries the port field given as the
context (see zone-policy.ciliumProxyField) in any toPorts[] of any direction (ingress, egress,
ingressDeny, egressDeny) of its spec or of any entry of its specs list. Every optional field is
guarded with has(), so a policy without toPorts is not matched.
*/}}
{{- define "zone-policy.ciliumL7Rule" -}}
{{- $p := include "zone-policy.ciliumProxyField" . -}}
variables.specs.exists(s,
{{- range $i, $d := list "ingress" "egress" "ingressDeny" "egressDeny" }}
  {{ if $i }}|| {{ end }}(has(s.{{ $d }}) && s.{{ $d }}.exists(r, has(r.toPorts) && r.toPorts.exists(p, {{ $p }})))
{{- end }})
{{- end }}
