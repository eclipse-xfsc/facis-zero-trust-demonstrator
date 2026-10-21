{{- define "tzm.name" -}}train-zone-manager{{- end -}}

{{- define "tzm.labels" -}}
app.kubernetes.io/name: {{ include "tzm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "tzm.selector" -}}
app.kubernetes.io/name: {{ include "tzm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tzm.image" -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- end -}}

{{/* The address a named server's glue carries: its own, or the zone's. */}}
{{- define "tzm.serverAddress" -}}
{{- $name := .name -}}
{{- if hasKey .root.Values.zone.serverAddresses $name -}}{{ index .root.Values.zone.serverAddresses $name }}{{- else -}}{{ .root.Values.zone.address }}{{- end -}}
{{- end -}}

{{/*
Hook annotations on the umbrella's hook-weight scheme (docs/umbrella-chart.md): band "platform"
starts at 40; the DS record runs at offset 10 within it. Written here because the helper lives in
the umbrella chart.
*/}}
{{- define "tzm.hook.annotations" -}}
helm.sh/hook: "post-install,post-upgrade"
helm.sh/hook-weight: "50"
helm.sh/hook-delete-policy: "before-hook-creation,hook-succeeded"
{{- end -}}

{{/* Fail early on values the zone manager cannot run with. */}}
{{- define "tzm.validate" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; the zone manager is deployed by digest only" -}}
{{- end -}}
{{- if not (regexMatch "^([a-z0-9-]+\\.)+[a-z0-9-]+$" (.Values.zone.name | toString)) -}}
{{- fail (printf "zone.name must be the delegated zone as a dotted name (got %q)" (.Values.zone.name | toString)) -}}
{{- end -}}
{{- if and (not .Values.zone.address) (ne .Values.service.dns.type "LoadBalancer") -}}
{{- fail "zone.address must be given unless service.dns.type is LoadBalancer, where it is discovered from the Service before the first start" -}}
{{- end -}}
{{- if not .Values.api.issuerUrl -}}
{{- fail "api.issuerUrl must be the OIDC issuer of the trust-framework manager's tokens" -}}
{{- end -}}
{{- if not .Values.api.clientId -}}
{{- fail "api.clientId must be the audience the API accepts" -}}
{{- end -}}
{{- if not .Values.storage.className -}}
{{- fail "storage.className must be the zone's storage class (zone.storageClass of the umbrella)" -}}
{{- end -}}
{{- if not (has .Values.service.dns.type (list "LoadBalancer" "NodePort" "ClusterIP")) -}}
{{- fail "service.dns.type must be LoadBalancer, NodePort or ClusterIP" -}}
{{- end -}}
{{- end -}}
