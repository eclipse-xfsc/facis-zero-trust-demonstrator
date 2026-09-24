{{- define "admission.name" -}}ztd-admission-provider{{- end -}}

{{- define "admission.labels" -}}
app.kubernetes.io/name: {{ include "admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "admission.selector" -}}
app.kubernetes.io/name: {{ include "admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The Service's DNS names, which the server certificate carries and the Provider URL uses. */}}
{{- define "admission.dnsNames" -}}
{{- $svc := include "admission.name" . -}}
{{- $ns := .Release.Namespace -}}
{{- toYaml (list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns)) -}}
{{- end -}}

{{/* Fail early on values the provider cannot run with. */}}
{{- define "admission.validate" -}}
{{- if ne .Release.Namespace .Values.gatekeeper.namespace -}}
{{- fail (printf "install into %s (Gatekeeper's namespace), not %s" .Values.gatekeeper.namespace .Release.Namespace) -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; the provider is deployed by digest only" -}}
{{- end -}}
{{- if not .Values.trust.repositories -}}
{{- fail "trust.repositories must list at least one allowed repository prefix" -}}
{{- end -}}
{{- if not (contains "BEGIN PUBLIC KEY" .Values.trust.publicKeys) -}}
{{- fail "trust.publicKeys must hold at least one PEM public key" -}}
{{- end -}}
{{- end -}}
