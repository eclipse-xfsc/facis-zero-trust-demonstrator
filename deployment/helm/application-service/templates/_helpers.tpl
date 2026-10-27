{{- define "app.labels" -}}
app.kubernetes.io/name: {{ .Values.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "app.selector" -}}
app.kubernetes.io/name: {{ .Values.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Fail early on values the release cannot run with. */}}
{{- define "app.validate" -}}
{{- if not (regexMatch "^[a-z][a-z0-9-]{0,62}$" (.Values.name | toString)) -}}
{{- fail "name must be a DNS label" -}}
{{- end -}}
{{- if not .Values.image.repository -}}
{{- fail "image.repository is required" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; services are deployed by digest only" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.host is required when the ingress is enabled" -}}
{{- end -}}
{{- if and (or .Values.serviceAccount.create .Values.identity.spireManagedIdentity) (not .Values.serviceAccount.name) -}}
{{- fail "serviceAccount.name is required for a created or SPIRE-managed identity" -}}
{{- end -}}
{{- range $name, $ref := .Values.secretEnv -}}
{{- if or (hasKey $.Values.env $name) (not $ref.name) (not $ref.key) -}}
{{- fail "secretEnv requires name/key and must not duplicate env" -}}
{{- end -}}
{{- end -}}
{{- $names := dict -}}
{{- $paths := dict -}}
{{- range concat .Values.secretMounts .Values.configMapMounts -}}
{{- if or (not .name) (not (hasPrefix "/" .mountPath)) (eq .mountPath "/") (hasKey $names .name) (hasKey $paths .mountPath) -}}
{{- fail "mounts require unique names and unique absolute non-root paths" -}}
{{- end -}}
{{- $_ := set $names .name true -}}{{- $_ := set $paths .mountPath true -}}
{{- end -}}
{{- range .Values.secretMounts -}}{{- if not .secretName -}}{{ fail "secretMounts requires secretName" }}{{- end -}}{{- end -}}
{{- range .Values.configMapMounts -}}{{- if not .configMapName -}}{{ fail "configMapMounts requires configMapName" }}{{- end -}}{{- end -}}
{{- end -}}
