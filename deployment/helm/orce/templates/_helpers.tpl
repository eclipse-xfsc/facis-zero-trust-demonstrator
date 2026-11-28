{{- define "orce.labels" -}}
app.kubernetes.io/name: orce
app.kubernetes.io/part-of: facis-ztd
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The selector of the hand-installed Deployment, kept so the release can adopt it: a selector is immutable. */}}
{{- define "orce.selector" -}}
app.kubernetes.io/name: orce
{{- end -}}

{{- define "orce.validate" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; ORCE is deployed by digest only" -}}
{{- end -}}
{{- if not .Values.credentialsSecret -}}
{{- fail "credentialsSecret must name the Secret holding ORCE's credentials; the chart never carries them" -}}
{{- end -}}
{{- if not .Values.serviceAccountName -}}
{{- fail "serviceAccountName must name the ServiceAccount ORCE deploys with" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$" (.Values.ingress.host | toString)) -}}
{{- fail "ingress.host must be a fully qualified DNS name" -}}
{{- end -}}
{{- if or (not .Values.ingress.clusterIssuer) (not .Values.ingress.tlsSecretName) -}}
{{- fail "ingress.clusterIssuer and ingress.tlsSecretName are required: the endpoint is HTTPS only" -}}
{{- end -}}
{{- end -}}
