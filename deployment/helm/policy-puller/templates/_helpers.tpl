{{- define "puller.name" -}}ztd-policy-puller{{- end -}}

{{- define "puller.labels" -}}
app.kubernetes.io/name: {{ include "puller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "puller.selector" -}}
app.kubernetes.io/name: {{ include "puller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Fail early on values the puller cannot run with. */}}
{{- define "puller.validate" -}}
{{- if ne .Release.Namespace .Values.argocd.namespace -}}
{{- fail (printf "install into %s (Argo CD's namespace, where the Application is), not %s" .Values.argocd.namespace .Release.Namespace) -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; the puller is deployed by digest only" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+$" (.Values.package.repository | toString)) -}}
{{- fail "package.repository must be the package's repository as host/path, without a scheme or a tag" -}}
{{- end -}}
{{- if not (contains "BEGIN PUBLIC KEY" .Values.trust.publicKeys) -}}
{{- fail "trust.publicKeys must hold at least one PEM public key" -}}
{{- end -}}
{{- end -}}
