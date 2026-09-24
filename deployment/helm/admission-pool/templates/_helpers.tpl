{{- define "admpool.labels" -}}
app.kubernetes.io/name: admission-pool
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "admpool.saNamespace" -}}
{{- default (first .Values.namespaces) .Values.tester.serviceAccount.namespace -}}
{{- end -}}
