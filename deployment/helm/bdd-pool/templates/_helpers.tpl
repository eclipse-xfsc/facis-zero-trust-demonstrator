{{- define "pool.saNamespace" -}}
{{- default .root.Release.Namespace .sa.namespace -}}
{{- end -}}

{{- define "pool.labels" -}}
app.kubernetes.io/name: bdd-pool
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Namespaces an identity may look up by name: the pool and kube-system (cluster identity). */}}
{{- define "pool.lookupNamespaces" -}}
{{- toYaml (concat (list "kube-system") .Values.namespaces) -}}
{{- end -}}
