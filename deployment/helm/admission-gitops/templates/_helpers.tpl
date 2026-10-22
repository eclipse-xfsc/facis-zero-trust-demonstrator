{{- define "admgitops.labels" -}}
app.kubernetes.io/name: admission-gitops
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- /* The sync policy of every child: automated, pruning what left Git, healing what was changed by hand. */ -}}
{{- define "admgitops.syncPolicy" -}}
automated:
  prune: true
  selfHeal: true
retry:
  {{- toYaml .Values.sync.retry | nindent 2 }}
{{- end -}}
