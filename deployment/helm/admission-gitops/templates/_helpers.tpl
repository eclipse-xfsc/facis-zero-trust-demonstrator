{{- define "admgitops.labels" -}}
app.kubernetes.io/name: admission-gitops
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- /*
The source of a child: the policy package in the registry when the parent carries a verified digest,
else the Git revision. The package holds the catalogue at its Git paths under deployment/admission,
so a child names the same path in both; an empty path is the catalogue's root.
*/ -}}
{{- define "admgitops.source" -}}
{{- $path := .path -}}
{{- with .ctx.Values -}}
{{- if and .package.repository .package.digest -}}
repoURL: {{ printf "oci://%s" .package.repository | quote }}
targetRevision: {{ .package.digest | quote }}
path: {{ $path | default "." | quote }}
{{- else -}}
repoURL: {{ .git.repoURL | quote }}
targetRevision: {{ .git.targetRevision | quote }}
path: {{ printf "deployment/admission/%s" $path | trimSuffix "/" | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- /* Fail early on values the children cannot be rendered from. */ -}}
{{- define "admgitops.validate" -}}
{{- if and .Values.package.digest (not .Values.package.repository) -}}
{{- fail "package.digest is set without package.repository" -}}
{{- end -}}
{{- if and .Values.package.digest (not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.package.digest | toString))) -}}
{{- fail "package.digest must be a sha256 digest" -}}
{{- end -}}
{{- end -}}

{{- /* The sync policy of every child: automated, pruning what left Git, healing what was changed by hand. */ -}}
{{- define "admgitops.syncPolicy" -}}
automated:
  prune: true
  selfHeal: true
retry:
  {{- toYaml .Values.sync.retry | nindent 2 }}
{{- end -}}
