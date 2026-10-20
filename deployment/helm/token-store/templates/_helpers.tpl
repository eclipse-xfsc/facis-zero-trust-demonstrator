{{- define "token-store.name" -}}ztd-token-store{{- end -}}

{{- define "token-store.labels" -}}
app.kubernetes.io/name: {{ include "token-store.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Fail early on values the store cannot run with. */}}
{{- define "token-store.validate" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; the store is deployed by digest only" -}}
{{- end -}}
{{- if not .Values.database.existingSecret -}}
{{- fail "database.existingSecret must name the Secret holding the connection URL; the chart never carries the credential" -}}
{{- end -}}
{{- if not .Values.database.secretKey -}}
{{- fail "database.secretKey must name the key of the connection URL in the Secret" -}}
{{- end -}}
{{- $w := int .Values.schema.hookWeight -}}
{{- if or (lt $w 40) (gt $w 59) -}}
{{- fail "schema.hookWeight must be inside the platform band, 40 to 59" -}}
{{- end -}}
{{- end -}}

{{/* The migration container: one definition for the install/upgrade Job and the uninstall Job. */}}
{{- define "token-store.migrateContainer" -}}
- name: migrate
  image: "{{ .root.Values.image.repository }}@{{ .root.Values.image.digest }}"
  args:
    {{- range .args }}
    - {{ . | quote }}
    {{- end }}
    - --timeout={{ .root.Values.schema.timeout }}
  env:
    - name: TOKEN_STORE_DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: {{ .root.Values.database.existingSecret | quote }}
          key: {{ .root.Values.database.secretKey | quote }}
  resources:
    {{- toYaml .root.Values.resources | nindent 4 }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
{{- end -}}
