{{- define "token-store.name" -}}ztd-token-store{{- end -}}

{{- define "token-store.labels" -}}
app.kubernetes.io/name: {{ include "token-store.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The service's pods, and only them: the migration Jobs' pods carry the same name and instance
labels, so the component keeps them out of the Service and the Deployment's selector.
*/}}
{{- define "token-store.selector" -}}
app.kubernetes.io/name: {{ include "token-store.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
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
{{- if not (regexMatch "^https?://(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/?$" (.Values.openbao.address | toString)) -}}
{{- fail "openbao.address must be the key-value store's base URL, http(s)://host[:port] with a DNS name or an IP, nothing more" -}}
{{- end -}}
{{- if not .Values.serviceAccount.name -}}
{{- fail "serviceAccount.name must name the ServiceAccount the service runs as; it is the last segment of the store's SPIFFE ID" -}}
{{- end -}}
{{- if not .Values.serviceAccount.schemaName -}}
{{- fail "serviceAccount.schemaName must name the ServiceAccount the migration Jobs run as" -}}
{{- end -}}
{{- if lt (int .Values.replicas) 1 -}}
{{- fail "replicas must be 1 or more" -}}
{{- end -}}
{{- if lt (int .Values.server.readinessTimeoutSeconds) 1 -}}
{{- fail "server.readinessTimeoutSeconds must be a whole number of seconds, 1 or more" -}}
{{- end -}}
{{- if lt (int .Values.server.shutdownTimeoutSeconds) 1 -}}
{{- fail "server.shutdownTimeoutSeconds must be a whole number of seconds, 1 or more" -}}
{{- end -}}
{{- if lt (int .Values.server.drainDelaySeconds) 0 -}}
{{- fail "server.drainDelaySeconds must be a whole number of seconds, 0 or more" -}}
{{- end -}}
{{- if not (has (.Values.server.logLevel | toString) (list "debug" "info" "warn" "error")) -}}
{{- fail "server.logLevel must be debug, info, warn or error" -}}
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
