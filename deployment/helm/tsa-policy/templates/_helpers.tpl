{{- define "tsa.validate" -}}
{{- range $name, $image := .Values.images -}}
{{- if or (not $image.repository) (not (regexMatch "^sha256:[a-f0-9]{64}$" $image.digest)) -}}{{ fail (printf "images.%s requires repository and sha256 digest" $name) }}{{- end -}}
{{- end -}}
{{- if not (contains "BEGIN PUBLIC KEY" .Values.trustRoot) -}}{{ fail "trustRoot must be a PEM public key" }}{{- end -}}
{{- if empty .Values.callers -}}{{ fail "callers must name the IF-05 adapters allowed to evaluate" }}{{- end -}}
{{- range .Values.callers -}}
{{- if or (not .namespace) (not .name) -}}{{ fail "every caller needs namespace and name" }}{{- end -}}
{{- end -}}
{{- with .Values.bundle -}}
{{- if or (and .ref (not .revision)) (and .revision (not .ref)) -}}{{ fail "bundle.ref and bundle.revision go together" }}{{- end -}}
{{- if and .ref (not (regexMatch "^[^@:/]+(:[0-9]+)?/[^@:]+@sha256:[a-f0-9]{64}$" .ref)) -}}{{ fail "bundle.ref must be host/repository@sha256:<digest>" }}{{- end -}}
{{- $repo := (split "@" .ref)._0 -}}
{{- if and .ref (ne $repo (trimSuffix "/" .repository)) (not (hasPrefix (printf "%s/" (trimSuffix "/" .repository)) $repo)) -}}{{ fail "bundle.ref must be under bundle.repository" }}{{- end -}}
{{- if and .revision (not (regexMatch "^[A-Za-z0-9._-]+$" .revision)) -}}{{ fail "bundle.revision must be [A-Za-z0-9._-]+" }}{{- end -}}
{{- if lt (int .pollSeconds) 1 -}}{{ fail "bundle.pollSeconds must be at least 1" }}{{- end -}}
{{- end -}}
{{- range $k, $v := .Values.policy -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" (toString $v)) -}}{{ fail (printf "policy.%s must be a plain path segment" $k) }}{{- end -}}
{{- end -}}
{{- end -}}

{{- define "tsa.evaluationPath" -}}
{{- with .Values.policy -}}/policy/{{ .repository }}/{{ .group }}/{{ .name }}/{{ .version }}/evaluation{{- end -}}
{{- end -}}

{{- define "tsa.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end -}}
