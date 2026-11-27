{{- define "access.validate" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}{{ fail "image.digest must be a sha256 digest" }}{{- end -}}
{{- if or (not .Values.target) (empty .Values.planeNamespaces) (empty .Values.approvers) (not .Values.keycloak.base) (not .Values.keycloak.secretRef.name) (not .Values.tls.secretName) -}}{{ fail "target, planeNamespaces, approvers, keycloak.base, keycloak.secretRef.name and tls.secretName are required" }}{{- end -}}
{{- range .Values.approvers -}}
{{- if or (not .sub) (ne .key.kty "EC") (ne .key.crv "P-256") (not .key.x) (not .key.y) -}}{{ fail "every approver needs a sub and an EC P-256 public key with quoted \"x\" and \"y\" members" }}{{- end -}}
{{- if or .key.d (hasKey .key "d") -}}{{ fail "an approver key must be public" }}{{- end -}}
{{- end -}}
{{- if has .Release.Namespace .Values.planeNamespaces -}}{{ fail "the runner's namespace cannot be a plane namespace" }}{{- end -}}
{{- end -}}
