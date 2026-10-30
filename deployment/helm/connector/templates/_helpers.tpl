{{- define "connector.labels" -}}
app.kubernetes.io/name: ztd-connector
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "connector.selector" -}}
app.kubernetes.io/name: ztd-connector
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "connector.validate" -}}
{{- if not .Values.image.repository -}}{{ fail "image.repository is required" }}{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be a sha256 digest" -}}
{{- end -}}
{{- if not (and .Values.database.existingSecret .Values.database.secretKey .Values.credentials.existingSecret) -}}
{{- fail "database and credentials existingSecret references are required" -}}
{{- end -}}
{{- range $name, $key := .Values.credentials.keys -}}
{{- if not (regexMatch "^[A-Za-z0-9_.-]+$" $key) -}}{{ fail (printf "invalid credentials key reference: %s" $name) }}{{- end -}}
{{- end -}}
{{- if not (regexMatch "^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$" .Values.oauth.issuer) -}}
{{- fail "oauth.issuer must be an https base URL without credentials" -}}
{{- end -}}
{{- if not (regexMatch "^https?://[A-Za-z0-9.-]+(:[0-9]+)?/oauth2/register$" .Values.oauth.registrationEndpoint) -}}
{{- fail "oauth.registrationEndpoint must be an absolute /oauth2/register URL" -}}
{{- end -}}
{{- if not (has .Values.oauth.registrationEndpoint .Values.oauth.registrarAudiences) -}}
{{- fail "oauth.registrarAudiences must include the registration endpoint" -}}
{{- end -}}
{{- if not (has "connector:client_registration" .Values.oauth.registrarScopes) -}}
{{- fail "oauth.registrarScopes must include connector:client_registration" -}}
{{- end -}}
{{- if has "connector:client_registration" .Values.oauth.registrarDelegableScopes -}}
{{- fail "registration scope cannot be delegated" -}}
{{- end -}}
{{- if not (regexMatch "^https?://[A-Za-z0-9.-]+(:[0-9]+)?/?$" .Values.openbao.address) -}}
{{- fail "openbao.address must be a base URL without credentials" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9_-]+$" .Values.openbao.signingKey) -}}{{ fail "openbao.signingKey is required" }}{{- end -}}
{{- if lt (int .Values.openbao.signingKeyVersion) 1 -}}{{ fail "openbao.signingKeyVersion must be positive" }}{{- end -}}
{{- if not .Values.serviceAccount.name -}}{{ fail "serviceAccount.name is required" }}{{- end -}}
{{- if not .Values.oauth.registrarID -}}{{ fail "oauth.registrarID is required" }}{{- end -}}
{{- if lt (int .Values.replicas) 1 -}}{{ fail "replicas must be positive" }}{{- end -}}
{{- if not .Values.dpop.enforce -}}{{ fail "the protected-service Connector requires dpop.enforce" }}{{- end -}}
{{- if or (lt (int .Values.server.readinessTimeoutSeconds) 1) (lt (int .Values.server.shutdownTimeoutSeconds) 1) (lt (int .Values.server.drainDelaySeconds) 0) (lt (int .Values.oauth.accessTokenLifespanSeconds) 1) -}}
{{- fail "server timeout and token lifetime values must be positive; drain delay may be zero" -}}
{{- end -}}
{{- if not (has .Values.server.logLevel (list "debug" "info" "warn" "error")) -}}{{ fail "invalid server.logLevel" }}{{- end -}}
{{- if and .Values.verifiedPresentation.enabled (not (and .Values.verifiedPresentation.existingConfigMap .Values.verifiedPresentation.issuersKey .Values.verifiedPresentation.scopeMapKey)) -}}
{{- fail "verifiedPresentation requires existingConfigMap and both JSON key names" -}}
{{- end -}}
{{- end -}}
