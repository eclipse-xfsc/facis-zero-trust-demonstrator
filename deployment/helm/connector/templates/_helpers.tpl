{{- define "connector.name" -}}ztd-connector{{- end -}}

{{- define "connector.labels" -}}
app.kubernetes.io/name: {{ include "connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The service's pods, and only them. */}}
{{- define "connector.selector" -}}
app.kubernetes.io/name: {{ include "connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{/* The registration endpoint as clients reach it: the configured one, or the Service's own. */}}
{{- define "connector.registrationEndpoint" -}}
{{- if .Values.registrationEndpoint -}}
{{- .Values.registrationEndpoint -}}
{{- else -}}
http://{{ include "connector.name" . }}.{{ .Release.Namespace }}.svc:8080/oauth2/register
{{- end -}}
{{- end -}}

{{/* A Kubernetes name or key: no space, nothing a reference could not hold. */}}
{{- define "connector.isName" -}}
{{- if regexMatch "^[-._a-zA-Z0-9]+$" (. | toString) -}}true{{- end -}}
{{- end -}}

{{/* A number as its digits: a values file reads 12345678 as a float, which toString would print in
exponent form. Anything not a whole number is left as it is, for the pattern to refuse. */}}
{{- define "connector.digits" -}}
{{- if and (kindIs "float64" .) (eq . (float64 (int64 .))) -}}{{ int64 . }}{{- else -}}{{ . }}{{- end -}}
{{- end -}}

{{/* Fail early on values the connector cannot run with. */}}
{{- define "connector.validate" -}}
{{- if not (regexMatch "^[a-zA-Z0-9][-a-zA-Z0-9._:/]*$" (.Values.image.repository | toString)) -}}
{{- fail "image.repository must name the connector image, without a tag or digest" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; the connector is deployed by digest only" -}}
{{- end -}}
{{- if not (has (.Values.zone | toString) (list "a" "b")) -}}
{{- fail "zone must be a or b: the source of the connector's security-state events" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.database.existingSecret) -}}
{{- fail "database.existingSecret must name the Secret holding the connection URL; the chart never carries the credential" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.database.secretKey) -}}
{{- fail "database.secretKey must name the key of the connection URL in the Secret" -}}
{{- end -}}
{{- if not (regexMatch "^https?://(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/?$" (.Values.openbao.address | toString)) -}}
{{- fail "openbao.address must be the key-value store's base URL, http(s)://host[:port] with a DNS name or an IP, nothing more" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.openbao.existingTokenSecret) -}}
{{- fail "openbao.existingTokenSecret must name the Secret holding the key-value store token" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.openbao.tokenSecretKey) -}}
{{- fail "openbao.tokenSecretKey must name the key of the token in that Secret" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.secrets.existingSecret) -}}
{{- fail "secrets.existingSecret must name the Secret holding the token, registration and registrar secrets" -}}
{{- end -}}
{{- if not (and (include "connector.isName" .Values.secrets.tokenSecretKey) (include "connector.isName" .Values.secrets.registrationSecretKey) (include "connector.isName" .Values.secrets.registrarSecretKey)) -}}
{{- fail "secrets.tokenSecretKey, secrets.registrationSecretKey and secrets.registrarSecretKey must name the keys in that Secret" -}}
{{- end -}}
{{- if not (regexMatch "^https://[^/?#@\\s]+(/[^?#\\s]*)?$" (.Values.issuer | toString)) -}}
{{- fail "issuer must be an https:// URL, the iss of the access tokens" -}}
{{- end -}}
{{- if and .Values.registrationEndpoint (not (regexMatch "^https?://[^/?#@\\s]+(/[^?#\\s]*)?$" (.Values.registrationEndpoint | toString))) -}}
{{- fail "registrationEndpoint must be an absolute http(s) URL" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.signing.key) -}}
{{- fail "signing.key must name the transit key that signs the access tokens" -}}
{{- end -}}
{{- if not (regexMatch "^[1-9][0-9]*$" (include "connector.digits" .Values.signing.version)) -}}
{{- fail "signing.version must be the pinned version of that key, 1 or more" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.registrar.id) -}}
{{- fail "registrar.id must name the registrar client" -}}
{{- end -}}
{{- range $key := list "scopes" "audiences" "delegableScopes" -}}
{{- if not (kindIs "slice" (index $.Values.registrar $key)) -}}
{{- fail (printf "registrar.%s must be a list" $key) -}}
{{- end -}}
{{- end -}}
{{- range concat .Values.registrar.scopes .Values.registrar.delegableScopes -}}
{{- if not (regexMatch "^[!#-\\[\\]-~]+$" (. | toString)) -}}
{{- fail "registrar.scopes and registrar.delegableScopes must list scope tokens, without spaces" -}}
{{- end -}}
{{- end -}}
{{- $audiences := prepend .Values.registrar.audiences (include "connector.registrationEndpoint" .) -}}
{{- if ne (len $audiences) (len (uniq $audiences)) -}}
{{- fail "registrar.audiences must not repeat a URL, nor name the registration endpoint, which the chart adds" -}}
{{- end -}}
{{- range .Values.registrar.audiences -}}
{{- if not (regexMatch "^https?://[^/?#@\\s]+(/[^?#\\s]*)?$" (. | toString)) -}}
{{- fail "registrar.audiences must list absolute http(s) URLs without credentials, query or fragment" -}}
{{- end -}}
{{- end -}}
{{- if not (has "connector:client_registration" .Values.registrar.scopes) -}}
{{- fail "registrar.scopes must include connector:client_registration" -}}
{{- end -}}
{{- if has "connector:client_registration" .Values.registrar.delegableScopes -}}
{{- fail "registrar.delegableScopes cannot include connector:client_registration" -}}
{{- end -}}
{{- if and .Values.verifiedPresentation.configMap (not (and (include "connector.isName" .Values.verifiedPresentation.configMap) (include "connector.isName" .Values.verifiedPresentation.issuersKey) (include "connector.isName" .Values.verifiedPresentation.scopeMapKey))) -}}
{{- fail "verifiedPresentation.configMap, issuersKey and scopeMapKey must name the ConfigMap and its keys" -}}
{{- end -}}
{{- if not (include "connector.isName" .Values.serviceAccount.name) -}}
{{- fail "serviceAccount.name must name the ServiceAccount the connector runs as; it is the last segment of its SPIFFE ID" -}}
{{- end -}}
{{- if not (regexMatch "^[1-9][0-9]*$" (include "connector.digits" .Values.replicas)) -}}
{{- fail "replicas must be 1 or more" -}}
{{- end -}}
{{- if not (regexMatch "^[1-9][0-9]*$" (include "connector.digits" .Values.server.readinessTimeoutSeconds)) -}}
{{- fail "server.readinessTimeoutSeconds must be a whole number of seconds, 1 or more" -}}
{{- end -}}
{{- if not (regexMatch "^[1-9][0-9]*$" (include "connector.digits" .Values.server.shutdownTimeoutSeconds)) -}}
{{- fail "server.shutdownTimeoutSeconds must be a whole number of seconds, 1 or more" -}}
{{- end -}}
{{- if not (regexMatch "^[0-9]+$" (include "connector.digits" .Values.server.drainDelaySeconds)) -}}
{{- fail "server.drainDelaySeconds must be a whole number of seconds, 0 or more" -}}
{{- end -}}
{{- if not (has (.Values.server.logLevel | toString) (list "debug" "info" "warn" "error")) -}}
{{- fail "server.logLevel must be debug, info, warn or error" -}}
{{- end -}}
{{- end -}}
