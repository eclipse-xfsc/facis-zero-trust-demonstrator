{{- define "verification-service.name" -}}verification-service{{- end -}}

{{- define "verification-service.labels" -}}
app.kubernetes.io/name: {{ include "verification-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "verification-service.selector" -}}
app.kubernetes.io/name: {{ include "verification-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The service's own SPIFFE ID: what every caller's proxy must see in the server certificate. */}}
{{- define "verification-service.spiffeID" -}}
spiffe://{{ .Values.mesh.trustDomain }}/ns/{{ .Release.Namespace }}/sa/{{ .Values.serviceAccount.name }}
{{- end -}}

{{/* Fail early on values the service cannot run with. */}}
{{- define "verification-service.validate" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (.Values.image.digest | toString)) -}}
{{- fail "image.digest must be a sha256 digest; the service is deployed by digest only" -}}
{{- end -}}
{{- if not (regexMatch "^https?://[^/?#]+" (.Values.issuer | toString)) -}}
{{- fail "issuer must be the absolute URI of the outcomes' iss" -}}
{{- end -}}
{{- if not .Values.callers -}}
{{- fail "callers must name at least one SPIFFE ID; the service refuses every other caller" -}}
{{- end -}}
{{- range .Values.callers -}}
{{- if not (regexMatch "^spiffe://[^/]+/ns/[^/]+/sa/[^/]+$" .) -}}{{ fail "callers must be SPIFFE service account identities" }}{{- end -}}
{{- end -}}
{{- if not (and .Values.database.existingSecret .Values.database.secretKey) -}}
{{- fail "database.existingSecret and database.secretKey must name the connection URL's Secret and key; the chart never carries the credential" -}}
{{- end -}}
{{- if not (regexMatch "^https?://(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/?$" (.Values.openbao.address | toString)) -}}
{{- fail "openbao.address must be http(s)://host[:port]" -}}
{{- end -}}
{{- if not (and .Values.openbao.existingSecret (regexMatch "^[A-Za-z0-9._-]+$" (.Values.openbao.tokenKey | toString)) .Values.openbao.signingKey) -}}
{{- fail "openbao.existingSecret, openbao.tokenKey and openbao.signingKey are required" -}}
{{- end -}}
{{- if not (and .Values.trust.existingConfigMap .Values.trust.issuerKeysKey) -}}
{{- fail "trust.existingConfigMap and trust.issuerKeysKey must name the issuer keys" -}}
{{- end -}}
{{- if eq (empty .Values.trust.tcr.url) (empty .Values.trust.fixtureTrustListKey) -}}
{{- fail "set exactly one trust source: trust.tcr.url (TRAIN) or trust.fixtureTrustListKey (fixture)" -}}
{{- end -}}
{{- if and .Values.trust.tcr.url (not .Values.trust.tcr.trustSchemePointers) -}}
{{- fail "trust.tcr.url needs trust.tcr.trustSchemePointers" -}}
{{- end -}}
{{- if not (and .Values.acceptedVCT .Values.statusPrefixes) -}}
{{- fail "acceptedVCT and statusPrefixes must not be empty" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9.-]+$" (.Values.mesh.trustDomain | toString)) -}}
{{- fail "mesh.trustDomain must be the zone's SPIFFE trust domain" -}}
{{- end -}}
{{- if not .Values.identity.spireManagedIdentity -}}
{{- fail "identity.spireManagedIdentity must stay on: the caller check reads the mesh identity" -}}
{{- end -}}
{{- if lt (int .Values.replicas) 1 -}}
{{- fail "replicas must be 1 or more" -}}
{{- end -}}
{{- end -}}
