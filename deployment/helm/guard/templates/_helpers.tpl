{{- define "guard.validate" -}}
{{- if and (not .Values.networkPolicy.istiod.enabled) (empty .Values.networkPolicy.egress) -}}{{ fail "guard requires explicit mesh-control egress while the sidecar holds application startup" }}{{- end -}}
{{- range .Values.images -}}
{{- if or (not .repository) (not (regexMatch "^sha256:[a-f0-9]{64}$" .digest)) -}}{{ fail "every guard image requires repository and sha256 digest" }}{{- end -}}
{{- end -}}
{{- range $key := list "issuer" "jwks_url" "inbound_audience" "upstream_audience" "published_base_url" "peer_zone" "policy_url" "store_url" -}}
{{- if not (get $.Values.config $key) -}}{{ fail (printf "config.%s is required" $key) }}{{- end -}}
{{- end -}}
{{- if not (regexMatch "^https?://[^/?#@]+/?$" .Values.config.published_base_url) -}}{{ fail "published_base_url must be an HTTP(S) authority without credentials, path, query or fragment" }}{{- end -}}
{{- if hasKey .Values.config "audience" -}}{{ fail "config.audience is obsolete; configure separate inbound_audience and upstream_audience" }}{{- end -}}
{{- if or (eq .Values.config.inbound_audience .Values.config.upstream_audience) (regexMatch "[[:space:]]" (printf "%s%s" .Values.config.inbound_audience .Values.config.upstream_audience)) -}}{{ fail "guard audiences must be distinct nonempty identifiers without whitespace" }}{{- end -}}
{{- if or (not .Values.trustDomain) (not .Values.participantServiceAccount) (not .Values.resourceName) (not .Values.policyRevision) -}}{{ fail "guard identity, resource and policy revision are required" }}{{- end -}}
{{- $participant := printf "spiffe://%s/ns/%s/sa/%s" .Values.trustDomain .Release.Namespace .Values.participantServiceAccount -}}
{{- if and .Values.config.allowed_callers (or (ne (len .Values.config.allowed_callers) 1) (not (has $participant .Values.config.allowed_callers))) -}}{{ fail "allowed_callers must match this namespace's configured Participant service account" }}{{- end -}}
{{- $scopes := .Values.config.scope_tenants -}}
{{- if or (not (get $scopes "report:read")) (not (get $scopes "report:summary")) (eq (get $scopes "report:read") (get $scopes "report:summary")) -}}{{ fail "full-report and summary scope tenants must be distinct" }}{{- end -}}
{{- end -}}

{{- define "guard.annotations" -}}
{{- $a := deepCopy .Values.podAnnotations -}}
{{- $p := dict -}}
{{- if hasKey $a "proxy.istio.io/config" -}}{{- $p = mustFromJson (index $a "proxy.istio.io/config") -}}{{- end -}}
{{- $_ := set $p "holdApplicationUntilProxyStarts" true -}}
{{- $_ := set $p "proxyHeaders" (mergeOverwrite (get $p "proxyHeaders" | default dict) (dict "forwardedClientCert" "SANITIZE_SET" "setCurrentClientCertDetails" (dict "uri" true "cert" false "chain" false "subject" false "dns" false))) -}}
{{- $_ := set $a "proxy.istio.io/config" (toJson $p) -}}
{{- toYaml $a -}}
{{- end -}}
