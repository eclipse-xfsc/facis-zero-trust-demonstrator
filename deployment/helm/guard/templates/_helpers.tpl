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
{{- if not (has (toString .Values.zone) (list "a" "b")) -}}{{ fail "zone must be a or b (the IF-01 event sources guard-<zone>, policy-<zone>)" }}{{- end -}}
{{- with .Values.policyRules.presentation -}}{{- if and .scopes (not (regexMatch "^(https|openid4vp)://" (toString .oid4vpLink))) -}}{{ fail "policyRules.presentation needs an https or openid4vp oid4vpLink" }}{{- end -}}{{- end -}}
{{- if and .Values.tenant.callerNamespaces (not .Values.tenant.enabled) -}}{{ fail "tenant.callerNamespaces needs tenant.enabled" }}{{- end -}}
{{- range .Values.tenant.callerNamespaces -}}
{{- if or (eq . $.Release.Namespace) (not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" .)) -}}{{ fail (printf "tenant.callerNamespaces: %s is not another tenant's namespace" .) }}{{- end -}}
{{- end -}}
{{- range .Values.grpc.methods -}}
{{- if not (regexMatch "^/[A-Za-z_][A-Za-z0-9_.]*/[A-Za-z_][A-Za-z0-9_]*$" .) -}}{{ fail (printf "grpc.methods: %q is not a full method path, /package.Service/Method" .) }}{{- end -}}
{{- end -}}
{{- if and .Values.grpc.methods (or (not .Values.grpc.resourcePort) (eq (int .Values.grpc.resourcePort) (int .Values.resourcePort))) -}}{{ fail "grpc.resourcePort is required with grpc.methods and must differ from resourcePort" }}{{- end -}}
{{- if hasKey .Values.config "grpc_methods" -}}{{ fail "config.grpc_methods is set from grpc.methods; do not set it directly" }}{{- end -}}
{{- $scopes := .Values.config.scope_tenants -}}
{{- if or (not (get $scopes "report:read")) (not (get $scopes "report:summary")) (eq (get $scopes "report:read") (get $scopes "report:summary")) -}}{{ fail "full-report and summary scope tenants must be distinct" }}{{- end -}}
{{- end -}}

{{/* XFCC sanitization is mesh-wide (zone-policy, EnvoyFilter xfcc-sanitize-set):
zone-policy refuses a per-pod proxy configuration in a plane namespace, and native sidecars start the
proxy before the application without holdApplicationUntilProxyStarts. */}}
{{/* The Participants the guard admits over the mesh: its own namespace's, then, in tenant mode, those
of tenant.callerNamespaces. */}}
{{- define "guard.callers" -}}
{{- $out := list (printf "spiffe://%s/ns/%s/sa/%s" .Values.trustDomain .Release.Namespace .Values.participantServiceAccount) -}}
{{- if .Values.tenant.enabled -}}
{{- range .Values.tenant.callerNamespaces -}}
{{- $out = append $out (printf "spiffe://%s/ns/%s/sa/%s" $.Values.trustDomain . $.Values.participantServiceAccount) -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{- define "guard.annotations" -}}
{{- if hasKey .Values.podAnnotations "proxy.istio.io/config" -}}{{ fail "podAnnotations: proxy.istio.io/config is refused at admission in a plane namespace (zone-policy); XFCC sanitization is mesh-wide, the EnvoyFilter xfcc-sanitize-set of zone-policy" }}{{- end -}}
{{- toYaml .Values.podAnnotations -}}
{{- end -}}

{{- /* The gRPC part of the guard's and the policy evaluator's configuration: the same list for both. */ -}}
{{- define "guard.grpcConfig" -}}
{{- if .Values.grpc.methods -}}{{ dict "grpc_methods" .Values.grpc.methods | toJson }}{{- else -}}{}{{- end -}}
{{- end -}}
