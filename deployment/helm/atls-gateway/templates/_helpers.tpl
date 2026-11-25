{{- define "atls-gateway.validate" -}}
{{- $v := .Values -}}
{{- if not (regexMatch "^ztd-[a-z0-9-]+$" $v.name) -}}{{ fail "name must match ^ztd-[a-z0-9-]+$ (the zone's naming rule)" }}{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $v.image.digest) -}}{{ fail "image.digest must be a sha256 digest" }}{{- end -}}
{{- if and (not $v.ingress.enabled) (not $v.egress.enabled) -}}{{ fail "at least one of ingress.enabled and egress.enabled: a release without a role serves nothing" }}{{- end -}}
{{- include "atls-gateway.port" (list "healthPort" $v.healthPort) -}}
{{- if hasKey $v.podAnnotations "proxy.istio.io/config" -}}{{ fail "podAnnotations: proxy.istio.io/config is refused at admission in a plane namespace (zone-policy)" }}{{- end -}}
{{- if not $v.tlsSecret -}}{{ fail "tlsSecret is required: the gateway's zone certificate" }}{{- end -}}
{{- if not (contains "BEGIN CERTIFICATE" $v.trustCaCert) -}}{{ fail "trustCaCert must hold the PEM CA certificate(s) of the zones' gateway certificates" }}{{- end -}}
{{- if not (regexMatch "^[^:/ ]+:[0-9]{1,5}$" $v.cmcd.address) -}}{{ fail "cmcd.address must be host:port of the zone's cmcd" }}{{- end -}}
{{- if $v.attestation.enabled -}}
{{- if not (and (kindIs "map" $v.attestation.zone) $v.attestation.zone.zone) -}}{{ fail "attestation.zone must be the zone's attestation configuration (deployment/attestation/<zone>.json)" }}{{- end -}}
{{- if not (contains "BEGIN CERTIFICATE" $v.attestation.metadataCaCert) -}}{{ fail "attestation.metadataCaCert must hold the PEM metadata CA certificate" }}{{- end -}}
{{- if lt (int $v.attestation.timeoutSeconds) 1 -}}{{ fail "attestation.timeoutSeconds must be at least 1" }}{{- end -}}
{{- end -}}
{{- if $v.ingress.enabled -}}
{{- include "atls-gateway.identity" (list "ingress.peerIdentity" $v.ingress.peerIdentity) -}}
{{- if or (not $v.ingress.upstream.name) (empty $v.ingress.sourceRanges) -}}{{ fail "ingress.upstream.name and ingress.sourceRanges are required" }}{{- end -}}
{{- include "atls-gateway.port" (list "ingress.port" $v.ingress.port) -}}
{{- include "atls-gateway.port" (list "ingress.upstream.port" $v.ingress.upstream.port) -}}
{{- include "atls-gateway.port" (list "ingress.service.port" $v.ingress.service.port) -}}
{{- if not (has $v.ingress.service.type (list "LoadBalancer" "NodePort" "ClusterIP")) -}}{{ fail "ingress.service.type must be LoadBalancer, NodePort or ClusterIP" }}{{- end -}}
{{- if not (has $v.ingress.service.externalTrafficPolicy (list "Local" "Cluster")) -}}{{ fail "ingress.service.externalTrafficPolicy must be Local or Cluster" }}{{- end -}}
{{- end -}}
{{- if $v.egress.enabled -}}
{{- if not $v.trustDomain -}}{{ fail "trustDomain is required for the egress role" }}{{- end -}}
{{- if empty $v.egress.callers -}}{{ fail "egress.callers: at least one caller" }}{{- end -}}
{{- range $v.egress.callers -}}
{{- if or (not .serviceAccount) (empty .podSelector) -}}{{ fail "every egress caller needs serviceAccount and podSelector" }}{{- end -}}
{{- end -}}
{{- $p := $v.egress.peer -}}
{{- if not $p.name -}}{{ fail "egress.peer.name is required" }}{{- end -}}
{{- if not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}$" $p.address) -}}{{ fail "egress.peer.address must be the peer ingress's IPv4 address" }}{{- end -}}
{{- include "atls-gateway.identity" (list "egress.peer.identity" $p.identity) -}}
{{- include "atls-gateway.port" (list "egress.port" $v.egress.port) -}}
{{- include "atls-gateway.port" (list "egress.peer.port" $p.port) -}}
{{- end -}}
{{- end -}}

{{/* A policy port is one TCP port, 1-65535: a zero, empty or absent port would open every port. */}}
{{- define "atls-gateway.port" -}}
{{- $name := index . 0 -}}{{- $p := toString (index . 1) -}}
{{- if not (regexMatch "^[1-9][0-9]{0,4}$" $p) -}}{{ fail (printf "%s must be one TCP port, 1-65535" $name) }}{{- end -}}
{{- if gt (atoi $p) 65535 -}}{{ fail (printf "%s must be one TCP port, 1-65535" $name) }}{{- end -}}
{{- end -}}

{{/* A peer identity is a URI: the subject alternative name the peer's certificate must carry. */}}
{{- define "atls-gateway.identity" -}}
{{- $name := index . 0 -}}{{- $id := toString (index . 1) -}}
{{- if not (regexMatch "^[a-z][a-z0-9+.-]*://[^ ]+$" $id) -}}{{ fail (printf "%s must be the peer gateway's identity URI, e.g. spiffe://zone-b/gateway" $name) }}{{- end -}}
{{- end -}}

{{/* The labels every gateway pod carries: the umbrella's contract plus the role. */}}
{{- define "atls-gateway.podLabels" -}}
app.kubernetes.io/name: atls-gateway
app.kubernetes.io/component: {{ . }}
app.kubernetes.io/part-of: facis-zero-trust-demonstrator
spiffe.io/spire-managed-identity: "true"
{{- end -}}

{{/* What a pod reads at start besides its configuration file: the trust anchors and the startup
check's inputs. Their digest is a pod annotation, so a change of any of them rolls the pod. */}}
{{- define "atls-gateway.material" -}}
{{- $v := .Values -}}
{{- $v.trustCaCert -}}
{{- if $v.attestation.enabled -}}{{ toPrettyJson $v.attestation.zone }}{{ $v.attestation.metadataCaCert }}{{- end -}}
{{- end -}}

{{/* The configuration file of one role, as mounted. */}}
{{- define "atls-gateway.config" -}}
{{- $role := index . 0 -}}{{- $v := (index . 1).Values -}}
{{- $cfg := dict "role" $role "certificate" "/etc/gateway/tls/tls.crt" "key" "/etc/gateway/tls/tls.key" "ca" "/etc/gateway/trust/ca.pem" "cmcd" $v.cmcd.address "health" (printf "0.0.0.0:%v" $v.healthPort) -}}
{{- if eq $role "ingress" -}}
{{- $_ := set $cfg "listen" (printf "0.0.0.0:%v" $v.ingress.port) -}}
{{- $_ := set $cfg "target" (printf "%s:%v" $v.ingress.upstream.name $v.ingress.upstream.port) -}}
{{- $_ := set $cfg "peerIdentity" $v.ingress.peerIdentity -}}
{{- else -}}
{{- $_ := set $cfg "listen" (printf "0.0.0.0:%v" $v.egress.port) -}}
{{- $_ := set $cfg "target" (printf "%s:%v" $v.egress.peer.address $v.egress.peer.port) -}}
{{- $_ := set $cfg "peerIdentity" $v.egress.peer.identity -}}
{{- end -}}
{{- if $v.attestation.enabled -}}
{{- $_ := set $cfg "attestation" (dict "zone" "/etc/gateway/attestation/zone.json" "metadataCA" (list "/etc/gateway/attestation/metadata-ca.pem") "timeoutSeconds" (int $v.attestation.timeoutSeconds)) -}}
{{- end -}}
{{ toPrettyJson $cfg }}
{{- end -}}
