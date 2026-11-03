{{- define "wallet.name" -}}ocm-wallet{{- end -}}

{{- define "wallet.labels" -}}
app.kubernetes.io/name: {{ include "wallet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ocm
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
ztd.facis.io/tenant: {{ .Values.tenant.id | quote }}
{{- end -}}

{{/* The pods of one component of this release, and only them. */}}
{{- define "wallet.selector" -}}
app.kubernetes.io/name: {{ include "wallet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Pod labels of one component: the release labels, the component and the identity label. */}}
{{- define "wallet.podLabels" -}}
{{ include "wallet.labels" . }}
app.kubernetes.io/component: {{ .component }}
{{- if .Values.identity.spireManagedIdentity }}
spiffe.io/spire-managed-identity: "true"
{{- end }}
{{- end -}}

{{/* A component's resource name: <release>-<component>. */}}
{{- define "wallet.component" -}}{{ printf "%s-%s" .Release.Name .component }}{{- end -}}

{{- define "wallet.did" -}}did:web:{{ .Values.tenant.host }}{{- end -}}
{{- define "wallet.key" -}}{{ .Values.tenant.key | default (printf "wallet-%s" .Values.tenant.id) }}{{- end -}}
{{- define "wallet.mount" -}}{{ .Values.tenant.transitMount | default (printf "ocm/%s" .Values.tenant.id) }}{{- end -}}
{{/* The storage service's engine, <mount>-storage (the plugin joins namespace and group with "/"; an empty group leaves the namespace as the engine path). */}}
{{- define "wallet.storageMount" -}}{{ printf "%s-storage" (include "wallet.mount" .) }}{{- end -}}
{{- define "wallet.prefix" -}}{{ .Values.messaging.prefix | default .Values.tenant.id }}{{- end -}}

{{- define "wallet.image" -}}
{{- $img := index .Values.images .image -}}
{{ $img.repository }}@{{ $img.digest }}
{{- end -}}

{{/* The security context every container shares. */}}
{{- define "wallet.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{/* Egress to the cluster resolver, the one lane every pod of the lane has. */}}
{{- define "wallet.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
    - { port: 8053, protocol: UDP }
    - { port: 8053, protocol: TCP }
{{- end -}}

{{/* Fail early on values the wallet cannot run with. */}}
{{- define "wallet.validate" -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$" (.Values.tenant.id | toString)) -}}
{{- fail "tenant.id must be a short lowercase name (letters, digits, hyphens)" -}}
{{- end -}}
{{- if not (regexMatch "^([a-z0-9-]+\\.)+[a-z0-9-]+$" (.Values.tenant.host | toString)) -}}
{{- fail (printf "tenant.host must be the DNS name of the did:web document, without scheme, port or path (got %q)" (.Values.tenant.host | toString)) -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$" (include "wallet.key" .)) -}}
{{- fail "tenant.key must be a transit key name" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(/[a-z0-9]([a-z0-9_-]*[a-z0-9])?)*$" (include "wallet.mount" .)) -}}
{{- fail "tenant.transitMount must be a transit engine path" -}}
{{- end -}}
{{- range $name, $img := .Values.images -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" ($img.digest | toString)) -}}
{{- fail (printf "images.%s.digest must be a sha256 digest; the wallet is deployed by digest only" $name) -}}
{{- end -}}
{{- end -}}
{{- if not (regexMatch "^https?://(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$" (.Values.openbao.address | toString)) -}}
{{- fail "openbao.address must be the key-value store's base URL, http(s)://host[:port], without a path or a trailing slash" -}}
{{- end -}}
{{- range $k := list "enabled" "cilium" -}}
{{- if not (kindIs "bool" (index $.Values.networkPolicy $k)) -}}{{- fail (printf "networkPolicy.%s must be a boolean, not a string" $k) -}}{{- end -}}
{{- end -}}
{{- if not (kindIs "bool" .Values.mesh.enabled) -}}{{- fail "mesh.enabled must be a boolean, not a string" -}}{{- end -}}
{{- if not (kindIs "bool" .Values.identity.spireManagedIdentity) -}}{{- fail "identity.spireManagedIdentity must be a boolean, not a string" -}}{{- end -}}
{{- if not (kindIs "bool" .Values.retrieval.disableTLS) -}}{{- fail "retrieval.disableTLS must be a boolean, not a string" -}}{{- end -}}
{{- if .Values.networkPolicy.enabled -}}
{{- if not (and (kindIs "slice" .Values.networkPolicy.edgeIngress.cidrs) .Values.networkPolicy.edgeIngress.cidrs) -}}
{{- fail "networkPolicy.edgeIngress.cidrs must be a non-empty list of CIDRs; an empty peer list would admit every source" -}}
{{- end -}}
{{- if not (and (kindIs "map" .Values.networkPolicy.openbaoSelector) .Values.networkPolicy.openbaoSelector) -}}
{{- fail "networkPolicy.openbaoSelector must be a non-empty label map; an empty selector would admit every pod" -}}
{{- end -}}
{{- if not (kindIs "slice" .Values.networkPolicy.issuerEgress.cidrs) -}}{{- fail "networkPolicy.issuerEgress.cidrs must be a list" -}}{{- end -}}
{{- range $peer := .Values.networkPolicy.issuerEgress.peers -}}
{{- if not (or (hasKey $peer "podSelector") (hasKey $peer "namespaceSelector") (hasKey $peer "ipBlock")) -}}{{- fail "networkPolicy.issuerEgress.peers entries are NetworkPolicyPeer objects (podSelector / namespaceSelector / ipBlock)" -}}{{- end -}}
{{- range $sel := list "podSelector" "namespaceSelector" -}}
{{- if hasKey $peer $sel -}}{{- $v := index $peer $sel -}}{{- if not (and (kindIs "map" $v) (or (hasKey $v "matchLabels") (hasKey $v "matchExpressions"))) -}}{{- fail (printf "networkPolicy.issuerEgress.peers: %s must hold matchLabels or matchExpressions" $sel) -}}{{- end -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not .Values.openbao.existingSecret -}}
{{- fail "openbao.existingSecret must name the Secret holding this release's OpenBao token (ztd-openbao-<serviceTokens name>); the chart never carries a token" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9._-]+$" (.Values.openbao.secretKey | toString)) -}}
{{- fail "openbao.secretKey must be a Secret data key" -}}
{{- end -}}
{{- if not .Values.edge.tls.existingSecret -}}
{{- fail "edge.tls.existingSecret must name the kubernetes.io/tls Secret for tenant.host; the chart issues no certificate" -}}
{{- end -}}
{{- if not (has .Values.edge.service.type (list "LoadBalancer" "NodePort" "ClusterIP")) -}}
{{- fail "edge.service.type must be LoadBalancer, NodePort or ClusterIP" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z][a-z0-9_]{0,47}$" (.Values.backbone.keyspace | toString)) -}}
{{- fail "backbone.keyspace must be a CQL identifier" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9-]+(\\.[a-z0-9-]+)*$" (include "wallet.prefix" .)) -}}
{{- fail "messaging.prefix must be a NATS subject prefix: dot-separated tokens of lowercase letters, digits and hyphens, no empty token" -}}
{{- end -}}
{{- $w := int .Values.hooks.weight -}}
{{- if or (lt $w 40) (gt $w 59) -}}
{{- fail "hooks.weight must be inside the platform band, 40 to 59" -}}
{{- end -}}
{{- if not (has (.Values.logLevel | toString) (list "debug" "info" "warn" "error")) -}}
{{- fail "logLevel must be debug, info, warn or error" -}}
{{- end -}}
{{- end -}}
