{{- define "backbone.name" -}}ocm-backbone{{- end -}}

{{- define "backbone.labels" -}}
app.kubernetes.io/name: {{ include "backbone.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ocm
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* The pods of one component, and only them. */}}
{{- define "backbone.selector" -}}
app.kubernetes.io/name: {{ include "backbone.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* The names the wallet charts reach the stores by: fixed, so a zone has one of each. */}}
{{- define "backbone.cassandra" -}}ocm-cassandra{{- end -}}
{{- define "backbone.nats" -}}ocm-nats{{- end -}}

{{/* Egress to the cluster resolver, the one lane every pod of the lane has. */}}
{{- define "backbone.dnsEgress" -}}
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

{{/* Fail early on values the stores cannot run with. */}}
{{- define "backbone.validate" -}}
{{- range $name, $img := .Values.images -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" ($img.digest | toString)) -}}
{{- fail (printf "images.%s.digest must be a sha256 digest; the stores are deployed by digest only" $name) -}}
{{- end -}}
{{- end -}}
{{- if not .Values.cassandra.storage.className -}}
{{- fail "cassandra.storage.className must be the zone's storage class (zone.storageClass of the umbrella)" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z][a-z0-9_]{0,47}$" (.Values.cassandra.keyspace | toString)) -}}
{{- fail "cassandra.keyspace must be a CQL identifier" -}}
{{- end -}}
{{- if lt (int .Values.cassandra.startupSeconds) 10 -}}
{{- fail "cassandra.startupSeconds must be 10 or more" -}}
{{- end -}}
{{- if not (regexMatch "^[0-9]+[MG]$" (.Values.cassandra.heap.max | toString)) -}}{{- fail "cassandra.heap.max must be a JVM size such as 1G or 512M" -}}{{- end -}}
{{- if not (regexMatch "^[0-9]+[MG]$" (.Values.cassandra.heap.new | toString)) -}}{{- fail "cassandra.heap.new must be a JVM size such as 200M" -}}{{- end -}}
{{- if not (kindIs "bool" .Values.networkPolicy.enabled) -}}{{- fail "networkPolicy.enabled must be a boolean, not a string" -}}{{- end -}}
{{- $w := int .Values.hooks.weight -}}
{{- if or (lt $w 40) (gt $w 59) -}}
{{- fail "hooks.weight must be inside the platform band, 40 to 59" -}}
{{- end -}}
{{- end -}}
