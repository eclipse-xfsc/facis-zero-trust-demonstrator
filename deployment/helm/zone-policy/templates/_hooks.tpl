{{/*
COPY of the hook helpers of the umbrella chart (deployment/helm/ztd/templates/_helpers.tpl,
"ztd.hook.weight" and "ztd.hook.annotations"), under this chart's names, so that the hook-weight
scheme reads the same across the charts. Change both together; docs/umbrella-chart.md describes
the scheme. The bands order jobs within one release; the order between the releases of a zone is
the installer's (scripts/install-zone/install.sh).
  preflight       0-19   checks that must hold before anything is installed
  identity       20-39   SPIRE: checks on the server, the trust bundle and the registration entries
  platform       40-59   jobs of OpenBao, Harbor, TSPA, estserver, observability and admission
  policy         60-79   jobs of the mesh and admission policy that depends on identity and platform
  workloads      80-99   jobs of the demonstrator workloads
  verification 100-119   read-back checks that fail the release when the layout is wrong
*/}}
{{- define "zone-policy.hook.weight" -}}
{{- $bands := dict "preflight" 0 "identity" 20 "platform" 40 "policy" 60 "workloads" 80 "verification" 100 -}}
{{- $band := toString .band -}}
{{- if not (hasKey $bands $band) -}}
{{- fail (printf "zone-policy.hook.weight: unknown band %q (preflight|identity|platform|policy|workloads|verification)" $band) -}}
{{- end -}}
{{- $offset := int (default 0 .offset) -}}
{{- if or (lt $offset 0) (gt $offset 19) -}}
{{- fail (printf "zone-policy.hook.weight: offset %d is outside the band (0-19)" $offset) -}}
{{- end -}}
{{- add (index $bands $band) $offset -}}
{{- end }}

{{/*
Hook annotations from the scheme. Called with
(dict "phase" "post-install,post-upgrade" "band" "identity" "offset" 5 ["deletePolicy" "..."]).
*/}}
{{- define "zone-policy.hook.annotations" -}}
helm.sh/hook: {{ .phase | quote }}
helm.sh/hook-weight: {{ include "zone-policy.hook.weight" . | quote }}
helm.sh/hook-delete-policy: {{ .deletePolicy | default "before-hook-creation,hook-succeeded" | quote }}
{{- end }}
