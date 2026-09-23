{{- define "fixture.labels" -}}
app.kubernetes.io/name: lifecycle-fixture
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
facis.ztd/fixture: "true"
{{- end -}}

{{- define "fixture.selector" -}}
app.kubernetes.io/name: lifecycle-fixture
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
