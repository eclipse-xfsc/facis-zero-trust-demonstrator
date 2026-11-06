{{- define "ztd.fullname" -}}{{- printf "%s-keycloak" .Release.Name | trunc 63 | trimSuffix "-" -}}{{- end -}}
{{- define "ztd.checkOwner" -}}
{{- $annotations := default (dict) .object.metadata.annotations -}}
{{- $owner := index $annotations "meta.helm.sh/release-name" -}}
{{- $namespace := index $annotations "meta.helm.sh/release-namespace" -}}
{{- if or (and $owner (ne $owner .release.Name)) (and $namespace (ne $namespace .release.Namespace)) -}}
{{- fail (printf "%s/%s belongs to Helm release %s in %s; use deployment.mode=existing instead of adopting another release's resources" .object.kind .object.metadata.name $owner $namespace) -}}
{{- end -}}
{{- end -}}
{{- define "ztd.labels" -}}
app.kubernetes.io/name: facis-ztd-keycloak
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}
{{- define "ztd.personaSecret" -}}
{{- if .Values.externalSecrets.enabled -}}
{{- printf "%s-openbao-personas" (include "ztd.fullname" .) -}}
{{- else -}}{{- default (printf "%s-personas" (include "ztd.fullname" .)) .Values.personas.existingSecret -}}{{- end -}}
{{- end -}}
{{- define "ztd.adminSecret" -}}
{{- if .Values.externalSecrets.enabled -}}{{- printf "%s-openbao-admin" (include "ztd.fullname" .) -}}
{{- else -}}{{- .Values.admin.existingSecret -}}{{- end -}}
{{- end -}}
{{- define "ztd.uiOrigin" -}}{{- trimSuffix "/" .Values.ui.origin -}}{{- end -}}
{{- define "ztd.callback" -}}{{- default (printf "%s/dev/ztd/oidc/callback" (include "ztd.uiOrigin" .)) .Values.ui.callbackUrl -}}{{- end -}}
{{- define "ztd.frontLogout" -}}{{- default (printf "%s/dev/ztd/oidc/frontchannel-logout" (include "ztd.uiOrigin" .)) .Values.ui.frontchannelLogoutUrl -}}{{- end -}}
{{- define "ztd.backLogout" -}}{{- default (printf "%s/dev/ztd/oidc/backchannel-logout" (include "ztd.uiOrigin" .)) .Values.ui.backchannelLogoutUrl -}}{{- end -}}
{{- define "ztd.afterLogout" -}}{{- default (printf "%s/dev/facis-demo/" (include "ztd.uiOrigin" .)) .Values.ui.postLogoutRedirectUrl -}}{{- end -}}
{{- define "ztd.validate" -}}
{{- if not (has .Values.deployment.mode (list "existing" "adopt" "new")) -}}{{- fail "deployment.mode must be existing, adopt or new" -}}{{- end -}}
{{- if not (regexMatch "^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$" .Values.keycloak.publicUrl) -}}{{- fail "keycloak.publicUrl must be an HTTPS origin" -}}{{- end -}}
{{- if not (regexMatch "^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$" .Values.ui.origin) -}}{{- fail "ui.origin must be an HTTPS origin" -}}{{- end -}}
{{- $origin := include "ztd.uiOrigin" . -}}
{{- range $url := list (include "ztd.callback" .) (include "ztd.frontLogout" .) (include "ztd.backLogout" .) (include "ztd.afterLogout" .) -}}
{{- if or (not (hasPrefix (printf "%s/" $origin) $url)) (regexMatch "[?*#]" $url) -}}{{- fail "UI callback/logout URLs must be exact URLs under ui.origin, without wildcards, queries or fragments" -}}{{- end -}}
{{- end -}}
{{- if and .Values.personas.credentialsJSON .Values.personas.existingSecret -}}{{- fail "Choose personas.credentialsJSON or personas.existingSecret" -}}{{- end -}}
{{- if and .Values.externalSecrets.enabled (or .Values.personas.credentialsJSON .Values.personas.existingSecret) -}}{{- fail "externalSecrets.enabled uses OpenBao personas; remove other persona inputs" -}}{{- end -}}
{{- if eq .Values.deployment.mode "new" -}}
{{- $_ := required "new mode requires keycloak.image (stock Keycloak image, preferably by digest)" .Values.keycloak.image -}}
{{- $_ := required "new mode requires postgresql.image (official Debian image, preferably by digest)" .Values.postgresql.image -}}
{{- if .Values.externalSecrets.enabled -}}{{- fail "For new mode, provision the initial runtime Secret first and use existing/adopt for OpenBao-managed apply credentials" -}}{{- end -}}
{{- if ne .Values.admin.existingSecret .Values.deployment.runtimeSecret -}}{{- fail "new mode uses admin.existingSecret = deployment.runtimeSecret" -}}{{- end -}}
{{- end -}}
{{- end -}}
