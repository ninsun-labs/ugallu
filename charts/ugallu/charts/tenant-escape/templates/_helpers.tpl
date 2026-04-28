{{/* Common labels for the tenant-escape subchart. */}}
{{- define "tenantescape.labels" -}}
app.kubernetes.io/name: ugallu-tenant-escape
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: tenant-escape
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "tenantescape.selectorLabels" -}}
app.kubernetes.io/name: ugallu-tenant-escape
app.kubernetes.io/component: tenant-escape
{{- end -}}

{{- define "tenantescape.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
