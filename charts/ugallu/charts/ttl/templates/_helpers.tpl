{{/* Common labels for the ttl subchart. */}}
{{- define "ttl.labels" -}}
app.kubernetes.io/name: ugallu-ttl
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: ttl
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "ttl.selectorLabels" -}}
app.kubernetes.io/name: ugallu-ttl
app.kubernetes.io/component: ttl
{{- end -}}

{{- define "ttl.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
