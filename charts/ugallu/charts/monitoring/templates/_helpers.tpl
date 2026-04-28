{{- define "monitoring.labels" -}}
app.kubernetes.io/name: ugallu-monitoring
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: monitoring
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "monitoring.namespace" -}}
{{ .Values.namespace | default "monitoring" }}
{{- end -}}
