{{/* Common labels for the backpressure subchart. */}}
{{- define "backpressure.labels" -}}
app.kubernetes.io/name: ugallu-backpressure
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: backpressure
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "backpressure.selectorLabels" -}}
app.kubernetes.io/name: ugallu-backpressure
app.kubernetes.io/component: backpressure
{{- end -}}

{{- define "backpressure.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
