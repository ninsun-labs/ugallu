{{/* Common labels for the honeypot subchart. */}}
{{- define "honeypot.labels" -}}
app.kubernetes.io/name: ugallu-honeypot
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: honeypot
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "honeypot.selectorLabels" -}}
app.kubernetes.io/name: ugallu-honeypot
app.kubernetes.io/component: honeypot
{{- end -}}

{{- define "honeypot.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
