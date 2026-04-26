{{/* Common labels for the attestor subchart. */}}
{{- define "attestor.labels" -}}
app.kubernetes.io/name: ugallu-attestor
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: attestor
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "attestor.selectorLabels" -}}
app.kubernetes.io/name: ugallu-attestor
app.kubernetes.io/component: attestor
{{- end -}}

{{- define "attestor.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
