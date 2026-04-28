{{/* Common labels for the dns-detect subchart. */}}
{{- define "dnsdetect.labels" -}}
app.kubernetes.io/name: ugallu-dns-detect
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: dns-detect
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "dnsdetect.selectorLabels" -}}
app.kubernetes.io/name: ugallu-dns-detect
app.kubernetes.io/component: dns-detect
{{- end -}}

{{- define "dnsdetect.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
