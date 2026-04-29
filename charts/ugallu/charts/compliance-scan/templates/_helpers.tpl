{{- define "compliancescan.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}

{{- define "compliancescan.labels" -}}
app.kubernetes.io/name: ugallu-compliance-scan
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: compliance-scan
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "compliancescan.selectorLabels" -}}
app.kubernetes.io/name: ugallu-compliance-scan
app.kubernetes.io/component: compliance-scan
{{- end -}}

{{- define "compliancescan.serviceAccount" -}}
ugallu-compliance-scan
{{- end -}}
