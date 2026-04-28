{{/* Common labels for the webhook-auditor subchart. */}}
{{- define "webhookauditor.labels" -}}
app.kubernetes.io/name: ugallu-webhook-auditor
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: webhook-auditor
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "webhookauditor.selectorLabels" -}}
app.kubernetes.io/name: ugallu-webhook-auditor
app.kubernetes.io/component: webhook-auditor
{{- end -}}

{{- define "webhookauditor.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
