{{/* Common labels for the gitops-responder subchart. */}}
{{- define "gitopsresponder.labels" -}}
app.kubernetes.io/name: ugallu-gitops-responder
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: gitops-responder
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "gitopsresponder.selectorLabels" -}}
app.kubernetes.io/name: ugallu-gitops-responder
app.kubernetes.io/component: gitops-responder
{{- end -}}

{{- define "gitopsresponder.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
