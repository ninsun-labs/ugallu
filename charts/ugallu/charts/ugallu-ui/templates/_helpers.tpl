{{/* Common labels for the ugallu-ui subchart. */}}
{{- define "ugalluui.labels" -}}
app.kubernetes.io/name: ugallu-ui
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: ui
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "ugalluui.selectorLabels" -}}
app.kubernetes.io/name: ugallu-ui
app.kubernetes.io/component: ui
{{- end -}}

{{- define "ugalluui.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}

{{- define "ugalluui.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "ugalluui.serviceAccountName" -}}
{{ .Values.serviceAccount.name | default "ugallu-ui-bff" }}
{{- end -}}
