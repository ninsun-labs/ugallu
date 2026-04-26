{{/* Common labels for the resolver subchart. */}}
{{- define "resolver.labels" -}}
app.kubernetes.io/name: ugallu-resolver
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: resolver
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "resolver.selectorLabels" -}}
app.kubernetes.io/name: ugallu-resolver
app.kubernetes.io/component: resolver
{{- end -}}

{{- define "resolver.namespace" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- end -}}
