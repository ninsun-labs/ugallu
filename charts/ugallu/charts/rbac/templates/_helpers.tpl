{{/* Common labels for rbac subchart resources. */}}
{{- define "rbac.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: rbac
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{/* Resolve namespace names from global with safe defaults. */}}
{{- define "rbac.ns.system" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}

{{- define "rbac.ns.privileged" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- end -}}
