{{- define "seccompgen.namespace" -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}

{{- define "seccompgen.labels" -}}
app.kubernetes.io/name: ugallu-seccomp-gen
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: seccomp-gen
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "seccompgen.selectorLabels" -}}
app.kubernetes.io/name: ugallu-seccomp-gen
app.kubernetes.io/component: seccomp-gen
{{- end -}}

{{- define "seccompgen.serviceAccount" -}}
ugallu-seccomp-gen
{{- end -}}
