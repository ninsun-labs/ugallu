{{- define "backupverify.namespace" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- end -}}

{{- define "backupverify.labels" -}}
app.kubernetes.io/name: ugallu-backup-verify
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: backup-verify
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "backupverify.selectorLabels" -}}
app.kubernetes.io/name: ugallu-backup-verify
app.kubernetes.io/component: backup-verify
{{- end -}}

{{- define "backupverify.serviceAccount" -}}
ugallu-backup-verify
{{- end -}}
