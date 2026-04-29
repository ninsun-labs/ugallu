{{- define "confidentialattestation.namespace" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- end -}}

{{- define "confidentialattestation.labels" -}}
app.kubernetes.io/name: ugallu-confidential-attestation
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: confidential-attestation
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "confidentialattestation.selectorLabels" -}}
app.kubernetes.io/name: ugallu-confidential-attestation
app.kubernetes.io/component: confidential-attestation
{{- end -}}

{{- define "confidentialattestation.serviceAccount" -}}
ugallu-confidential-attestation
{{- end -}}
