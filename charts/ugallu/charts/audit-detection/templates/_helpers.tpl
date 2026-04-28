{{/* Common labels for the audit-detection subchart. */}}
{{- define "auditdetection.labels" -}}
app.kubernetes.io/name: ugallu-audit-detection
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: audit-detection
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "auditdetection.selectorLabels" -}}
app.kubernetes.io/name: ugallu-audit-detection
app.kubernetes.io/component: audit-detection
{{- end -}}

{{/*
Namespace selection by source mode:
  - webhook: ugallu-system (PSA restricted, no host access needed)
  - file:    ugallu-system-privileged (PSA privileged, hostPath required
             to read the kubelet/apiserver audit log)
*/}}
{{- define "auditdetection.namespace" -}}
{{- if eq .Values.source.mode "file" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- else -}}
{{ .Values.global.namespaces.system | default "ugallu-system" }}
{{- end -}}
{{- end -}}

{{/* env block with shared secret + cluster identity. */}}
{{- define "auditdetection.env" -}}
- name: CLUSTER_ID
  value: {{ .Values.clusterIdentity.clusterID | quote }}
- name: CLUSTER_NAME
  value: {{ .Values.clusterIdentity.clusterName | quote }}
{{- if eq .Values.source.mode "webhook" }}
{{- if .Values.source.webhook.sharedSecretRef.secretName }}
- name: AUDIT_WEBHOOK_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.source.webhook.sharedSecretRef.secretName }}
      key: {{ .Values.source.webhook.sharedSecretRef.key }}
{{- end }}
{{- end }}
{{- end -}}

{{/* args block selects file / webhook flags based on source.mode. */}}
{{- define "auditdetection.args" -}}
{{- if .Values.placeholder -}}
{{ toJson .Values.args }}
{{- else -}}
[
  "--source={{ .Values.source.mode }}",
  "--cluster-id=$(CLUSTER_ID)",
  "--metrics-bind-address=:{{ .Values.metricsPort }}",
  "--health-probe-bind-address=:{{ .Values.healthProbePort }}",
  "--leader-election-namespace={{ include "auditdetection.namespace" . }}"
{{- if eq .Values.source.mode "file" -}}
  ,"--audit-log-path={{ .Values.source.file.path }}"
{{- else -}}
  ,"--webhook-listen={{ .Values.source.webhook.listenAddr }}",
  "--webhook-path={{ .Values.source.webhook.path }}"
{{- if .Values.source.webhook.tlsSecretRef.secretName -}}
  ,"--webhook-cert=/tls/tls.crt",
  "--webhook-key=/tls/tls.key"
{{- end -}}
{{- if .Values.source.webhook.clientCASecretRef.secretName -}}
  ,"--webhook-client-ca=/client-ca/ca.crt"
{{- end -}}
{{- end -}}
]
{{- end -}}
{{- end -}}
