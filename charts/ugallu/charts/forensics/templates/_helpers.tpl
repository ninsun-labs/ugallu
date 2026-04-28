{{/* Common labels for the forensics subchart. */}}
{{- define "forensics.labels" -}}
app.kubernetes.io/name: ugallu-forensics
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: forensics
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "forensics.selectorLabels" -}}
app.kubernetes.io/name: ugallu-forensics
app.kubernetes.io/component: forensics
{{- end -}}

{{- define "forensics.namespace" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- end -}}

{{/* Operator args. Real-binary path renders the controller-runtime
     flags; placeholder mode falls back to the user-supplied args
     (typically "" so sleep stays running). */}}
{{- define "forensics.args" -}}
{{- if .Values.placeholder -}}
{{ toJson .Values.args }}
{{- else -}}
[
  "--metrics-bind-address=:{{ .Values.metricsPort }}",
  "--health-probe-bind-address=:{{ .Values.healthProbePort }}",
  "--leader-election-namespace={{ include "forensics.namespace" . }}",
  "--cluster-id={{ .Values.clusterIdentity.clusterID }}",
  "--snapshot-image={{ .Values.image.repository }}:{{ .Values.image.tag }}",
  "--snapshot-image-pull-policy={{ .Values.image.pullPolicy }}",
  "--worm-endpoint={{ .Values.worm.endpoint }}",
  "--worm-bucket={{ .Values.worm.bucket }}",
  "--worm-region={{ .Values.worm.region }}",
  "--worm-path-style={{ .Values.worm.usePathStyle }}",
  "--worm-secret-name={{ .Values.worm.secret.name }}",
  "--worm-secret-namespace={{ .Values.worm.secret.namespace }}",
  "--worm-lock-mode={{ .Values.worm.lockMode }}",
  "--worm-lock-until={{ .Values.worm.lockUntil }}",
  "--forensics-namespace={{ include "forensics.namespace" . }}"
]
{{- end -}}
{{- end -}}
