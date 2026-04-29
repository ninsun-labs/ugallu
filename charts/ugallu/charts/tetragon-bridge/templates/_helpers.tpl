{{- define "tetragonbridge.namespace" -}}
{{ .Values.global.namespaces.privileged | default "ugallu-system-privileged" }}
{{- end -}}

{{- define "tetragonbridge.labels" -}}
app.kubernetes.io/name: ugallu-tetragon-bridge
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/part-of: ugallu
app.kubernetes.io/component: tetragon-bridge
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") }}
{{- end -}}

{{- define "tetragonbridge.selectorLabels" -}}
app.kubernetes.io/name: ugallu-tetragon-bridge
app.kubernetes.io/component: tetragon-bridge
{{- end -}}

{{- define "tetragonbridge.serviceAccount" -}}
ugallu-tetragon-bridge
{{- end -}}

{{- define "tetragonbridge.useUDS" -}}
{{- if hasPrefix "unix://" .Values.source.tetragon.endpoint -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
Render the args list as a JSON array. Kept as a helper so the
DaemonSet template stays terse.
*/}}
{{- define "tetragonbridge.args" -}}
[
  "--source={{ .Values.source.mode }}",
  "--listen-addr=:{{ .Values.ports.grpc }}",
  "--probe-addr=:{{ .Values.ports.probe }}",
  "--per-subscriber-buffer={{ .Values.buffer.perSubscriberSize }}",
  "--default-events-per-sec={{ .Values.buffer.defaultEventsPerSec }}"
{{- if eq .Values.source.mode "tetragon" -}}
  ,"--tetragon-endpoint={{ .Values.source.tetragon.endpoint }}"
{{- else -}}
  ,"--synthetic-loop={{ .Values.source.synthetic.loopInterval }}"
{{- end -}}
{{- if .Values.bearerToken.secretName -}}
  ,"--bearer-token-file=/etc/ugallu/bridge-token/{{ .Values.bearerToken.key }}"
{{- end -}}
]
{{- end -}}
