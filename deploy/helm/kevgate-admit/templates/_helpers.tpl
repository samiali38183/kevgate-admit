{{- define "kevgate-admit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kevgate-admit.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kevgate-admit.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "kevgate-admit.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kevgate-admit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kevgate-admit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kevgate-admit.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- define "kevgate-admit.tlsSecret" -}}
{{- if eq .Values.tls.mode "existingSecret" -}}
{{- required "tls.secretName is required when tls.mode is existingSecret" .Values.tls.secretName -}}
{{- else -}}
{{- default (printf "%s-tls" (include "kevgate-admit.fullname" .)) .Values.tls.secretName -}}
{{- end -}}
{{- end -}}

{{- define "kevgate-admit.evidenceConfigMap" -}}
{{- default (printf "%s-evidence" (include "kevgate-admit.fullname" .)) .Values.evidence.existingConfigMap -}}
{{- end -}}
