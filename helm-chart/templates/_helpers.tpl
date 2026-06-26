{{/*
Expand the name of the chart.
*/}}
{{- define "vaultls.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "vaultls.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version label.
*/}}
{{- define "vaultls.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "vaultls.labels" -}}
helm.sh/chart: {{ include "vaultls.chart" . }}
{{ include "vaultls.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "vaultls.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultls.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the application Secret (generated or existing).
*/}}
{{- define "vaultls.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "vaultls.fullname" . }}
{{- end }}
{{- end }}

{{/*
Name of the backup Secret (generated or existing).
*/}}
{{- define "vaultls.backupSecretName" -}}
{{- if .Values.backup.restic.existingSecret }}
{{- .Values.backup.restic.existingSecret }}
{{- else }}
{{- printf "%s-backup" (include "vaultls.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Name of the PVC (generated or existing).
*/}}
{{- define "vaultls.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "vaultls.fullname" . }}
{{- end }}
{{- end }}
