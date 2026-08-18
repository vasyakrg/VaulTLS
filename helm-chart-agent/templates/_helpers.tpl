{{- define "vaultls-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vaultls-agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "vaultls-agent.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "vaultls-agent.labels" -}}
app.kubernetes.io/name: {{ include "vaultls-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "vaultls-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultls-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vaultls-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vaultls-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "vaultls-agent.credentialsSecret" -}}
{{- default (printf "%s-credentials" (include "vaultls-agent.fullname" .)) .Values.vaultls.existingSecret -}}
{{- end -}}

{{/*
The namespaces the agent writes Secrets into. Every one of them gets its own
Role and RoleBinding, so the agent never holds cluster-wide access to Secrets.
*/}}
{{- define "vaultls-agent.targetNamespaces" -}}
{{- $ns := list -}}
{{- range .Values.certificates -}}
{{- $ns = append $ns (required "certificates[].namespace is required" .namespace) -}}
{{- end -}}
{{- $ns | uniq | toJson -}}
{{- end -}}
