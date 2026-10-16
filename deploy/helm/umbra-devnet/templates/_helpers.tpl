{{- define "umbra-devnet.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "umbra-devnet.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "umbra-devnet.labels" -}}
{{ include "umbra-devnet.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: umbra
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- /* devnet.sh puts the address into a sed expression and refuses other characters. */ -}}
{{- define "umbra-devnet.host" -}}
{{- if not (regexMatch "^[A-Za-z0-9.-]+$" (toString .Values.host)) -}}
{{- fail (printf "host is an IPv4 address or a host name: %v" .Values.host) -}}
{{- end -}}
{{- .Values.host -}}
{{- end -}}
