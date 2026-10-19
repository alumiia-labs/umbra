{{- define "relay.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "relay.labels" -}}
app.kubernetes.io/name: umbra-relay
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- /* The directories of the relay on the node, and their owners. */ -}}
{{- define "relay.init" -}}
- name: init
  image: {{ include "relay.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args: ["init", "/srv/umbra"]
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    seccompProfile:
      type: RuntimeDefault
    capabilities:
      drop: [ALL]
      add: [CHOWN, FOWNER, DAC_OVERRIDE]
  volumeMounts:
    - name: root
      mountPath: /srv/umbra
{{- end -}}

{{- define "relay.root" -}}
- name: root
  hostPath:
    path: {{ .Values.root }}
    type: DirectoryOrCreate
{{- end -}}
