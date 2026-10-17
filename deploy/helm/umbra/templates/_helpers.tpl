{{- define "umbra.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- /* The image of the services of one server: (list $ $server). A server
       with its own imageTag takes a new image before the others. */ -}}
{{- define "umbra.serverImage" -}}
{{- $root := index . 0 -}}
{{- $server := index . 1 -}}
{{ $root.Values.image.repository }}:{{ $server.imageTag | default $root.Values.image.tag | default $root.Chart.AppVersion }}
{{- end -}}

{{- define "umbra.labels" -}}
app.kubernetes.io/name: umbra
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- /* The server of a name, as JSON: (list $ "east-1"). */ -}}
{{- define "umbra.server" -}}
{{- $root := index . 0 -}}
{{- $name := index . 1 -}}
{{- $found := dict -}}
{{- range $root.Values.servers -}}
{{- if eq .name $name -}}{{- $found = . -}}{{- end -}}
{{- end -}}
{{- if not $found -}}{{- fail (printf "no server %s in servers" $name) -}}{{- end -}}
{{- $found | toJson -}}
{{- end -}}

{{- define "umbra.node" -}}
{{- .node | default .name -}}
{{- end -}}

{{- /* The servers with an entry relay, as a JSON list of names. */ -}}
{{- define "umbra.entries" -}}
{{- $entries := list -}}
{{- range .Values.servers -}}
{{- $server := . -}}
{{- range .relays -}}
{{- if eq .role "entry" -}}{{- $entries = append $entries $server.name -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- $entries | uniq | toJson -}}
{{- end -}}

{{- /* NTF-002: the first entry server that is not the server of a gateway:
       (list $ "east-1"). */ -}}
{{- define "umbra.route" -}}
{{- $root := index . 0 -}}
{{- $gateway := index . 1 -}}
{{- $route := "" -}}
{{- range (include "umbra.entries" $root | fromJsonArray) -}}
{{- if and (not $route) (ne . $gateway) -}}{{- $route = . -}}{{- end -}}
{{- end -}}
{{- if not $route -}}
{{- fail (printf "no entry relay on another server than %s, the server of a gateway (NTF-002)" $gateway) -}}
{{- end -}}
{{- $route -}}
{{- end -}}

{{- /* The container security of a service with no privilege. */ -}}
{{- define "umbra.security" -}}
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
runAsNonRoot: true
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
seccompProfile:
  type: RuntimeDefault
capabilities:
  drop: [ALL]
{{- end -}}

{{- /* The state directory of each relay of the network, by its name. */ -}}
{{- define "umbra.relayDirs" -}}
{{- $dirs := list "relays" -}}
{{- range .Values.servers -}}
{{- range .relays -}}
{{- $dirs = append $dirs (printf "relays/%s" .name) -}}
{{- end -}}
{{- end -}}
{{- join " " $dirs -}}
{{- end -}}

{{- /* The directories of each service on the node, and their owners. */ -}}
{{- define "umbra.init" -}}
- name: init
  image: {{ include "umbra.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args: ["init", "/srv/umbra"]
  env:
    - name: UMBRA_RELAY_DIRS
      value: {{ include "umbra.relayDirs" . | quote }}
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

{{- define "umbra.trustEnv" -}}
{{- if .Values.trust }}
- name: UMBRA_TRUST
  value: /etc/umbra/trust/ca.pem
{{- end }}
{{- end -}}

{{- define "umbra.trustMount" -}}
{{- if .Values.trust }}
- name: trust
  mountPath: /etc/umbra/trust
  readOnly: true
{{- end }}
{{- end -}}

{{- /* The volumes of each pod: the state on the node, memory for the
       settings, and the test CA. */ -}}
{{- define "umbra.volumes" -}}
- name: root
  hostPath:
    path: {{ .Values.root }}
    type: DirectoryOrCreate
- name: run
  emptyDir:
    medium: Memory
    sizeLimit: 8Mi
- name: tmp
  emptyDir:
    medium: Memory
    sizeLimit: 64Mi
{{- if .Values.trust }}
- name: trust
  configMap:
    name: {{ .Release.Name }}-trust
{{- end }}
{{- end -}}

{{- define "umbra.baseMounts" -}}
- name: run
  mountPath: /run/umbra
- name: tmp
  mountPath: /tmp
{{- end -}}

{{- /* Each relay of the network for the signer and the measurer:
       <name>,<role>,<class>, with a space between two. */ -}}
{{- define "umbra.relayList" -}}
{{- $list := list -}}
{{- range .Values.servers -}}
{{- range .relays -}}
{{- $list = append $list (printf "%s,%s,%v" .name .role .class) -}}
{{- end -}}
{{- end -}}
{{- join " " $list -}}
{{- end -}}

{{- /* The revoked measurer certificates: <id>,<not_after>. */ -}}
{{- define "umbra.revoked" -}}
{{- $list := list -}}
{{- range .Values.signer.revokedMeasurers -}}
{{- $list = append $list (printf "%s,%v" .id .not_after) -}}
{{- end -}}
{{- join " " $list -}}
{{- end -}}
