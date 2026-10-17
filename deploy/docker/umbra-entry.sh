#!/bin/bash
# The entry of each UMBRA server container. It does what the roles of
# deploy/ansible do on a server: it makes the secrets of a service one time,
# writes its settings file from the environment, and starts it.
#
#   umbra-entry init                    # as root: the directories and owners
#   umbra-entry relay [descriptor]      # a relay, or its signed descriptor
#   umbra-entry ndr [key-config]        # the notification server, or its key
#   umbra-entry directory [pins]        # the directory, or its pins
#   umbra-entry signer [sign [--force]] # the signer loop, or one manifest
#   umbra-entry manifest                # nginx, which serves the manifest
#   umbra-entry authority               # the authority tool
#   umbra-entry measurer [now]          # the weekly class tests, or one run
#
# deploy/docker/README.md names each variable. A secret never leaves the
# state directory of its service.
set -euo pipefail
umask 077
# Under Kubernetes this shell is process 1, which takes no default action
# on a signal.
trap 'exit 143' TERM INT

TLS_DIR=/etc/umbra/tls
NETWORK_DIR=/etc/umbra/network
STATE=/var/lib/umbra
RUN=/run/umbra
SIGNER_HOME=/var/lib/umbra-signer
SIGNER_KEYS="${UMBRA_SIGNER_KEYS:-$SIGNER_HOME/keys}"
OUT=/var/www/umbra/.well-known/umbra
DESCRIPTORS=/etc/umbra-signer/descriptors
AUTHORITY=/var/lib/umbra-authority
AUTHORITY_KEYS=/var/lib/umbra-authority-keys
MEASURER=/var/lib/umbra-measurer

say() { echo "umbra-entry: $*" >&2; }
die() { say "$*"; exit 1; }
# An alert line starts with ALERT, thus a log watcher finds it.
alert() { say "ALERT: $*"; }

need() {
    local name
    for name in "$@"; do
        [ -n "${!name:-}" ] || die "set $name"
    done
}

# A sleep that a signal ends at once.
nap() {
    sleep "$1" &
    wait $! || true
}

seed() { head -c 32 /dev/urandom | od -An -tx1 -v | tr -d ' \n'; }

# A settings file in a file system of memory: the secrets in it then never
# reach a disk outside the state directory.
conf_dir() { mkdir -p "$RUN"; }

wait_for() {
    local file=$1 what=$2 waited=0
    until [ -s "$file" ]; do
        if [ $((waited % 300)) -eq 0 ]; then
            say "waiting for $what ($file)"
        fi
        nap 5
        waited=$((waited + 5))
    done
}

tls_lines() {
    wait_for "$TLS_DIR/cert.pem" "the certificate of this server"
    wait_for "$TLS_DIR/key.pem" "the key of the certificate"
    echo "cert=$TLS_DIR/cert.pem"
    echo "key=$TLS_DIR/key.pem"
}

trust_line() {
    if [ -n "${UMBRA_TRUST:-}" ]; then
        echo "${1:-trust}=$UMBRA_TRUST"
    fi
}

# Docker and Kubernetes give a user with no root no capability, thus a port
# below 1024 needs the setting of the host. The service then holds no
# capability at all.
port_check() {
    local port=$1 first
    first=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)
    if [ "$port" -lt "$first" ]; then
        die "port $port needs net.ipv4.ip_unprivileged_port_start=$port or lower on the host (deploy/docker/README.md)"
    fi
}

# A service reads its certificate at its start. Thus the entry stops it when
# certbot writes a new one, and the restart policy starts it again.
# UMBRA_RESTART_DELAY keeps the relays of one server from a restart together.
# A service with no certificate, as the authority tool, has an empty stamp.
stamp() {
    stat -Lc '%Y %s' "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem" 2>/dev/null | tr '\n' ' ' || true
}

supervise() {
    local before pid
    before=$(stamp)
    "$@" &
    pid=$!
    trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"; exit 143' TERM INT
    while kill -0 "$pid" 2>/dev/null; do
        sleep 60 &
        wait $! || true
        if [ "$(stamp)" != "$before" ]; then
            sleep "${UMBRA_RESTART_DELAY:-0}"
            say "the certificate is new: the service starts again"
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" || true
            exit 0
        fi
    done
    wait "$pid"
}

# Makes a secrets file one time. It takes its name only once each line
# checks, thus a failed start leaves no half file.
secret_once() {
    local file=$1 check=$2 make=$3 tmp
    [ -s "$file" ] && return 0
    tmp=$(mktemp "$file.XXXXXX")
    "$make" > "$tmp"
    if ! grep -Eq "$check" "$tmp"; then
        rm -f "$tmp"
        die "the new secrets of $file do not check"
    fi
    mv "$tmp" "$file"
    say "made $file"
}

# --- The relay (roles/relay_identity and roles/relay) -----------------------

relay_secret() { umbra-relay keygen | grep -v '^#'; }

relay_conf() {
    need UMBRA_RELAY_NAME UMBRA_RELAY_ROLE UMBRA_RELAY_CLASS UMBRA_PUBLIC_HOST \
        UMBRA_PUBLIC_ADDRESS UMBRA_PUBLIC_PORT UMBRA_OPERATOR UMBRA_COUNTRY UMBRA_ASN \
        UMBRA_FAMILY UMBRA_SIGNER
    local name=$UMBRA_RELAY_NAME role=$UMBRA_RELAY_ROLE class=$UMBRA_RELAY_CLASS roles
    [[ "$name" =~ ^[a-z0-9-]+$ ]] || die "UMBRA_RELAY_NAME takes a-z, 0-9 and -"
    [[ "$class" =~ ^[0-3]$ ]] || die "UMBRA_RELAY_CLASS is 0, 1, 2 or 3"
    [[ "$UMBRA_FAMILY" =~ ^[0-9a-f]{64}$ ]] || die "UMBRA_FAMILY is 64 hex characters"
    [[ "$UMBRA_PUBLIC_ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "UMBRA_PUBLIC_ADDRESS is an IPv4 address"
    [[ "$UMBRA_SIGNER" =~ ^[A-Za-z0-9.-]+,[0-9.]+,[0-9]+$ ]] ||
        die "UMBRA_SIGNER is <host name>,<IPv4 address>,<port>"
    case $role in
        entry)
            roles=chain,ingress
            # Phones reach an entry relay, and a network that lets out
            # port 443 alone still reaches it.
            [ "$class" -ge 1 ] || die "an entry relay takes class 1 or more"
            [ "$UMBRA_PUBLIC_PORT" = 443 ] || die "an entry relay takes port 443"
            ;;
        middle) roles=chain ;;
        exit) roles=queue,chain,attachment ;;
        *) die "UMBRA_RELAY_ROLE is entry, middle or exit" ;;
    esac
    secret_once "$STATE/secret.conf" '^identity_seed=[0-9a-f]{64}$' relay_secret
    grep -Eq '^static_secret=[0-9a-f]{64}$' "$STATE/secret.conf" ||
        die "$STATE/secret.conf holds no static_secret"
    conf_dir
    # The lines that the descriptor states. A change of one of them takes a
    # new descriptor.
    {
        echo "public=$UMBRA_PUBLIC_HOST,$UMBRA_PUBLIC_ADDRESS,$UMBRA_PUBLIC_PORT"
        echo "operator=$UMBRA_OPERATOR"
        echo "country=$UMBRA_COUNTRY"
        echo "asn=$UMBRA_ASN"
        echo "family=$UMBRA_FAMILY"
        echo "class=$class"
        echo "roles=$roles"
        # Part 10 REL-127: a relay with the attachment role alone holds chunks.
        if [ "$role" = exit ]; then
            echo "chunk_capacity=${UMBRA_CHUNK_CAPACITY:-1073741824}"
        fi
    } > "$RUN/public.conf"
    {
        echo "listen=0.0.0.0:${UMBRA_LISTEN_PORT:-$UMBRA_PUBLIC_PORT}"
        tls_lines
        echo "store=$STATE/relay.db"
        cat "$RUN/public.conf"
        echo "manifest=$STATE/manifest.bin"
        # A rotation of the key set (Part 10 REL-200) writes this file.
        echo "keyset=$STATE/keyset.bin"
        echo "manifest_from=$UMBRA_SIGNER"
        # NTF-002: the gateway sits on another server than this entry relay.
        [ -z "${UMBRA_OHTTP_GATEWAY:-}" ] || echo "ohttp_gateway=$UMBRA_OHTTP_GATEWAY"
        [ -z "${UMBRA_DIRECTORY_GATEWAY:-}" ] || echo "directory_gateway=$UMBRA_DIRECTORY_GATEWAY"
        # A route goes with its key alone. Before the operator has the keys,
        # the relay still signs its descriptor.
        if [ -n "${UMBRA_NDR_ROUTE:-}" ] && [ -n "${UMBRA_NDR_KEY_CONFIG:-}" ]; then
            echo "ndr_route=$UMBRA_NDR_ROUTE"
            echo "ndr_key_config=$UMBRA_NDR_KEY_CONFIG"
        fi
        if [ -n "${UMBRA_DIRECTORY_ROUTE:-}" ] && [ -n "${UMBRA_DIRECTORY_PINS:-}" ]; then
            echo "directory_route=$UMBRA_DIRECTORY_ROUTE"
            echo "directory_pins=$UMBRA_DIRECTORY_PINS"
        fi
        trust_line
        cat "$STATE/secret.conf"
    } > "$RUN/relay.conf"
}

# Each signature differs, and a manifest with another descriptor has another
# root. An hour takes one root (Part 10 REL-160). Thus the relay signs only
# when it has no descriptor, or when a line that the descriptor states
# changed.
relay_descriptor() {
    local sum
    sum=$(cat "$RUN/public.conf" "$STATE/secret.conf" | sha256sum | cut -d' ' -f1)
    if [ -s "$STATE/relay.desc" ] && [ "$(cat "$STATE/relay.desc.sum" 2>/dev/null)" = "$sum" ]; then
        return 0
    fi
    umbra-relay sign-descriptor "$RUN/relay.conf" "$STATE/relay.desc.part"
    mv "$STATE/relay.desc.part" "$STATE/relay.desc"
    echo "$sum" > "$STATE/relay.desc.sum"
    chmod 0644 "$STATE/relay.desc"
    say "signed a new descriptor: give $STATE/relay.desc to the signer as $UMBRA_RELAY_NAME.desc"
}

fetch_manifest() {
    local into=$1 host ip port
    IFS=, read -r host ip port <<< "$UMBRA_SIGNER"
    curl -fsS --max-time 30 --proto =https --tlsv1.3 \
        --resolve "$host:$port:$ip" ${UMBRA_TRUST:+--cacert "$UMBRA_TRUST"} \
        -o "$into.tmp" "https://$host:$port/.well-known/umbra/manifest" &&
        mv "$into.tmp" "$into"
}

relay_run() {
    relay_conf
    relay_descriptor
    if [ "$UMBRA_RELAY_ROLE" = exit ]; then
        # NTF-127 and Part 13 §13.5: an exit relay pushes, and it takes the
        # issuer keys, through an entry relay on another server. It waits
        # with its descriptor ready, thus the operator can collect it.
        local name
        for name in UMBRA_NDR_ROUTE UMBRA_NDR_KEY_CONFIG UMBRA_DIRECTORY_ROUTE UMBRA_DIRECTORY_PINS; do
            if [ -z "${!name:-}" ]; then
                say "waiting for $name: an exit relay needs it; set it and start the relay again"
                while true; do nap 3600; done
            fi
        done
    fi
    # The key set is the root of trust of the relay, thus it comes from the
    # operator and not from the network. A rotation later writes a newer one.
    if [ ! -s "$STATE/keyset.bin" ]; then
        wait_for "$NETWORK_DIR/keyset.bin" "the key set of the signer"
        install -m 0644 "$NETWORK_DIR/keyset.bin" "$STATE/keyset.bin"
    fi
    # The relay verifies each manifest under the key set. With no manifest
    # it waits for the first one. With one, a fetched manifest goes beside
    # it, and the relay takes it when the old one gives this relay no place.
    if [ ! -s "$STATE/manifest.bin" ]; then
        until fetch_manifest "$STATE/manifest.bin"; do
            say "no manifest from $UMBRA_SIGNER yet; next try in 60 s"
            nap 60
        done
    else
        fetch_manifest "$STATE/manifest.part" || say "no fresh manifest from $UMBRA_SIGNER"
    fi
    port_check "${UMBRA_LISTEN_PORT:-$UMBRA_PUBLIC_PORT}"
    supervise umbra-relay "$RUN/relay.conf"
}

# --- The notification server (roles/ndr) ------------------------------------

ndr_secret() { echo "kem_seed=$(seed)"; }

ndr_conf() {
    secret_once "$STATE/secret.conf" '^kem_seed=[0-9a-f]{64}$' ndr_secret
    [ -s /etc/umbra/fcm.json ] ||
        die "no /etc/umbra/fcm.json: give the service account file of the Firebase project"
    conf_dir
    {
        echo "listen=0.0.0.0:${UMBRA_LISTEN_PORT:-8443}"
        tls_lines
        echo "key_id=1"
        echo "store=$STATE/ndr.db"
        echo "fcm_credentials=/etc/umbra/fcm.json"
        trust_line
        cat "$STATE/secret.conf"
    } > "$RUN/ndr.conf"
}

# --- The directory and the issuer (roles/directory) -------------------------

directory_secret() {
    echo "kem_seed=$(seed)"
    echo "voprf_seed=$(seed)"
    echo "vrf_seed=$(seed)"
    echo "issuer_seed=$(seed)"
    echo "cross_relay_seed=$(seed)"
    echo "signer_seeds=$(seed),$(seed),$(seed)"
}

directory_conf() {
    secret_once "$STATE/secret.conf" '^signer_seeds=[0-9a-f]{64},[0-9a-f]{64},[0-9a-f]{64}$' \
        directory_secret
    conf_dir
    {
        echo "listen=0.0.0.0:${UMBRA_LISTEN_PORT:-8443}"
        tls_lines
        echo "key_id=1"
        echo "store=$STATE/directory.db"
        echo "keyset_epoch=${UMBRA_DIRECTORY_KEYSET_EPOCH:-1}"
        cat "$STATE/secret.conf"
    } > "$RUN/directory.conf"
}

# --- The signer (roles/signer) ----------------------------------------------

# UMBRA_RELAYS lists each relay of the network: <name>,<role>,<class>, with
# a space between two relays.
relay_list() {
    need UMBRA_RELAYS
    local entry name role class
    for entry in $UMBRA_RELAYS; do
        IFS=, read -r name role class <<< "$entry"
        [[ "$name" =~ ^[a-z0-9-]+$ && "$class" =~ ^[0-3]$ ]] ||
            die "UMBRA_RELAYS: $entry is not <name>,<role>,<class>"
        case $role in
            entry) echo "$name ingress $class" ;;
            middle | exit) echo "$name $role $class" ;;
            *) die "UMBRA_RELAYS: the role of $name is entry, middle or exit" ;;
        esac
    done
}

# The playbook makes keys on a signer that holds none, and never after that.
# A signer with a key chain, a key set in any directory, or a published key
# set gets no new keys.
signer_keys() {
    if [ ! -e "$SIGNER_HOME/keychain" ] && [ ! -e "$OUT/keyset.bin" ] &&
        [ -z "$(find "$SIGNER_HOME" -maxdepth 2 -name keyset.bin -print -quit)" ]; then
        umbra-signer keygen "$SIGNER_KEYS"
        say "made the authority keys in $SIGNER_KEYS: back the directory up offline"
    fi
    [ -s "$SIGNER_KEYS/keyset.bin" ] ||
        die "$SIGNER_KEYS holds no key set, and this signer made its keys before. Check UMBRA_SIGNER_KEYS."
    # Each relay pins this file; the authority tool and the measurer read it.
    (umask 022 && cp "$SIGNER_KEYS/keyset.bin" "$OUT/keyset.bin.tmp" && mv "$OUT/keyset.bin.tmp" "$OUT/keyset.bin")
    # The authority tool reaches the network, thus it sees the seeds of the
    # authorities 0 and 1 alone, in a directory of their own.
    local index
    for index in 0 1; do
        install -m 0600 "$SIGNER_KEYS/authority-$index.seed" "$AUTHORITY_KEYS/authority-$index.seed"
    done
}

sign_conf() {
    need UMBRA_OPERATOR
    local name place class missing="" list
    list=$(relay_list) || return 1
    conf_dir
    {
        echo "keys=$SIGNER_KEYS"
        echo "out=$OUT"
        echo "keychain=$SIGNER_HOME/keychain"
        while read -r name place class; do
            [ -s "$DESCRIPTORS/$name.desc" ] || missing="$missing $name"
            echo "relay=$DESCRIPTORS/$name.desc,$UMBRA_OPERATOR,$class,$place"
        done <<< "$list"
        echo "report_queue=0,$AUTHORITY/report-queue.bin"
        echo "verdicts=$AUTHORITY/verdicts"
        echo "results=$MEASURER/results"
        mkdir -p "$SIGNER_HOME/state"
        echo "class_state=$SIGNER_HOME/state/class_state"
        local revoked
        for revoked in ${UMBRA_REVOKED_MEASURERS:-}; do
            echo "revoked=$revoked"
        done
        if [ -n "$missing" ]; then
            say "no descriptor in $DESCRIPTORS for:$missing"
            return 1
        fi
    } > "$RUN/sign.conf"
}

sign_once() {
    sign_conf || return 1
    # nginx reads the files that this run writes, thus the mask.
    (umask 022 && umbra-signer sign "$@" "$RUN/sign.conf")
}

measurer_cert() {
    (umask 022 && umbra-signer measurer-cert "$SIGNER_KEYS" "$MEASURER/keys/measurer.pub" \
        "$MEASURER/cert/measurer.cert" "${UMBRA_MEASURER_CERT_EPOCHS:-24}")
}

# One manifest each hour, at two minutes past it (a root lives three hours),
# and a measurer certificate when the measurer asks for one. A failed run
# tries again in 5 minutes.
signer_run() {
    local now hour minute last="" next_try=0
    signer_keys
    while true; do
        now=$(date +%s)
        hour=$((now / 3600))
        minute=$(((now % 3600) / 60))
        if [ "$hour" != "$last" ] && [ "$now" -ge "$next_try" ] &&
            { [ -z "$last" ] || [ "$minute" -ge 2 ]; }; then
            if sign_once; then
                last=$hour
            else
                alert "the signer signed no manifest; the network stops when the last one ends"
                next_try=$((now + 300))
            fi
        fi
        if [ -s "$MEASURER/request" ] &&
            { [ ! -s "$MEASURER/cert/measurer.cert" ] || [ "$MEASURER/request" -nt "$MEASURER/cert/measurer.cert" ]; }; then
            measurer_cert || alert "the signer issued no measurer certificate"
        fi
        nap 20
    done
}

# The HTTPS carrier of Part 3 §3.10: the manifest alone, with no log of who
# fetched it. Before the first rotation of the key set no key chain exists,
# and each request for it gets 404 (Part 10 REL-199).
manifest_run() {
    local port=${UMBRA_LISTEN_PORT:-443} six=""
    # A host with no IPv6 refuses an IPv6 listener.
    if [ -s /proc/net/if_inet6 ]; then
        six="listen [::]:$port ssl;"
    fi
    conf_dir
    mkdir -p /tmp/nginx
    port_check "$port"
    tls_lines > /dev/null
    cat > "$RUN/nginx.conf" <<NGINX
worker_processes 1;
pid /tmp/nginx/nginx.pid;
error_log stderr crit;
events { worker_connections 1024; }
http {
    client_body_temp_path /tmp/nginx/body;
    proxy_temp_path /tmp/nginx/proxy;
    fastcgi_temp_path /tmp/nginx/fastcgi;
    uwsgi_temp_path /tmp/nginx/uwsgi;
    scgi_temp_path /tmp/nginx/scgi;
    server_tokens off;
    access_log off;
    log_not_found off;
    server {
        listen $port ssl;
        $six
        ssl_certificate $TLS_DIR/cert.pem;
        ssl_certificate_key $TLS_DIR/key.pem;
        ssl_protocols TLSv1.3;
        root /var/www/umbra;
        location = /.well-known/umbra/manifest {
            default_type application/octet-stream;
            add_header Cache-Control "no-cache" always;
        }
        location = /.well-known/umbra/keychain {
            default_type application/octet-stream;
            add_header Cache-Control "no-cache" always;
        }
        location / {
            return 404;
        }
    }
}
NGINX
    supervise nginx -e stderr -c "$RUN/nginx.conf" -g 'daemon off;'
}

# --- The authority tool (roles/authority) -----------------------------------

authority_run() {
    wait_for "$SIGNER_KEYS/authority-1.seed" "the seeds that the signer gives this tool"
    wait_for "$OUT/manifest" "the first manifest of the signer"
    mkdir -p "$AUTHORITY/secrets"
    chmod 0700 "$AUTHORITY/secrets"
    conf_dir
    {
        echo "keys=$SIGNER_KEYS"
        echo "secrets=$AUTHORITY/secrets"
        echo "index=0"
        echo "verdicts=$AUTHORITY/verdicts"
        echo "manifest=$OUT/manifest"
        echo "keyset=$OUT/keyset.bin"
        echo "state=$AUTHORITY/report-queue.state"
        echo "queue=$AUTHORITY/report-queue.bin"
        # One operator holds each key, thus this tool is both aggregators of
        # Part 10 §10.8.
        echo "aggregators=0,1"
        trust_line ca
    } > "$RUN/authority.conf"
    supervise umbra-authority "$RUN/authority.conf"
}

# --- The measurer (roles/measurer) ------------------------------------------

measurer_conf() {
    local name place class list
    list=$(relay_list) || return 1
    if [ ! -s "$MEASURER/keys/measurer.seed" ]; then
        (umask 022 && umbra-measurer keygen "$MEASURER/keys")
    fi
    conf_dir
    {
        echo "key=$MEASURER/keys/measurer.seed"
        echo "cert=$MEASURER/cert/measurer.cert"
        echo "manifest=$OUT/manifest"
        echo "keyset=$OUT/keyset.bin"
        echo "results=$MEASURER/results"
        echo "capacity=${UMBRA_MEASURER_CAPACITY:-500}"
        echo "slot=30"
        echo "sockets=4"
        # A relay that failed the test of C0 is in no manifest. The measurer
        # tests it all the same, thus a later pass lists it again.
        while read -r name place class; do
            echo "unlisted=$DESCRIPTORS/$name.desc,$place"
        done <<< "$list"
        trust_line
    } > "$RUN/measurer.conf"
}

# Each run takes a new certificate first: the measurer asks, and the signer
# issues it under two authority keys with no network.
measure_once() {
    local waited=0
    measurer_conf
    (umask 022 && date +%s > "$MEASURER/request")
    until [ -s "$MEASURER/cert/measurer.cert" ] && [ "$MEASURER/cert/measurer.cert" -nt "$MEASURER/request" ]; do
        [ "$waited" -lt 600 ] || { alert "the signer gave the measurer no certificate"; return 1; }
        nap 5
        waited=$((waited + 5))
    done
    if ! (umask 022 && umbra-measurer run "$RUN/measurer.conf"); then
        alert "a relay gave the measurer no result; it keeps its class"
        return 1
    fi
}

# Part 10 REL-097: one run in each 7 days, at a random time in the 12 hours
# after Monday 02:20 UTC. A run that the container missed goes at its start.
next_measure() {
    local monday
    monday=$(date -u -d 'monday 02:20' +%s)
    [ "$monday" -gt "$(date +%s)" ] || monday=$((monday + 7 * 86400))
    echo $((monday + $(od -An -tu4 -N4 /dev/urandom | tr -d ' ') % 43200))
}

measurer_run() {
    measurer_conf
    [ -s "$MEASURER/next-run" ] || next_measure > "$MEASURER/next-run"
    while true; do
        if [ "$(date +%s)" -ge "$(cat "$MEASURER/next-run")" ]; then
            measure_once || true
            next_measure > "$MEASURER/next-run"
        fi
        nap 60
    done
}

# --- The directories (as root, before the services) -------------------------

# The user of each service. Each one owns its state alone, and the group
# umbra-tls reads the key of the certificate.
UID_TLS=10000
UID_RELAY=10001
UID_NDR=10002
UID_DIRECTORY=10003
UID_SIGNER=10004
UID_MEASURER=10005

init_dirs() {
    local root=${1:-/srv/umbra} dir
    [ "$(id -u)" = 0 ] || die "init runs as root"
    umask 022
    place() { mkdir -p "$root/$1" && chown "$2" "$root/$1" && chmod "$3" "$root/$1"; }
    place tls "0:$UID_TLS" 0750
    place letsencrypt 0:0 0700
    place network 0:0 0755
    place secrets 0:0 0755
    if [ -e "$root/secrets/fcm.json" ]; then
        chown "0:$UID_NDR" "$root/secrets/fcm.json"
        chmod 0640 "$root/secrets/fcm.json"
    fi
    # The state directory of each relay: relay1 and relay2 of compose.yaml,
    # or relays/<name> of the Helm chart.
    for dir in ${UMBRA_RELAY_DIRS:-relay1 relay2}; do
        place "$dir" "$UID_RELAY:$UID_RELAY" 0700
    done
    place ndr "$UID_NDR:$UID_NDR" 0700
    place directory "$UID_DIRECTORY:$UID_DIRECTORY" 0700
    place signer "$UID_SIGNER:$UID_SIGNER" 0700
    place www "$UID_SIGNER:$UID_SIGNER" 0755
    place descriptors 0:0 0755
    place authority "$UID_SIGNER:$UID_SIGNER" 0750
    place authority-keys "$UID_SIGNER:$UID_SIGNER" 0700
    place measurer "$UID_MEASURER:$UID_MEASURER" 0755
    place measurer/keys "$UID_MEASURER:$UID_MEASURER" 0755
    # The signer writes the certificate of each run here.
    place measurer/cert "$UID_SIGNER:$UID_SIGNER" 0755
    say "the directories under $root are in place"
}

service=${1:-}
shift || true
case "$service:${1:-}" in
    init:*) init_dirs "$@" ;;
    relay:) relay_run ;;
    relay:descriptor) relay_conf && relay_descriptor && cat "$STATE/relay.desc" ;;
    ndr:) ndr_conf && supervise umbra-ndr "$RUN/ndr.conf" ;;
    ndr:key-config) ndr_conf && umbra-ndr key-config "$RUN/ndr.conf" ;;
    directory:) directory_conf && supervise umbra-directory "$RUN/directory.conf" ;;
    directory:pins) directory_conf && umbra-directory pins "$RUN/directory.conf" ;;
    signer:) signer_run ;;
    signer:sign) shift && signer_keys && sign_once "$@" ;;
    manifest:) manifest_run ;;
    authority:) authority_run ;;
    measurer:) measurer_run ;;
    measurer:now) measure_once ;;
    *) die "unknown command: $service ${1:-}. See the head of $0." ;;
esac
