#!/bin/bash
# The entry of the UMBRA relay image. It makes the keys of the relay one
# time, writes its settings file from the environment, and starts it.
#
#   umbra-entry init     # as root: the directories and their owners
#   umbra-entry relay      # the relay
#   umbra-entry join       # the join request of the relay, as text
#   umbra-entry preflight  # the checks before the first start
#
# deploy/relay/relay.env.example names each variable. The keys never leave
# the state directory.
#
# A relay with no UMBRA_PUBLIC_HOST is in pin form (Part 10 REL-143): it
# makes its own link certificate in the state directory, and it needs no
# DNS name, no certbot, and no port 80. An entry relay has a host, because
# phones verify its certificate against that name.
#
# The intake of the network (Part 10 §10.6.4) tells a relay its address,
# its AS number, and the country of that AS, for each of the three that the
# environment does not set. The relay sends its join request to the intake
# by itself. The owner of the network still decides on it.
set -euo pipefail
umask 077

UMBRA_PUBLIC_HOST=${UMBRA_PUBLIC_HOST:-}

# Under Kubernetes this shell is process 1, which takes no default action
# on a signal.
trap 'exit 143' TERM INT

TLS_DIR=/etc/umbra/tls
STATE=/var/lib/umbra
RUN=/run/umbra
# The public values of the network and the key set of the release app.
NETWORK=/usr/local/share/umbra
UID_TLS=10000
UID_RELAY=10001

say() { echo "umbra-entry: $*" >&2; }
die() { say "$*"; exit 1; }

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

# Each value of the network that the environment does not set comes from
# the image.
network_values() {
    local line name
    while IFS= read -r line; do
        case $line in '' | '#'*) continue ;; esac
        name=${line%%=*}
        [ -n "${!name:-}" ] || export "$line"
    done < "$NETWORK/network.env"
}

# One request to the intake of the network, which the server of the signer
# carries. The answer holds `name=value` lines.
signer_ask() {
    local path=$1 host ip port
    shift
    IFS=, read -r host ip port <<< "$UMBRA_SIGNER"
    curl -sS --max-time 30 --proto =https --tlsv1.3 --resolve "$host:$port:$ip" \
        "$@" "https://$host:$port/.well-known/umbra/$path"
}

# The value of one line of an answer, when it has the form of the pattern.
# An answer is not trusted: a value of another form is no value.
value_of() {
    local name=$1 pattern=$2 text=$3 value
    value=$(sed -n "s/^$name=//p" <<< "$text" | head -n 1)
    [[ "$value" =~ ^$pattern$ ]] && echo "$value"
}

# The address, the AS number, and the country that the environment does not
# set come from the intake: it states the address that this machine shows
# to the network. The last answer stays in the state directory, thus a
# start with no answer still has its values.
learn_public() {
    UMBRA_PUBLIC_ADDRESS=${UMBRA_PUBLIC_ADDRESS:-}
    UMBRA_ASN=${UMBRA_ASN:-}
    UMBRA_COUNTRY=${UMBRA_COUNTRY:-}
    if [ -n "$UMBRA_PUBLIC_ADDRESS" ] && [ -n "$UMBRA_ASN" ] && [ -n "$UMBRA_COUNTRY" ]; then
        return 0
    fi

    local answer file="$STATE/whoami" address asn country
    if answer=$(signer_ask whoami -f 2>/dev/null) && grep -q '^address=' <<< "$answer"; then
        echo "$answer" > "$file"
    elif [ -s "$file" ]; then
        say "the network gives no answer: the address of the last start stays"
        answer=$(cat "$file")
    else
        die "the network does not tell this relay its address: set UMBRA_ADDRESS, UMBRA_ASN and UMBRA_COUNTRY, or try again later"
    fi

    address=$(value_of address '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$answer") || true
    asn=$(value_of asn '[0-9]{1,10}' "$answer") || true
    country=$(value_of country '[A-Z]{2}' "$answer") || true

    if [ -n "$UMBRA_PUBLIC_ADDRESS" ] && [ -n "$address" ] && [ "$UMBRA_PUBLIC_ADDRESS" != "$address" ]; then
        say "UMBRA_ADDRESS is $UMBRA_PUBLIC_ADDRESS, and the network sees this machine at $address"
    fi
    UMBRA_PUBLIC_ADDRESS=${UMBRA_PUBLIC_ADDRESS:-$address}
    UMBRA_ASN=${UMBRA_ASN:-$asn}
    UMBRA_COUNTRY=${UMBRA_COUNTRY:-$country}

    [ -n "$UMBRA_PUBLIC_ADDRESS" ] || die "the answer of the network holds no address: set UMBRA_ADDRESS"
    [ -n "$UMBRA_ASN" ] ||
        die "the network does not know the autonomous system of $UMBRA_PUBLIC_ADDRESS: set UMBRA_ASN (whois names it)"
    [ -n "$UMBRA_COUNTRY" ] ||
        die "the network does not know the country of $UMBRA_PUBLIC_ADDRESS: set UMBRA_COUNTRY"
    # The country is the one of the provider. A machine in another country
    # states its own in UMBRA_COUNTRY.
    say "this relay: address $UMBRA_PUBLIC_ADDRESS, AS$UMBRA_ASN, country $UMBRA_COUNTRY"
}

# Docker and Kubernetes give a user with no root no capability, thus a port
# below 1024 needs the setting of the host.
port_check() {
    local port=$1 first
    first=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)
    if [ "$port" -lt "$first" ]; then
        die "port $port needs net.ipv4.ip_unprivileged_port_start=$port or lower on the host (deploy/relay/README.md)"
    fi
}

# An exit relay reads each chunk two times into memory at its start. A lower
# limit passes while the store is small, and then stops the relay at each
# start when the store fills.
memory_check() {
    local capacity=${UMBRA_CHUNK_CAPACITY:-1073741824} limit need
    [ "$UMBRA_RELAY_ROLE" = exit ] || return 0
    # Bash reads a number with a leading zero as octal, and the relay reads
    # it as decimal.
    [[ "$capacity" =~ ^(0|[1-9][0-9]{0,14})$ ]] ||
        die "UMBRA_CHUNK_CAPACITY is a number of bytes, with no leading zero"

    # cgroup v2, then cgroup v1. A value that is not a number is no limit.
    limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null ||
        cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo max)
    [[ "$limit" =~ ^[0-9]+$ ]] || return 0

    need=$((2 * 10#$capacity + (300 << 20)))
    if [ "$limit" -lt "$need" ]; then
        die "an exit relay with UMBRA_CHUNK_CAPACITY=$capacity needs a memory limit of $((need >> 20)) MiB or more, and the limit is $((limit >> 20)) MiB: raise UMBRA_MEMORY_MAX, or memory.exit of the Helm chart"
    fi
}

# The relay reads its certificate at its start. Thus the entry stops it when
# certbot writes a new one, and the restart policy starts it again. A relay
# in pin form reads no file of certbot, and its link certificate stays.
stamp() {
    [ -n "$UMBRA_PUBLIC_HOST" ] || return 0
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
            say "the certificate is new: the relay starts again"
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" || true
            exit 0
        fi
    done

    wait "$pid"
}

# The keys take their name only once each line checks, thus a failed start
# leaves no half file.
make_keys() {
    local file="$STATE/secret.conf" tmp
    [ -s "$file" ] && return 0

    tmp=$(mktemp "$file.XXXXXX")
    umbra-relay keygen | grep -v '^#' > "$tmp"
    if ! grep -Eq '^identity_seed=[0-9a-f]{64}$' "$tmp" ||
        ! grep -Eq '^static_secret=[0-9a-f]{64}$' "$tmp"; then
        rm -f "$tmp"
        die "the new keys of $file do not check"
    fi

    mv "$tmp" "$file"
    say "made the keys of the relay in $file"
}

relay_conf() {
    network_values
    need UMBRA_SIGNER
    learn_public
    need UMBRA_RELAY_NAME UMBRA_RELAY_ROLE UMBRA_RELAY_CLASS \
        UMBRA_PUBLIC_ADDRESS UMBRA_PUBLIC_PORT UMBRA_OPERATOR UMBRA_COUNTRY UMBRA_ASN \
        UMBRA_FAMILY UMBRA_SIGNER
    local name=$UMBRA_RELAY_NAME role=$UMBRA_RELAY_ROLE class=$UMBRA_RELAY_CLASS roles
    local host=$UMBRA_PUBLIC_HOST

    [[ "$name" =~ ^[a-z0-9-]+$ ]] || die "UMBRA_RELAY_NAME takes a-z, 0-9 and -"
    [[ "$class" =~ ^[0-3]$ ]] || die "UMBRA_RELAY_CLASS is 0, 1, 2 or 3"
    [[ "$UMBRA_FAMILY" =~ ^[0-9a-f]{64}$ ]] || die "UMBRA_FAMILY is 64 hex characters"
    [[ "$UMBRA_PUBLIC_ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "UMBRA_ADDRESS is an IPv4 address"
    [[ "$UMBRA_COUNTRY" =~ ^[A-Z]{2}$ ]] || die "UMBRA_COUNTRY is two capital letters, as DE"
    [[ "$UMBRA_ASN" =~ ^[0-9]+$ ]] || die "UMBRA_ASN is a number, without AS"
    # These values go into the lines of relay.conf and of the join request.
    # A space, a comma, or a line end in one of them would make a second
    # value there. scripts/relay-admit.py has the same patterns.
    [[ "$UMBRA_OPERATOR" =~ ^[A-Za-z0-9._-]+$ ]] ||
        die "UMBRA_OPERATOR takes letters, digits, and . _ -"
    [[ "$host" =~ ^[A-Za-z0-9.-]*$ ]] || die "UMBRA_HOST is a DNS name, or it is empty"
    [[ "$UMBRA_PUBLIC_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$UMBRA_PUBLIC_PORT" -ge 1 ] &&
        [ "$UMBRA_PUBLIC_PORT" -le 65535 ] || die "UMBRA_PORT is a port number"

    case $role in
        entry)
            roles=chain,ingress
            # Phones reach an entry relay, and a network that lets out
            # port 443 alone still reaches it.
            [ "$class" -ge 1 ] || die "an entry relay takes class 1 or more"
            [ "$UMBRA_PUBLIC_PORT" = 443 ] || die "an entry relay takes port 443"
            # Part 10 REL-226: a phone verifies the certificate of an entry
            # relay against its name.
            [ -n "$host" ] || die "an entry relay takes a DNS name: set UMBRA_HOST"
            ;;
        middle) roles=chain ;;
        exit) roles=queue,chain,attachment ;;
        *) die "UMBRA_RELAY_ROLE is entry, middle or exit" ;;
    esac

    make_keys
    mkdir -p "$RUN"

    # The lines that the descriptor states. A change of one of them takes a
    # new descriptor.
    {
        echo "public=$host,$UMBRA_PUBLIC_ADDRESS,$UMBRA_PUBLIC_PORT"
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

    # A relay with a host waits for the files of certbot. A relay in pin
    # form waits for nothing: the relay makes its link certificate itself.
    if [ -n "$host" ]; then
        wait_for "$TLS_DIR/cert.pem" "the certificate of $host"
        wait_for "$TLS_DIR/key.pem" "the key of the certificate"
    fi

    # The settings file stays in memory, thus the keys in it reach no disk
    # outside the state directory.
    {
        echo "listen=0.0.0.0:$UMBRA_PUBLIC_PORT"
        if [ -n "$host" ]; then
            echo "cert=$TLS_DIR/cert.pem"
            echo "key=$TLS_DIR/key.pem"
        else
            echo "link=$STATE/link"
        fi
        echo "store=$STATE/relay.db"
        cat "$RUN/public.conf"
        echo "manifest=$STATE/manifest.bin"
        # A rotation of the key set (Part 10 REL-200) writes this file.
        echo "keyset=$STATE/keyset.bin"
        echo "manifest_from=$UMBRA_SIGNER"
        echo "ohttp_gateway=$UMBRA_OHTTP_GATEWAY"
        echo "directory_gateway=$UMBRA_DIRECTORY_GATEWAY"
        echo "ndr_route=$UMBRA_NDR_ROUTE"
        echo "ndr_key_config=$UMBRA_NDR_KEY_CONFIG"
        echo "directory_route=$UMBRA_DIRECTORY_ROUTE"
        echo "directory_pins=$UMBRA_DIRECTORY_PINS"
        cat "$STATE/secret.conf"
    } > "$RUN/relay.conf"
}

# What the descriptor states: the public lines, the keys, and the link
# certificate of a relay in pin form, whose pin the descriptor carries.
descriptor_sum() {
    {
        cat "$RUN/public.conf" "$STATE/secret.conf"
        if [ -z "$UMBRA_PUBLIC_HOST" ] && [ -s "$STATE/link.cert" ]; then
            cat "$STATE/link.cert"
        fi
    } | sha256sum | cut -d' ' -f1
}

# Each signature differs, and a manifest with another descriptor has another
# root. An hour takes one root (Part 10 REL-160). Thus the relay signs only
# when it has no descriptor, or when a value that the descriptor states
# changed.
relay_descriptor() {
    if [ -s "$STATE/relay.desc" ] && [ "$(cat "$STATE/relay.desc.sum" 2>/dev/null)" = "$(descriptor_sum)" ]; then
        return 0
    fi

    # A relay in pin form makes its link certificate here, at its first
    # descriptor. The sum thus comes after the signature.
    umbra-relay sign-descriptor "$RUN/relay.conf" "$STATE/relay.desc.part"
    mv "$STATE/relay.desc.part" "$STATE/relay.desc"
    descriptor_sum > "$STATE/relay.desc.sum"
    chmod 0644 "$STATE/relay.desc"
    say "signed a new descriptor"
}

fetch_manifest() {
    local into=$1 host ip port
    IFS=, read -r host ip port <<< "$UMBRA_SIGNER"
    curl -fsS --max-time 30 --proto =https --tlsv1.3 --resolve "$host:$port:$ip" \
        -o "$into.tmp" "https://$host:$port/.well-known/umbra/manifest" &&
        mv "$into.tmp" "$into"
}

relay_run() {
    relay_conf
    memory_check
    relay_descriptor
    relay_announce

    # The key set is the root of trust of the relay, thus it comes from the
    # image and not from the network. A rotation later writes a newer one.
    if [ ! -s "$STATE/keyset.bin" ]; then
        install -m 0644 "$NETWORK/keyset.bin" "$STATE/keyset.bin"
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

    port_check "$UMBRA_PUBLIC_PORT"
    local started status=0
    started=$(date +%s)
    supervise umbra-relay "$RUN/relay.conf" || status=$?
    # The trap of supervise names its process, which is gone now.
    trap 'exit 143' TERM INT

    # Until the manifest lists it, a relay stops at its start. A quick
    # restart would ask the signer for the manifest each few seconds.
    # supervise sees the stop up to 60 s late, thus 90 s.
    if [ "$status" -ne 0 ] && [ $(($(date +%s) - started)) -lt 90 ]; then
        local wait=${UMBRA_ADMISSION_WAIT:-600}
        say "the relay stopped at its start; a relay that waits for its admission stops so. Next try in $wait s"
        relay_announce again
        nap "$wait"
    fi
    return "$status"
}

relay_id_of() {
    local relay_id
    relay_id=$(umbra-relay descriptor "$RUN/relay.conf" | cut -d' ' -f6)
    [[ "$relay_id" =~ ^[0-9a-f]{64}$ ]] || die "the relay_id does not read from the settings"
    echo "$relay_id"
}

# The request that the network gets: the signed descriptor and the facts of
# the dossier (Part 10 §10.6). Each value is public.
relay_join() {
    local relay_id
    relay_id=$(relay_id_of)

    echo "-----BEGIN UMBRA RELAY REQUEST-----"
    echo "name=$UMBRA_RELAY_NAME"
    echo "role=$UMBRA_RELAY_ROLE"
    echo "class=$UMBRA_RELAY_CLASS"
    echo "public=$UMBRA_PUBLIC_HOST,$UMBRA_PUBLIC_ADDRESS,$UMBRA_PUBLIC_PORT"
    echo "operator=$UMBRA_OPERATOR"
    echo "country=$UMBRA_COUNTRY"
    echo "asn=$UMBRA_ASN"
    echo "family=$UMBRA_FAMILY"
    echo "relay_id=$relay_id"
    echo "descriptor="
    base64 -w 76 "$STATE/relay.desc"
    echo "-----END UMBRA RELAY REQUEST-----"
}

# Sends the join request to the intake, one time for each descriptor, and
# says what the intake holds. The owner of the network decides on the
# request (Part 10 REL-012). With `again`, a request that the intake holds
# no more goes there again.
relay_announce() {
    local again=${1:-} sum relay_id answer state
    sum=$(cat "$STATE/relay.desc.sum")
    relay_id=$(relay_id_of)

    if [ "$(cat "$STATE/join.sum" 2>/dev/null)" = "$sum" ]; then
        answer=$(signer_ask "join/$relay_id" 2>/dev/null) || true
        state=$(value_of state '[a-z]+' "$answer") || true
        case $state in
            received)
                say "the network holds the join request of this relay, and its owner decides on it"
                return 0
                ;;
            refused)
                say "the owner of the network refused this relay"
                return 0
                ;;
            unknown) [ "$again" = again ] || return 0 ;;
            *)
                say "the network gives no answer about the join request"
                return 0
                ;;
        esac
    fi

    answer=$(relay_join | signer_ask join --data-binary @- -H 'Content-Type: text/plain' 2>/dev/null) || true
    state=$(value_of state '[a-z]+' "$answer") || true
    if [ "$state" = received ]; then
        echo "$sum" > "$STATE/join.sum"
        say "sent the join request of this relay to the network; its owner decides on it"
        return 0
    fi

    say "the network did not take the join request: $(value_of refused '[ -~]+' "$answer" || echo "no answer")"
    say "the join command prints the request, which you can give to the network by hand"
}

# The checks that an operator runs before the first start. Stop the relay
# before this command: the last check needs the port of the relay.
relay_preflight() {
    network_values
    need UMBRA_SIGNER
    UMBRA_RELAY_ROLE=${UMBRA_RELAY_ROLE:-middle}
    local port=${UMBRA_PUBLIC_PORT:-9443} failed=0 answer address remote there here skew pid
    pass() { say "ok: $*"; }
    fail() {
        say "FAIL: $*"
        failed=1
    }

    if answer=$(signer_ask whoami -f 2>/dev/null) && address=$(value_of address '[0-9.]+' "$answer"); then
        pass "the network sees this machine at $address"
        pass "its autonomous system is AS$(value_of asn '[0-9]+' "$answer" || echo " unknown: set UMBRA_ASN")"
        pass "the country of that system is $(value_of country '[A-Z]{2}' "$answer" || echo "unknown: set UMBRA_COUNTRY")"
    else
        fail "the network gives no answer: check the DNS of this machine, and that it reaches port 443 of other machines"
    fi

    # A relay with a wrong clock takes no manifest.
    remote=$(signer_ask manifest -f -I 2>/dev/null | tr -d '\r' | sed -n 's/^[Dd]ate: //p') || true
    if there=$(date -d "$remote" +%s 2>/dev/null) && [ -n "$remote" ]; then
        here=$(date +%s)
        skew=$((here > there ? here - there : there - here))
        if [ "$skew" -le 30 ]; then
            pass "the clock is $skew s from the clock of the network"
        else
            fail "the clock is $skew s from the clock of the network: start a time service, as chrony"
        fi
    else
        fail "the clock of the network does not read"
    fi

    if (port_check "$port") 2>/dev/null; then
        pass "this user can open port $port"
    else
        fail "port $port needs net.ipv4.ip_unprivileged_port_start=$port or lower on the host"
    fi

    if (memory_check) 2>/dev/null; then
        pass "the memory limit is enough for the role $UMBRA_RELAY_ROLE"
    else
        fail "the memory limit is too low for an exit relay: raise UMBRA_MEMORY_MAX"
    fi

    # The intake connects to the port from outside while this relay holds it.
    umbra-relay hold-port "$port" 45 &
    pid=$!
    nap 2
    if ! kill -0 "$pid" 2>/dev/null; then
        fail "port $port is not free: stop the relay before this check"
    else
        answer=$(signer_ask "reach/$port" 2>/dev/null) || true
        case $(value_of reach '[a-z]+' "$answer" || true) in
            open) pass "port $port reaches this machine from outside" ;;
            closed) fail "port $port does not reach this machine from outside: forward it on the router, and open it in the firewall. An address behind carrier-grade NAT does not work" ;;
            *) fail "the network gave no result for port $port" ;;
        esac
        kill "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true

    if [ "$failed" -eq 0 ]; then
        say "each check passed: start the relay"
    else
        say "correct each FAIL line, and run the preflight again"
    fi
    return "$failed"
}

# The group of TLS_DIR reads the key of the certificate, and the relay user
# is in that group.
init_dirs() {
    local root=${1:-/srv/umbra}
    [ "$(id -u)" = 0 ] || die "init runs as root"
    umask 022

    place() { mkdir -p "$root/$1" && chown "$2" "$root/$1" && chmod "$3" "$root/$1"; }
    place tls "0:$UID_TLS" 0750
    place letsencrypt 0:0 0700
    place relay "$UID_RELAY:$UID_RELAY" 0700

    say "the directories of the relay under $root are in place"
}

case "${1:-}" in
    init) shift && init_dirs "$@" ;;
    relay) relay_run ;;
    join) relay_conf && relay_descriptor && relay_join ;;
    preflight) relay_preflight ;;
    *) die "unknown command: ${1:-}. See the head of $0." ;;
esac
