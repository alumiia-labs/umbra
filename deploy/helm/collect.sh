#!/usr/bin/env bash
# Collects the public values of a network that the Helm chart runs: the key
# of the notification server, the pins of the directory, the descriptor of
# each relay, the key set and the manifest of the signer, and the network
# file of the release app. It writes them to deploy/helm/build/, with a
# values file for the next `helm upgrade`. Each value is public.
#
#   bash deploy/helm/collect.sh [<namespace>]
#
# scripts/release-network.sh deploy/helm/build then gives the release app
# its network.
set -euo pipefail

# Git Bash on Windows turns each /path argument into a Windows path.
export MSYS_NO_PATHCONV=1

namespace="${1:-umbra}"
out="$(cd "$(dirname "$0")" && pwd)/build"
mkdir -p "$out/descriptors"

k() { kubectl -n "$namespace" "$@"; }

k exec deploy/ndr -c ndr -- umbra-entry ndr key-config | tr -d '\r\n' > "$out/ndr-key-config.hex"
k exec deploy/directory -c directory -- umbra-entry directory pins | tr -d '\r\n' > "$out/directory-pins.hex"

# Each relay signed its descriptor at its start.
relays=$(k get deploy -l app.kubernetes.io/component=relay \
    -o jsonpath='{range .items[*]}{.metadata.labels.umbra\.app/relay}{"\n"}{end}')
for relay in $relays; do
    k exec "deploy/relay-$relay" -c relay -- cat /var/lib/umbra/relay.desc > "$out/descriptors/$relay.desc"
done

# The signer has no key set before its first start, and no manifest before
# it holds each descriptor.
www=/var/www/umbra/.well-known/umbra
k exec deploy/signer -c signer -- cat "$www/keyset.bin" > "$out/keyset.bin"
k exec deploy/signer -c signer -- cat "$www/manifest" > "$out/manifest" 2>/dev/null || rm -f "$out/manifest"

k get configmap -l app.kubernetes.io/name=umbra \
    -o jsonpath='{range .items[*]}{.data.network\.properties}{end}' > "$out/network.properties"


{
    echo "# Written by deploy/helm/collect.sh. Public values alone."
    echo "network:"
    echo "  keyset: $(base64 -w0 < "$out/keyset.bin")"
    echo "  ndrKeyConfig: $(cat "$out/ndr-key-config.hex")"
    echo "  directoryPins: $(cat "$out/directory-pins.hex")"
    echo "  descriptors:"
    for relay in $relays; do
        echo "    $relay: $(base64 -w0 < "$out/descriptors/$relay.desc")"
    done
} > "$out/network-values.yaml"

echo "wrote $out"
