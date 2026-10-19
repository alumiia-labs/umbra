#!/bin/sh
# The certificate of this server, from Let's Encrypt, in the certbot image.
# Certbot answers the challenge on port 80 itself, and it renews the
# certificate twice a day when it is due. Each new certificate goes to the
# TLS directory, and each service starts again with it (umbra-entry). Let's
# Encrypt sends no expiry mail, thus the account holds no address.
set -eu

: "${UMBRA_FQDN:?set UMBRA_FQDN to the name of this server}"
tls=/etc/umbra/tls

# Certbot calls this after each new certificate. The group 10000 (umbra-tls)
# holds each service user. The files take their names last, thus a service
# never reads half a file.
if [ "${1:-}" = install ]; then
    lineage="${RENEWED_LINEAGE:-/etc/letsencrypt/live/$UMBRA_FQDN}"
    install -o 0 -g 10000 -m 0644 "$lineage/fullchain.pem" "$tls/cert.pem.tmp"
    install -o 0 -g 10000 -m 0640 "$lineage/privkey.pem" "$tls/key.pem.tmp"
    mv "$tls/key.pem.tmp" "$tls/key.pem"
    mv "$tls/cert.pem.tmp" "$tls/cert.pem"
    echo "the certificate of $UMBRA_FQDN is in $tls"
    exit 0
fi

hook="sh $0 install"
if [ ! -s "/etc/letsencrypt/live/$UMBRA_FQDN/fullchain.pem" ]; then
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$UMBRA_FQDN" --deploy-hook "$hook"
elif [ ! -s "$tls/cert.pem" ]; then
    RENEWED_LINEAGE="/etc/letsencrypt/live/$UMBRA_FQDN" sh "$0" install
fi
while true; do
    sleep 43200
    certbot renew --non-interactive --deploy-hook "$hook" || echo "ALERT: the renewal failed"
done
