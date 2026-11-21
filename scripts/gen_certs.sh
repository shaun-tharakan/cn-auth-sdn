#!/usr/bin/env bash
# Generate a local lab CA and TLS server certificate for the auth server.
set -euo pipefail
cd "$(dirname "$0")/.."

CERT_DIR="${1:-certs}"
FORCE="${2:-}"
if [ "${1:-}" = "--force" ]; then
  CERT_DIR="certs"
  FORCE="--force"
fi

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ] && [ -f "$CERT_DIR/ca.crt" ] && [ "$FORCE" != "--force" ]; then
  echo "TLS certificates already exist in $CERT_DIR/ (pass --force to regenerate)"
  exit 0
fi

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

TMP_CNF="$(mktemp)"
trap 'rm -f "$TMP_CNF" "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"' EXIT

cat > "$TMP_CNF" <<'EOCNF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req

[dn]
CN = cn-auth-sdn

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign

[v3_req]
subjectAltName   = @alt_names
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
IP.2  = 10.10.0.254
EOCNF

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj "/CN=cn-auth-sdn-ca" -extensions v3_ca -config "$TMP_CNF" 2>/dev/null

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -config "$TMP_CNF" 2>/dev/null

openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 365 \
  -extensions v3_req -extfile "$TMP_CNF" 2>/dev/null

chmod 600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
echo "Generated TLS certificates in $CERT_DIR/ (ca.crt, server.crt, server.key)"
