#!/bin/bash
set -euo pipefail

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

### === Configurable === ###
SERVER_CN="kms-server.local"
SERVER_IP="127.0.0.1"
CLIENT_CN="kms-client"
DAYS_VALID=365
###########################

echo "🔧 Generating root CA..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days $DAYS_VALID \
  -out "$CERT_DIR/ca.crt" -subj "/CN=KMS Root CA"

### === Server Certificate === ###
echo "🔧 Generating server TLS certificate..."

openssl genrsa -out "$CERT_DIR/tls.key" 4096

cat > "$CERT_DIR/server.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${SERVER_CN}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVER_CN}
IP.1 = ${SERVER_IP}
EOF

openssl req -new -key "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.csr" -config "$CERT_DIR/server.cnf"

openssl x509 -req -in "$CERT_DIR/tls.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/tls.crt" -days $DAYS_VALID -sha256 \
  -extensions v3_req -extfile "$CERT_DIR/server.cnf"

### === Client Certificate (mTLS) === ###
echo "🔧 Generating client TLS certificate for mTLS..."

openssl genrsa -out "$CERT_DIR/client.key" 4096

cat > "$CERT_DIR/client.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${CLIENT_CN}

[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" -config "$CERT_DIR/client.cnf"

openssl x509 -req -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/client.crt" -days $DAYS_VALID -sha256 \
  -extensions v3_req -extfile "$CERT_DIR/client.cnf"

echo "✅ All certificates generated in $CERT_DIR:"
ls -1 "$CERT_DIR"
