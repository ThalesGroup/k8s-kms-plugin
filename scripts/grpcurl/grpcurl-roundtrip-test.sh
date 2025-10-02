#!/usr/bin/env bash
set -euo pipefail

# ---- Check for required tools ----
if ! command -v grpcurl >/dev/null 2>&1; then
  echo "❌ Error: grpcurl is not installed. Please install grpcurl and retry."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "❌ Error: jq is not installed. Please install jq and retry."
  exit 1
fi

if ! command -v base64 >/dev/null 2>&1; then
  echo "❌ Error: base64 is not installed. Please install base64 and retry."
  exit 1
fi

API_PROTO_URL="https://raw.githubusercontent.com/kubernetes/kms/refs/tags/v0.34.1/apis/v2/api.proto"
if [[ ! -f api.proto ]]; then
  echo "api.proto file not found. Downloading protobufer API file from ${API_PROTO_URL}..."
  curl -sSL -o api.proto "${API_PROTO_URL}"
else
  echo "Using existing api.proto. If you want to update it, please remove this file."
fi

# ---- Parse user input ----
PLAINTEXT="${1:-}"
SOCKET="${2:-}"
VERBOSE="${VERBOSE:-false}"

if [[ -z "$PLAINTEXT" || -z "$SOCKET" ]]; then
  echo "Usage: $0 <plaintext> <unix-socket-path>"
  echo "Example: $0 'hello world' /run/user/1000/k8s-kms-plugin.sock"
  echo "         VERBOSE=true $0 'hello world' /run/user/1000/k8s-kms-plugin.sock"
  echo ""
  echo "This script performs a KMSv2 StatusRequest to get a key_id."
  echo "Then does an EncryptRequest using the user input plaintext and the key_id."
  echo "Then does a DecryptRequest and verifies the decrypted ciphertext matches the user provided plaintext."
  echo ""
  echo "Set VERBOSE=true to dump full JSON responses."
  exit 1
fi

# ---- Base64-encode plaintext ----
PLAINTEXT_BASE64=$(echo -n "$PLAINTEXT" | base64)
echo "🔐 Input plaintext: $PLAINTEXT"
echo "🔐 Base64 encoded: $PLAINTEXT_BASE64"
echo ""

echo "1️⃣ ℹ️ Status Request & Response"
# ---- Get key_id from Status ----
STATUS_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d '{}' \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Status)

[[ "$VERBOSE" == true ]] && echo -e "📦 Full StatusResponse JSON:" && echo "$STATUS_RESPONSE" | jq

echo ""
KEY_ID=$(echo "$STATUS_RESPONSE" | jq -r .keyId)
echo "🧾 key_id from Status: $KEY_ID"
echo ""

# ---- Encrypt ----
echo "2️⃣ ℹ️ Encrypt Request & Response"

ENCRYPT_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "{\"plaintext\": \"$PLAINTEXT_BASE64\", \"uid\": \"test-enc-1\"}" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Encrypt)

[[ "$VERBOSE" == true ]] && echo -e "📦 Full EncryptResponse JSON:" && echo "$ENCRYPT_RESPONSE" | jq

echo ""
CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | jq -r .ciphertext)
echo "🗄️  Ciphertext JWE only (base64): $CIPHERTEXT"

echo ""
echo "⬇️ Full EncryptResponse JSON base64 encoded: use this as <base64 EncryptResponse old kek> in the grpcurl-roundtrip-key-rotation.sh script:"
echo "$ENCRYPT_RESPONSE" | jq -c | base64 -w 0
echo ""

echo ""
# ---- Decrypt ----
echo "3️⃣ ℹ️ Decrypt Request & Response"

DECRYPT_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "{\"ciphertext\": \"$CIPHERTEXT\", \"uid\": \"test-dec-1\", \"key_id\": \"$KEY_ID\"}" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Decrypt)

[[ "$VERBOSE" == true ]] && echo -e "📦 Full DecryptResponse JSON:" && echo "$DECRYPT_RESPONSE" | jq

DECRYPTED_BASE64=$(echo "$DECRYPT_RESPONSE" | jq -r .plaintext)
DECRYPTED_TEXT=$(echo "$DECRYPTED_BASE64" | base64 -d)

echo ""
echo "🔓 Decrypted text: $DECRYPTED_TEXT"
echo ""

# ---- Compare ----
echo "4️⃣ ℹ️ Summary"
if [[ "$DECRYPTED_TEXT" == "$PLAINTEXT" ]]; then
  echo "✅ Round-trip encryption/decryption successful!"
else
  echo "❌ Decryption mismatch! Expected '$PLAINTEXT' but got '$DECRYPTED_TEXT'"
  exit 1
fi
