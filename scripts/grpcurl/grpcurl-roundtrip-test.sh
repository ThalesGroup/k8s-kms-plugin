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

print_jwe_header() {
  local jwe b64
  jwe=$(printf '%s' "$1" | base64 -d)
  b64=$(printf '%s' "$jwe" | cut -d. -f1 | tr -- '-_' '+/')
  case $((${#b64} % 4)) in
    2) b64="${b64}==" ;;
    3) b64="${b64}=" ;;
  esac
  echo "🔑 JWE Header:"
  echo '```json'
  printf '%s' "$b64" | base64 -d | jq
  echo '```'
}

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
  echo "Set VERBOSE=true to dump full JSON requests and responses."
  exit 1
fi

echo "# 🔐 KMS v2 Round-Trip Test"
echo ""
[[ "$VERBOSE" == true ]] && echo "🔍 Verbose: enabled" || echo "🔇 Verbose: disabled — set \`VERBOSE=true\` to see full JSON requests and responses"
echo ""

# ---- Base64-encode plaintext ----
PLAINTEXT_BASE64=$(echo -n "$PLAINTEXT" | base64)
echo "🔐 Input plaintext: \`$PLAINTEXT\`"
echo "🔐 Base64 encoded: \`$PLAINTEXT_BASE64\`"

echo ""
echo "---"
echo ""
echo "## 1️⃣ Status"
echo ""

# ---- Get key_id from Status ----
STATUS_REQUEST='{}'
[[ "$VERBOSE" == true ]] && { echo "📤 StatusRequest:"; echo '```json'; echo "$STATUS_REQUEST" | jq; echo '```'; echo ""; }

STATUS_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$STATUS_REQUEST" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Status)

[[ "$VERBOSE" == true ]] && { echo "📥 StatusResponse:"; echo '```json'; echo "$STATUS_RESPONSE" | jq; echo '```'; echo ""; }

KEY_ID=$(echo "$STATUS_RESPONSE" | jq -r .keyId)
echo "🧾 key_id: \`$KEY_ID\`"

echo ""
echo "---"
echo ""
echo "## 2️⃣ Encrypt"
echo ""

# ---- Encrypt ----
ENCRYPT_REQUEST="{\"plaintext\": \"$PLAINTEXT_BASE64\", \"uid\": \"test-enc-1\"}"
[[ "$VERBOSE" == true ]] && { echo "📤 EncryptRequest:"; echo '```json'; echo "$ENCRYPT_REQUEST" | jq; echo '```'; echo ""; }

ENCRYPT_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$ENCRYPT_REQUEST" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Encrypt)

[[ "$VERBOSE" == true ]] && { echo "📥 EncryptResponse:"; echo '```json'; echo "$ENCRYPT_RESPONSE" | jq; echo '```'; echo ""; }

CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | jq -r .ciphertext)
[[ "$VERBOSE" == true ]] && { echo "🗄️ Ciphertext JWE (base64):"; echo '```'; echo "$CIPHERTEXT"; echo '```'; echo ""; }
print_jwe_header "$CIPHERTEXT"
echo ""

if [[ "$VERBOSE" == true ]]; then
  ENCRYPT_RESPONSE_B64=$(echo "$ENCRYPT_RESPONSE" | jq -c | base64 -w 0)
  echo "> ⬇️ Run key rotation test with the old KEK data from this run:"
  echo '```bash'
  printf 'VERBOSE=true ./grpcurl-roundtrip-key-rotation.sh \\\n'
  printf '  '"'"'<plaintext for ACTIVE KEK>'"'"' \\\n'
  printf '  '"'"'%s'"'"' \\\n' "$PLAINTEXT"
  printf '  '"'"'%s'"'"' \\\n' "$ENCRYPT_RESPONSE_B64"
  printf '  '"'"'%s'"'"'\n' "$SOCKET"
  echo '```'
fi

echo ""
echo "---"
echo ""
echo "## 3️⃣ Decrypt"
echo ""

# ---- Decrypt ----
DECRYPT_REQUEST="{\"ciphertext\": \"$CIPHERTEXT\", \"uid\": \"test-dec-1\", \"key_id\": \"$KEY_ID\"}"
[[ "$VERBOSE" == true ]] && { echo "📤 DecryptRequest:"; echo '```json'; echo "$DECRYPT_REQUEST" | jq; echo '```'; echo ""; }

DECRYPT_RESPONSE=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$DECRYPT_REQUEST" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Decrypt)

[[ "$VERBOSE" == true ]] && { echo "📥 DecryptResponse:"; echo '```json'; echo "$DECRYPT_RESPONSE" | jq; echo '```'; echo ""; }

DECRYPTED_BASE64=$(echo "$DECRYPT_RESPONSE" | jq -r .plaintext)
DECRYPTED_TEXT=$(echo "$DECRYPTED_BASE64" | base64 -d)
echo "🔓 Decrypted text: \`$DECRYPTED_TEXT\`"

echo ""
echo "---"
echo ""
echo "## 4️⃣ Summary"
echo ""

# ---- Compare ----
if [[ "$DECRYPTED_TEXT" == "$PLAINTEXT" ]]; then
  echo "✅ Round-trip encryption/decryption successful!"
else
  echo "❌ Decryption mismatch! Expected \`$PLAINTEXT\` but got \`$DECRYPTED_TEXT\`"
  exit 1
fi
