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
PLAINTEXT_ACTIVE_KEY_ID="${1:-hello world ACTIVE KEK}"
PLAINTEXT_OLD_KEY_ID="${2:-hello world}"
ENCRYPT_RESPONSE_OLD_KEY_ID="${3:-}" # retrive this from grpcurl-roundtrip-test.sh
SOCKET="${4:-}"
VERBOSE="${VERBOSE:-false}"

if [[ -z "$PLAINTEXT_ACTIVE_KEY_ID" || -z "$SOCKET" ]]; then
  echo "Usage: $0 <plaintext active kek> <plaintext old kek> <base64 EncryptResponse old kek> <unix-socket-path> <old-p11-key-id>"
  echo "Example: $0 'hello world ACTIVE KEK' 'hello world old kek' <base64 EncryptResponse old kek> /run/user/1000/k8s-kms-plugin.sock"
  echo "         VERBOSE=true $0 'hello world ACTIVE KEK' 'hello world old kek' <base64 EncryptResponse old kek> /run/user/1000/k8s-kms-plugin.sock"
  echo ""
  echo "You need 2 different KEK keys in your TPM or HSM with different labels and IDs."
  echo "One key will be used as the ACTIVE KEK and the other will be used as the OLD KEK being rotated."
  echo ""
  echo "Before running 'k8s-kms-plugin serve rotation' against the grpcurl-roundtrip-key-rotation.sh script, run"
  echo "'k8s-kms-plugin serve' using the OLD KEK against grpcurl-roundtrip-test.sh and save the content of an EncryptResponse."
  echo ""
  echo "This script performs a KMSv2 StatusRequest to get a key_id of the ACTIVE KEK."
  echo "Then it does an EncryptRequest using the user input plaintext and the key_id of the ACTIVE KEK."
  echo "Then it does a DecryptRequest with the ID of the ACTIVE KEK and verifies the decrypted ciphertext matches the user provided plaintext."
  echo ""
  echo "Then it does a DecryptRequest with the ID of the OLD KEK and shows the decrypted ciphertext."
  echo ""
  echo "Set VERBOSE=true to dump full JSON requests and responses."
  exit 1
fi

echo "# 🔄 KMS v2 Key Rotation Round-Trip Test"
echo ""
[[ "$VERBOSE" == true ]] && echo "🔍 Verbose: enabled" || echo "🔇 Verbose: disabled — set \`VERBOSE=true\` to see full JSON requests and responses"

echo ""
echo "---"
echo ""
echo "## ▶️ Active KEK — Status, Encrypt & Decrypt"
echo ""

# ---- Base64-encode plaintext ----
PLAINTEXT_BASE64_ACTIVE=$(echo -n "$PLAINTEXT_ACTIVE_KEY_ID" | base64)
echo "🔐 Input plaintext: \`$PLAINTEXT_ACTIVE_KEY_ID\`"
echo "🔐 Base64 encoded: \`$PLAINTEXT_BASE64_ACTIVE\`"

echo ""
echo "### 1️⃣ Status"
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
echo "🧾 key_id (ACTIVE KEK): \`$KEY_ID\`"

echo ""
echo "### 2️⃣ Encrypt"
echo ""

# ---- Encrypt ----
ENCRYPT_REQUEST="{\"plaintext\": \"$PLAINTEXT_BASE64_ACTIVE\", \"uid\": \"test-enc-1\"}"
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
[[ "$VERBOSE" == true ]] && { echo "🗄️ Ciphertext (base64):"; echo '```'; echo "$CIPHERTEXT"; echo '```'; echo ""; }
print_jwe_header "$CIPHERTEXT"
echo ""

echo "### 3️⃣ Decrypt"
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
echo "### 4️⃣ Summary"
echo ""

# ---- Compare ----
if [[ "$DECRYPTED_TEXT" == "$PLAINTEXT_ACTIVE_KEY_ID" ]]; then
  echo "✅ Round-trip encryption/decryption successful!"
else
  echo "❌ Decryption mismatch! Expected \`$PLAINTEXT_ACTIVE_KEY_ID\` but got \`$DECRYPTED_TEXT\`"
  exit 1
fi

echo ""
echo "---"
echo ""
echo "## ▶️ Old Rotated KEK — Decrypt"
echo ""

[[ "$VERBOSE" == true ]] && { echo "📦 OLD EncryptResponse JSON:"; echo '```json'; echo "$ENCRYPT_RESPONSE_OLD_KEY_ID" | base64 -d | jq; echo '```'; echo ""; }

OLD_P11_KEY_ID=$(echo "$ENCRYPT_RESPONSE_OLD_KEY_ID" | base64 -d | jq -r .keyId)
CIPHERTEXT_OLD_KEY_ID=$(echo "$ENCRYPT_RESPONSE_OLD_KEY_ID" | base64 -d | jq -r .ciphertext)
echo "🧾 key_id (OLD KEK): \`$OLD_P11_KEY_ID\`"
echo ""
print_jwe_header "$CIPHERTEXT_OLD_KEY_ID"
echo ""

echo "### Decrypt"
echo ""

# ---- Decrypt with old KEK ----
DECRYPT_REQUEST_OLD="{\"ciphertext\": \"$CIPHERTEXT_OLD_KEY_ID\", \"uid\": \"test-dec-1\", \"key_id\": \"$OLD_P11_KEY_ID\"}"
[[ "$VERBOSE" == true ]] && { echo "📤 DecryptRequest:"; echo '```json'; echo "$DECRYPT_REQUEST_OLD" | jq; echo '```'; echo ""; }

DECRYPT_RESPONSE_OLD_KEY_ID=$(grpcurl \
  -plaintext \
  -proto api.proto \
  -d "$DECRYPT_REQUEST_OLD" \
  -unix \
  unix://"$SOCKET" \
  v2.KeyManagementService.Decrypt)

[[ "$VERBOSE" == true ]] && { echo "📥 DecryptResponse:"; echo '```json'; echo "$DECRYPT_RESPONSE_OLD_KEY_ID" | jq; echo '```'; echo ""; }

DECRYPTED_BASE64_OLD_KEY_ID=$(echo "$DECRYPT_RESPONSE_OLD_KEY_ID" | jq -r .plaintext)
DECRYPTED_TEXT_OLD_KEY_ID=$(echo "$DECRYPTED_BASE64_OLD_KEY_ID" | base64 -d)
echo "🔓 Decrypted text: \`$DECRYPTED_TEXT_OLD_KEY_ID\`"

echo ""
echo "### Summary"
echo ""

if [[ "$DECRYPTED_TEXT_OLD_KEY_ID" == "$PLAINTEXT_OLD_KEY_ID" ]]; then
  echo "✅ Rotation decryption successful!"
else
  echo "❌ Key rotation decryption mismatch! Expected \`$PLAINTEXT_OLD_KEY_ID\` but got \`$DECRYPTED_TEXT_OLD_KEY_ID\`"
  exit 1
fi
