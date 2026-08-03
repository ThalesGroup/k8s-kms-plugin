#!/usr/bin/env bash
set -euo pipefail

# ---- Check for required tools ----
# Probe by *running* each tool, not with `command -v` — the same rule the Makefile
# applies (see `define require`). A goenv/asdf/pyenv shim stays on PATH even when
# the tool is not installed for the active version, so `command -v grpcurl` says
# yes and the shim only fails once called, with
# `goenv: 'grpcurl' command not found` — an error that surfaces far from its cause.
#
# Exit 127 — missing binary, or a shim with nothing behind it — is the only status
# treated as missing; tools that reject --version exit 1 or 2 and pass.
MISSING=()
require_tool() {   # require_tool <binary> <how to install it>
  local rc=0
  "$1" --version >/dev/null 2>&1 || rc=$?
  (( rc != 127 )) || MISSING+=("$1|$2")
}

require_tool grpcurl "go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
require_tool jq      "sudo apt-get install jq"
require_tool base64  "sudo apt-get install coreutils"
require_tool curl    "sudo apt-get install curl"

if (( ${#MISSING[@]} > 0 )); then
  echo "❌ Required tools are not installed:" >&2
  for m in "${MISSING[@]}"; do
    IFS='|' read -r _tool _hint <<<"$m"
    echo "   • $_tool — install it with:" >&2
    echo "       $_hint" >&2
  done
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

# print_mlkem_envelope shows the size of the AEAD-wrapped seed (ciphertext) and the raw
# ML-KEM encapsulation ciphertext (the kem-ct annotation). ML-KEM has no JWE header to
# print — the KEM ciphertext travels as a plain KMS v2 annotation instead (see
# ml-kem-kmsv2-implementation-spec.md).
print_mlkem_envelope() {
  local ciphertext_b64="$1" encrypt_response="$2"
  local ct_len kemct_b64 kemct_len

  ct_len=$(printf '%s' "$ciphertext_b64" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]')
  kemct_b64=$(printf '%s' "$encrypt_response" | jq -r '(.annotations // {})["kem-ct.k8s-kms-plugin.keysealer.eclipse.org"] // empty')
  kemct_len=0
  [[ -n "$kemct_b64" ]] && kemct_len=$(printf '%s' "$kemct_b64" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]')

  echo "🧬 ML-KEM envelope (no JWE):"
  echo '```'
  echo "ciphertext:        ${ct_len} B  (nonce || AES-256-GCM-sealed DEK seed)"
  echo "kem-ct annotation: ${kemct_len} B  (raw ML-KEM encapsulation ciphertext)"
  echo '```'
}

# print_ciphertext_info prints either the JWE protected header (AES-GCM / AES-CBC+HMAC /
# RSA-OAEP) or the ML-KEM binary envelope's size breakdown, depending on the
# "algorithm-family" annotation the plugin attaches to every EncryptResponse — so this
# reports what the plugin actually produced, not an assumption baked into the script.
print_ciphertext_info() {
  local ciphertext_b64="$1" encrypt_response="$2"
  local family_b64 family

  family_b64=$(printf '%s' "$encrypt_response" | jq -r '(.annotations // {})["algorithm-family.k8s-kms-plugin.keysealer.eclipse.org"] // empty')
  family=""
  [[ -n "$family_b64" ]] && family=$(printf '%s' "$family_b64" | base64 -d 2>/dev/null || true)

  if [[ "$family" == "ml-kem" ]]; then
    print_mlkem_envelope "$ciphertext_b64" "$encrypt_response"
  else
    print_jwe_header "$ciphertext_b64"
  fi
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
print_ciphertext_info "$CIPHERTEXT" "$ENCRYPT_RESPONSE"
echo ""

echo "### 3️⃣ Decrypt"
echo ""

# ---- Decrypt ----
# Annotations are forwarded from EncryptResponse, mirroring the apiserver's round-trip
# guarantee — required for ML-KEM, whose kem-ct annotation the plugin needs back to decrypt.
DECRYPT_REQUEST=$(echo "$ENCRYPT_RESPONSE" | jq -c --arg uid "test-dec-1" --arg kid "$KEY_ID" \
  '{ciphertext: .ciphertext, uid: $uid, key_id: $kid} + (if (.annotations // {}) == {} then {} else {annotations: .annotations} end)')
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

ENCRYPT_RESPONSE_OLD_KEY_ID_JSON=$(echo "$ENCRYPT_RESPONSE_OLD_KEY_ID" | base64 -d)
[[ "$VERBOSE" == true ]] && { echo "📦 OLD EncryptResponse JSON:"; echo '```json'; echo "$ENCRYPT_RESPONSE_OLD_KEY_ID_JSON" | jq; echo '```'; echo ""; }

OLD_P11_KEY_ID=$(echo "$ENCRYPT_RESPONSE_OLD_KEY_ID_JSON" | jq -r .keyId)
CIPHERTEXT_OLD_KEY_ID=$(echo "$ENCRYPT_RESPONSE_OLD_KEY_ID_JSON" | jq -r .ciphertext)
echo "🧾 key_id (OLD KEK): \`$OLD_P11_KEY_ID\`"
echo ""
print_ciphertext_info "$CIPHERTEXT_OLD_KEY_ID" "$ENCRYPT_RESPONSE_OLD_KEY_ID_JSON"
echo ""

echo "### Decrypt"
echo ""

# ---- Decrypt with old KEK ----
# Annotations are forwarded from the OLD KEK's EncryptResponse — required for ML-KEM.
DECRYPT_REQUEST_OLD=$(echo "$ENCRYPT_RESPONSE_OLD_KEY_ID_JSON" | jq -c --arg uid "test-dec-1" --arg kid "$OLD_P11_KEY_ID" \
  '{ciphertext: .ciphertext, uid: $uid, key_id: $kid} + (if (.annotations // {}) == {} then {} else {annotations: .annotations} end)')
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
